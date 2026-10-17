"""
Controlled auto-blocking of malicious IPs with temporary lease durations and reliable failure reporting.

Linux: uses iptables (requires root/sudo capabilities).
Windows: uses netsh advfirewall (requires Administrator privileges).
"""

import ipaddress
import os
import platform
import subprocess
import threading
import time
from typing import Dict, List, Any, Optional

from utils.logger import log_audit

DEFAULT_BLOCK_DURATION = int(os.getenv("NIDS_BLOCK_DURATION", "300"))  # 5 minutes default

# Active blocks registry: ip -> {blocked_at, duration, expires_at, timer}
_active_blocks: Dict[str, Dict[str, Any]] = {}
_lock = threading.Lock()


def validate_ip(ip: str) -> bool:
    """Validate that the given string is a valid IPv4 or IPv6 address."""
    try:
        ipaddress.ip_address(ip.strip())
        return True
    except (ValueError, AttributeError):
        return False


def _build_block_command(system: str, ip: str) -> List[str]:
    if system == "Linux":
        return ["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"]
    elif system == "Windows":
        return [
            "netsh", "advfirewall", "firewall", "add", "rule",
            f"name=NIDS_Block_{ip}", "dir=in", "action=block",
            f"remoteip={ip}",
        ]
    return []


def _build_unblock_command(system: str, ip: str) -> List[str]:
    if system == "Linux":
        return ["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"]
    elif system == "Windows":
        return [
            "netsh", "advfirewall", "firewall", "delete", "rule",
            f"name=NIDS_Block_{ip}",
        ]
    return []


def block_ip(ip: str, duration: int = DEFAULT_BLOCK_DURATION) -> bool:
    """
    Block an IP address at the OS firewall level for a controlled duration.
    Accurately reports success or failure and logs to the audit table.

    :param ip: The target IP address to block.
    :param duration: Time in seconds before automatic unblock (0 for indefinite).
    :return: True if successfully blocked at OS level, False otherwise.
    """
    ip = ip.strip()
    if not validate_ip(ip):
        detail = f"Invalid IP address format: {ip!r}"
        print(f"[firewall] {detail}")
        log_audit("firewall_block_rejected", ip, success=False, detail=detail)
        return False

    with _lock:
        if ip in _active_blocks:
            # Refresh lease duration if already blocked
            now = time.time()
            if duration > 0:
                old_timer = _active_blocks[ip].get("timer")
                if old_timer:
                    old_timer.cancel()
                new_timer = threading.Timer(duration, unblock_ip, args=[ip])
                new_timer.daemon = True
                new_timer.start()
                _active_blocks[ip]["timer"] = new_timer
                _active_blocks[ip]["expires_at"] = now + duration
            return True

    system = platform.system()
    cmd = _build_block_command(system, ip)
    if not cmd:
        detail = f"Unsupported operating system '{system}' for firewall blocking"
        print(f"[firewall] {detail}")
        log_audit("firewall_block_failed", ip, success=False, detail=detail)
        return False

    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
        if proc.returncode != 0:
            err_msg = proc.stderr.strip() or proc.stdout.strip() or f"Exit code {proc.returncode}"
            # Common case: insufficient permissions
            if "requires elevation" in err_msg.lower() or "administrator" in err_msg.lower() or "permission denied" in err_msg.lower():
                detail = f"Elevation required: {err_msg}"
            else:
                detail = f"Command failed ({proc.returncode}): {err_msg}"
            print(f"[firewall] Failed to block {ip}: {detail}")
            log_audit("firewall_block_failed", ip, success=False, detail=detail)
            return False

        # Successfully added firewall rule
        now = time.time()
        timer = None
        if duration > 0:
            timer = threading.Timer(duration, unblock_ip, args=[ip])
            timer.daemon = True
            timer.start()

        with _lock:
            _active_blocks[ip] = {
                "blocked_at": now,
                "duration": duration,
                "expires_at": now + duration if duration > 0 else None,
                "timer": timer,
            }

        detail = f"Blocked on {system} firewall for {duration}s" if duration > 0 else f"Blocked on {system} firewall indefinitely"
        print(f"[firewall] {detail}: {ip}")
        log_audit("firewall_block_success", ip, success=True, detail=detail)
        return True

    except FileNotFoundError:
        detail = f"Firewall command '{cmd[0]}' not found in PATH"
        print(f"[firewall] {detail}")
        log_audit("firewall_block_failed", ip, success=False, detail=detail)
        return False
    except Exception as exc:
        detail = f"{type(exc).__name__}: {exc}"
        print(f"[firewall] Unexpected error blocking {ip}: {detail}")
        log_audit("firewall_block_error", ip, success=False, detail=detail)
        return False


def unblock_ip(ip: str) -> bool:
    """
    Remove the firewall block rule for an IP address.

    :param ip: The IP address to unblock.
    :return: True if successfully removed or was not blocked, False if command failed.
    """
    ip = ip.strip()
    with _lock:
        block_info = _active_blocks.pop(ip, None)
        if block_info and block_info.get("timer"):
            block_info["timer"].cancel()

    system = platform.system()
    cmd = _build_unblock_command(system, ip)
    if not cmd:
        return True

    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
        if proc.returncode != 0:
            err_msg = proc.stderr.strip() or proc.stdout.strip()
            # If the rule simply doesn't exist, treat as success
            if "no rules match" in err_msg.lower() or "not found" in err_msg.lower() or "does not exist" in err_msg.lower():
                log_audit("firewall_unblock", ip, success=True, detail="Rule was already removed")
                return True
            detail = f"Failed to delete rule: {err_msg}"
            print(f"[firewall] {detail}")
            log_audit("firewall_unblock_failed", ip, success=False, detail=detail)
            return False

        print(f"[firewall] Unblocked IP: {ip}")
        log_audit("firewall_unblock", ip, success=True, detail="Firewall rule removed (lease expired or manual unblock)")
        return True

    except Exception as exc:
        detail = f"{type(exc).__name__}: {exc}"
        print(f"[firewall] Error during unblock of {ip}: {detail}")
        log_audit("firewall_unblock_error", ip, success=False, detail=detail)
        return False


def is_blocked(ip: str) -> bool:
    """Check if an IP address currently has an active block."""
    ip = ip.strip()
    with _lock:
        if ip not in _active_blocks:
            return False
        info = _active_blocks[ip]
        if info.get("expires_at") and time.time() > info["expires_at"]:
            return False
        return True


def get_active_blocks() -> List[Dict[str, Any]]:
    """Return a list of all currently active temporary and permanent blocks."""
    now = time.time()
    results = []
    with _lock:
        for ip, info in list(_active_blocks.items()):
            expires_at = info.get("expires_at")
            remaining = round(expires_at - now, 1) if expires_at else None
            if remaining is not None and remaining <= 0:
                continue
            results.append({
                "ip": ip,
                "blocked_at": info["blocked_at"],
                "duration": info["duration"],
                "expires_at": expires_at,
                "remaining_seconds": remaining,
            })
    return results
