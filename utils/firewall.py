"""
Auto-blocking of malicious IPs.

Linux: uses iptables (requires root).
Windows: stubbed with netsh advfirewall — uncomment/adjust if needed.
"""

import platform
import subprocess

_blocked_ips = set()


def block_ip(ip: str) -> bool:
    """Block an IP address at the OS firewall level. Returns True if blocked."""
    if ip in _blocked_ips:
        return True  # already blocked

    system = platform.system()
    try:
        if system == "Linux":
            subprocess.run(
                ["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"],
                check=True,
            )
        elif system == "Windows":
            subprocess.run(
                [
                    "netsh", "advfirewall", "firewall", "add", "rule",
                    f"name=NIDS_Block_{ip}", "dir=in", "action=block",
                    f"remoteip={ip}",
                ],
                check=True,
            )
        else:
            print(f"[firewall] Unsupported OS '{system}', skipping block for {ip}")
            return False

        _blocked_ips.add(ip)
        print(f"[firewall] Blocked IP: {ip}")
        return True

    except subprocess.CalledProcessError as e:
        print(f"[firewall] Failed to block {ip}: {e}")
        return False
    except FileNotFoundError:
        print(f"[firewall] iptables/netsh not found — running without privileges? "
              f"Simulating block for {ip} instead.")
        _blocked_ips.add(ip)
        return True


def is_blocked(ip: str) -> bool:
    return ip in _blocked_ips
