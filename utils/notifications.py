"""
Email notification module for high-severity intrusion alerts with per-IP cooldown.

Configurable via environment variables:
  ALERT_EMAIL_ENABLED    : '1' or 'true' to enable SMTP sending (default: '0')
  SMTP_HOST              : SMTP server hostname (default: 'localhost')
  SMTP_PORT              : SMTP server port (default: '587')
  SMTP_USER              : SMTP authentication username (optional)
  SMTP_PASS              : SMTP authentication password (optional)
  SMTP_USE_TLS           : '1' to use STARTTLS (default: '1')
  ALERT_EMAIL_TO         : Destination email address
  ALERT_EMAIL_FROM       : Sender address (default: 'nids-alerts@localhost')
  EMAIL_COOLDOWN_SECONDS : Minimum seconds between notifications for same IP (default: 300)
"""

import os
import smtplib
import threading
import time
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Dict, Any, Optional

from utils.logger import log_audit

# Per-source-IP cooldown tracker
_last_notification_time: Dict[str, float] = {}
_cooldown_lock = threading.Lock()


def get_notification_config() -> Dict[str, Any]:
    """Return the current notification configuration dictionary."""
    return {
        "enabled": os.getenv("ALERT_EMAIL_ENABLED", "0").strip().lower() in ("1", "true", "yes"),
        "smtp_host": os.getenv("SMTP_HOST", "localhost"),
        "smtp_port": int(os.getenv("SMTP_PORT", "587")),
        "smtp_user": os.getenv("SMTP_USER", "").strip(),
        "smtp_pass": os.getenv("SMTP_PASS", "").strip(),
        "use_tls": os.getenv("SMTP_USE_TLS", "1").strip().lower() in ("1", "true", "yes"),
        "to_email": os.getenv("ALERT_EMAIL_TO", "").strip(),
        "from_email": os.getenv("ALERT_EMAIL_FROM", "nids-alerts@localhost").strip(),
        "cooldown_seconds": int(os.getenv("EMAIL_COOLDOWN_SECONDS", "300")),
    }


def reset_cooldowns():
    """Reset the notification cooldown registry (useful for testing)."""
    with _cooldown_lock:
        _last_notification_time.clear()


def check_and_update_cooldown(src_ip: str, cooldown_seconds: int) -> tuple[bool, float]:
    """
    Check if an alert for src_ip can be sent.
    Returns (can_send, remaining_seconds).
    """
    now = time.time()
    with _cooldown_lock:
        last_time = _last_notification_time.get(src_ip, 0.0)
        elapsed = now - last_time
        if elapsed < cooldown_seconds:
            return False, round(cooldown_seconds - elapsed, 1)
        _last_notification_time[src_ip] = now
        return True, 0.0


def format_alert_email(alert_info: Dict[str, Any]) -> tuple[str, str, str]:
    """Format subject, text body, and HTML body for the alert email."""
    src_ip = alert_info.get("src_ip", "Unknown")
    attack_type = alert_info.get("attack_type", "Intrusion")
    source = alert_info.get("source")
    confidence = alert_info.get("confidence")
    if source == "rule":
        conf_str = "Rule Match (Deterministic)"
    elif confidence is not None:
        conf_str = f"{confidence * 100:.1f}%" + (" (ML)" if source == "ml" else "")
    else:
        conf_str = "Rule Match (Deterministic)"
    severity = alert_info.get("severity", "HIGH").upper()
    reason = alert_info.get("reason", "Threshold exceeded")
    blocked = alert_info.get("blocked", False)
    block_status = "Temporarily Blocked by Firewall" if blocked else "Not Blocked (Alert Only)"
    feats = alert_info.get("features") or {}

    subject = f"[NIDS {severity} ALERT] {attack_type} detected from {src_ip}"

    text_body = f"""
============================================================
NETWORK INTRUSION DETECTION SYSTEM - HIGH SEVERITY ALERT
============================================================

An intrusion attempt has been detected that requires attention.

Summary:
------------------------------------------------------------
- Attack Type:      {attack_type}
- Severity:         {severity}
- Confidence:       {conf_str}
- Source IP:        {src_ip}
- Firewall Action:  {block_status}
- Trigger Rationale:
  {reason}

Behavioral Metrics (5-second window):
------------------------------------------------------------
- Packet Rate:      {feats.get('packet_rate', 'N/A')} pkts/sec
- Unique Ports:     {feats.get('unique_ports', 'N/A')}
- SYN Rate:         {feats.get('syn_rate', 'N/A')} SYN/sec
- Avg Packet Len:   {feats.get('avg_packet_len', 'N/A')} bytes

Timestamp: {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())}
============================================================
"""

    html_body = f"""
<!DOCTYPE html>
<html>
<head>
  <style>
    body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #0f1117; color: #e6e6e6; margin: 0; padding: 20px; }}
    .container {{ max-width: 600px; margin: 0 auto; background: #1a1d27; border: 1px solid #2a2e3a; border-radius: 8px; overflow: hidden; }}
    .header {{ background: #ef6161; color: #fff; padding: 16px 20px; font-size: 18px; font-weight: bold; }}
    .content {{ padding: 20px; }}
    .alert-box {{ background: rgba(239, 97, 97, 0.15); border-left: 4px solid #ef6161; padding: 12px; margin-bottom: 20px; border-radius: 4px; }}
    table {{ width: 100%; border-collapse: collapse; margin-bottom: 20px; font-size: 14px; }}
    td {{ padding: 8px 6px; border-bottom: 1px solid #2a2e3a; }}
    td:first-child {{ color: #9aa0ac; width: 150px; font-weight: 500; }}
    .metric-grid {{ display: flex; gap: 10px; margin-top: 10px; }}
    .metric-card {{ background: #0f1117; border: 1px solid #2a2e3a; padding: 10px; border-radius: 6px; text-align: center; flex: 1; }}
    .metric-val {{ font-size: 16px; font-weight: bold; color: #5ad1a3; }}
    .metric-lbl {{ font-size: 11px; color: #9aa0ac; text-transform: uppercase; }}
  </style>
</head>
<body>
  <div class="container">
    <div class="header">🚨 High-Severity Intrusion Alert</div>
    <div class="content">
      <div class="alert-box">
        <strong>{attack_type}</strong> detected from <strong>{src_ip}</strong> (Confidence: {conf_str})<br>
        <span style="font-size: 13px; color: #f7a8a8;">{reason}</span>
      </div>

      <table>
        <tr><td>Source IP</td><td><strong>{src_ip}</strong></td></tr>
        <tr><td>Attack Classification</td><td>{attack_type}</td></tr>
        <tr><td>Severity</td><td><span style="color:#ef6161;font-weight:bold;">{severity}</span></td></tr>
        <tr><td>Firewall Action</td><td>{block_status}</td></tr>
        <tr><td>Timestamp</td><td>{time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())}</td></tr>
      </table>

      <h4 style="margin: 16px 0 8px; color: #9aa0ac; font-size: 12px; text-transform: uppercase;">Observed Metrics</h4>
      <div class="metric-grid">
        <div class="metric-card">
          <div class="metric-val">{feats.get('packet_rate', '—')}</div>
          <div class="metric-lbl">Packets/s</div>
        </div>
        <div class="metric-card">
          <div class="metric-val">{feats.get('unique_ports', '—')}</div>
          <div class="metric-lbl">Unique Ports</div>
        </div>
        <div class="metric-card">
          <div class="metric-val">{feats.get('syn_rate', '—')}</div>
          <div class="metric-lbl">SYN/s</div>
        </div>
      </div>
    </div>
  </div>
</body>
</html>
"""
    return subject, text_body, html_body


def send_high_severity_alert(alert_info: Dict[str, Any], dry_run: bool = False) -> Dict[str, Any]:
    """
    Send an email notification for a high-severity alert if cooldown has expired.
    Returns status dictionary.
    """
    cfg = get_notification_config()
    src_ip = alert_info.get("src_ip", "0.0.0.0")

    # Check cooldown
    can_send, remaining = check_and_update_cooldown(src_ip, cfg["cooldown_seconds"])
    if not can_send:
        msg = f"Notification suppressed for {src_ip}: cooldown active ({remaining}s remaining)"
        print(f"[notifications] {msg}")
        return {"sent": False, "reason": "cooldown_active", "remaining_seconds": remaining}

    subject, text_body, html_body = format_alert_email(alert_info)

    if dry_run or not cfg["enabled"]:
        print(f"[notifications] Email notifications disabled or in dry-run mode. Alert queued for {src_ip}.")
        log_audit(
            "email_alert_simulated", src_ip, success=True,
            detail=f"Subject: {subject} (Email notifications disabled in config)"
        )
        return {"sent": False, "reason": "notifications_disabled", "simulated": True, "subject": subject}

    if not cfg["to_email"]:
        print("[notifications] ALERT_EMAIL_TO is not set; skipping email delivery.")
        return {"sent": False, "reason": "missing_recipient"}

    try:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"] = cfg["from_email"]
        msg["To"] = cfg["to_email"]
        msg.attach(MIMEText(text_body, "plain"))
        msg.attach(MIMEText(html_body, "html"))

        server = smtplib.SMTP(cfg["smtp_host"], cfg["smtp_port"], timeout=10)
        if cfg["use_tls"]:
            server.starttls()
        if cfg["smtp_user"] and cfg["smtp_pass"]:
            server.login(cfg["smtp_user"], cfg["smtp_pass"])

        server.send_message(msg)
        server.quit()

        print(f"[notifications] Sent high-severity email alert to {cfg['to_email']} for {src_ip}")
        log_audit(
            "email_alert_sent", src_ip, success=True,
            detail=f"Sent alert for {alert_info.get('attack_type')} to {cfg['to_email']}"
        )
        return {"sent": True, "to": cfg["to_email"], "subject": subject}

    except Exception as exc:
        err_msg = f"{type(exc).__name__}: {exc}"
        print(f"[notifications] Failed to send email alert for {src_ip}: {err_msg}")
        log_audit(
            "email_alert_failed", src_ip, success=False,
            detail=err_msg
        )
        return {"sent": False, "error": err_msg}


def notify_high_severity_async(alert_info: Dict[str, Any]):
    """Launch notification in a daemon thread so packet capture is not delayed."""
    t = threading.Thread(target=send_high_severity_alert, args=(alert_info,), daemon=True)
    t.start()
    return t
