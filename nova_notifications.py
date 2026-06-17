"""
Nova Notifications v1.0
========================
Real-time alerts when Nova finds something.

Supported channels:
- Telegram (easiest, works on mobile)
- Email (SMTP)
- Webhook (Slack, Discord, custom)

When to notify:
- Critical finding discovered
- High severity finding
- Scan completed
- Session completed
- Error occurred
"""

import json
import logging
import smtplib
from typing import Dict, List, Optional, Any
from dataclasses import dataclass
from datetime import datetime
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from enum import Enum

logger = logging.getLogger(__name__)


class NotificationLevel(Enum):
    """When to send notifications"""
    CRITICAL_ONLY = "critical_only"
    HIGH_AND_ABOVE = "high_and_above"
    ALL_FINDINGS = "all_findings"
    COMPLETION_ONLY = "completion_only"


@dataclass
class Notification:
    """A notification to send"""
    title: str
    message: str
    severity: str = "INFO"
    target: str = ""
    session_id: str = ""
    timestamp: str = ""
    metadata: Dict[str, Any] = None

    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = datetime.now().isoformat()
        if self.metadata is None:
            self.metadata = {}

    def format_telegram(self) -> str:
        """Format for Telegram"""

        severity_emoji = {
            "CRITICAL": "🚨",
            "HIGH": "🔴",
            "MEDIUM": "🟡",
            "LOW": "🟢",
            "INFO": "ℹ️"
        }.get(self.severity, "📌")

        return (
            f"{severity_emoji} *Nova Alert*\n\n"
            f"*{self.title}*\n\n"
            f"{self.message}\n\n"
            f"Target: `{self.target}`\n"
            f"Time: {self.timestamp[:19]}"
        )

    def format_email_html(self) -> str:
        """Format for HTML email"""

        color = {
            "CRITICAL": "#ff0000",
            "HIGH": "#ff6400",
            "MEDIUM": "#ffc800",
            "LOW": "#00c864",
            "INFO": "#0088ff"
        }.get(self.severity, "#888888")

        return f"""
<html>
<body style="font-family: Arial; background: #0a0a0a; color: #e0e0e0; padding: 20px;">
    <div style="max-width: 600px; margin: 0 auto;">
        <div style="background: #1a1a2e; padding: 20px; border-left: 4px solid #00ff88;">
            <h2 style="color: #00ff88;">🦅 Nova Alert</h2>
        </div>
        <div style="background: #111; padding: 20px; margin-top: 10px;">
            <span style="background: {color}33; color: {color}; padding: 3px 10px; 
                         border-radius: 3px; font-size: 12px;">
                {self.severity}
            </span>
            <h3 style="color: #fff; margin-top: 15px;">{self.title}</h3>
            <p style="color: #ccc; line-height: 1.6;">{self.message}</p>
            <hr style="border-color: #333;">
            <p style="color: #888; font-size: 12px;">
                Target: {self.target} | {self.timestamp[:19]}
            </p>
        </div>
    </div>
</body>
</html>"""

    def format_webhook(self) -> Dict:
        """Format for webhook (Slack/Discord compatible)"""

        color = {
            "CRITICAL": "#ff0000",
            "HIGH": "#ff6400",
            "MEDIUM": "#ffc800",
            "LOW": "#00c864",
            "INFO": "#0088ff"
        }.get(self.severity, "#888888")

        return {
            "text": f"*Nova Alert: {self.title}*",
            "attachments": [
                {
                    "color": color,
                    "title": self.title,
                    "text": self.message,
                    "fields": [
                        {"title": "Target", "value": self.target, "short": True},
                        {"title": "Severity", "value": self.severity, "short": True},
                        {"title": "Time", "value": self.timestamp[:19], "short": True}
                    ]
                }
            ]
        }


class NovaNotifications:
    """
    Sends notifications when Nova finds something.

    Works with:
    - Telegram (instant mobile alerts)
    - Email (detailed reports)
    - Webhooks (Slack, Discord, custom)
    """

    def __init__(self, config: Optional[Dict] = None):
        """
        Initialize notifications.

        Args:
            config: Notification configuration
        """

        self.config = config or {}
        self.enabled = self.config.get("enabled", False)
        self.level = NotificationLevel(
            self.config.get("level", "critical_only")
        )

        self.telegram = TelegramNotifier(
            token=self.config.get("telegram_token", ""),
            chat_id=self.config.get("telegram_chat_id", "")
        )

        self.email = EmailNotifier(
            smtp_server=self.config.get("email_smtp", ""),
            username=self.config.get("email_user", ""),
            password=self.config.get("email_password", ""),
            recipient=self.config.get("email_recipient", "")
        )

        self.webhook = WebhookNotifier(
            url=self.config.get("webhook_url", "")
        )

        self.notification_history: List[Notification] = []

        logger.info(f"Notifications initialized (enabled: {self.enabled})")

    def notify_finding(self, finding: Dict, session_id: str = "") -> bool:
        """
        Send notification for a finding.

        Args:
            finding: Finding dictionary
            session_id: Current session ID
        """

        severity = finding.get("severity", "INFO")

        # Check if we should notify for this severity
        if not self._should_notify(severity):
            return False

        # Enrich message with Truth Engine confidence if available
        truth   = finding.get("_truth", {})
        conf    = truth.get("confidence")
        oob_ok  = truth.get("oob_used", False)
        v_pass  = truth.get("verifications_passed", "?")
        v_total = truth.get("verifications_total", "?")

        SEV_EMOJI = {
            "CRITICAL": "🔴", "HIGH": "🟠",
            "MEDIUM": "🟡", "LOW": "🟢", "INFO": "ℹ️"
        }
        emoji = SEV_EMOJI.get(str(severity).upper(), "⚠️")

        title_str  = finding.get("title", "Unknown")
        ep         = finding.get("endpoint", finding.get("url", ""))
        desc       = finding.get("description", "")

        if conf is not None:
            conf_line = f"\nConfidence: {conf:.0%} ({truth.get('confidence_label', '')})"
            oob_line  = " ✅ OOB confirmed" if oob_ok else ""
            ver_line  = f"\nVerifications: {v_pass}/{v_total} passed"
            ep_line   = f"\nEndpoint: `{ep}`" if ep else ""
            msg = (
                f"{emoji} *Nova Confirmed Finding*\n"
                f"*{severity.upper()}* — {title_str}"
                f"{ep_line}"
                f"{conf_line}{oob_line}"
                f"{ver_line}"
            )
        else:
            msg = desc or title_str

        notification = Notification(
            title=f"{emoji} {severity.upper()}: {title_str}",
            message=msg,
            severity=severity,
            target=finding.get("target", ep),
            session_id=session_id,
            metadata=finding
        )

        return self._send(notification)

    def notify_completion(
        self,
        target: str,
        session_id: str,
        findings_count: int,
        critical_count: int
    ) -> bool:
        """Send notification when scan completes"""

        if not self.config.get("notify_on_completion", True):
            return False

        message = (
            f"Scan completed for {target}.\n"
            f"Total findings: {findings_count}\n"
            f"Critical: {critical_count}"
        )

        notification = Notification(
            title=f"Scan Complete: {target}",
            message=message,
            severity="INFO",
            target=target,
            session_id=session_id
        )

        return self._send(notification)

    def notify_error(self, error: str, target: str = "") -> bool:
        """Send notification for critical error"""

        notification = Notification(
            title="Nova Error",
            message=error,
            severity="HIGH",
            target=target
        )

        return self._send(notification)

    def notify_custom(
        self,
        title: str,
        message: str,
        severity: str = "INFO"
    ) -> bool:
        """Send custom notification"""

        notification = Notification(
            title=title,
            message=message,
            severity=severity
        )

        return self._send(notification)

    def _send(self, notification: Notification) -> bool:
        """Send notification through all configured channels"""

        if not self.enabled:
            logger.debug("Notifications disabled, skipping")
            return False

        self.notification_history.append(notification)
        sent = False

        # Send via Telegram
        if self.telegram.is_configured():
            try:
                result = self.telegram.send(notification)
                if result:
                    sent = True
                    logger.info(f"Telegram notification sent: {notification.title}")
            except Exception as e:
                logger.error(f"Telegram error: {e}")

        # Send via Email
        if self.email.is_configured():
            try:
                result = self.email.send(notification)
                if result:
                    sent = True
                    logger.info(f"Email notification sent: {notification.title}")
            except Exception as e:
                logger.error(f"Email error: {e}")

        # Send via Webhook
        if self.webhook.is_configured():
            try:
                result = self.webhook.send(notification)
                if result:
                    sent = True
                    logger.info(f"Webhook notification sent: {notification.title}")
            except Exception as e:
                logger.error(f"Webhook error: {e}")

        return sent

    def _should_notify(self, severity: str) -> bool:
        """Check if we should notify for this severity"""

        if self.level == NotificationLevel.CRITICAL_ONLY:
            return severity == "CRITICAL"

        elif self.level == NotificationLevel.HIGH_AND_ABOVE:
            return severity in ["CRITICAL", "HIGH"]

        elif self.level == NotificationLevel.ALL_FINDINGS:
            return True

        elif self.level == NotificationLevel.COMPLETION_ONLY:
            return False

        return False

    def test(self) -> Dict[str, bool]:
        """Test all notification channels"""

        test_notification = Notification(
            title="Nova Test Notification",
            message="This is a test from Nova Security Platform",
            severity="INFO",
            target="test.local"
        )

        results = {}

        if self.telegram.is_configured():
            results["telegram"] = self.telegram.send(test_notification)

        if self.email.is_configured():
            results["email"] = self.email.send(test_notification)

        if self.webhook.is_configured():
            results["webhook"] = self.webhook.send(test_notification)

        return results


class TelegramNotifier:
    """Sends notifications via Telegram"""

    def __init__(self, token: str, chat_id: str):
        self.token = token
        self.chat_id = chat_id

    def is_configured(self) -> bool:
        return bool(self.token and self.chat_id)

    def send(self, notification: Notification) -> bool:
        """Send Telegram message"""

        if not self.is_configured():
            return False

        try:
            import urllib.request
            import urllib.parse

            message = notification.format_telegram()
            url = f"https://api.telegram.org/bot{self.token}/sendMessage"

            data = urllib.parse.urlencode({
                "chat_id": self.chat_id,
                "text": message,
                "parse_mode": "Markdown"
            }).encode()

            req = urllib.request.Request(url, data=data)
            response = urllib.request.urlopen(req, timeout=10)

            return response.status == 200

        except Exception as e:
            logger.error(f"Telegram send failed: {e}")
            return False


class EmailNotifier:
    """Sends notifications via Email"""

    def __init__(
        self,
        smtp_server: str,
        username: str,
        password: str,
        recipient: str
    ):
        self.smtp_server = smtp_server
        self.username = username
        self.password = password
        self.recipient = recipient

    def is_configured(self) -> bool:
        return bool(
            self.smtp_server and
            self.username and
            self.password and
            self.recipient
        )

    def send(self, notification: Notification) -> bool:
        """Send email"""

        if not self.is_configured():
            return False

        try:
            msg = MIMEMultipart("alternative")
            msg["Subject"] = f"[Nova] {notification.severity}: {notification.title}"
            msg["From"] = self.username
            msg["To"] = self.recipient

            html_content = notification.format_email_html()
            msg.attach(MIMEText(html_content, "html"))

            with smtplib.SMTP_SSL(self.smtp_server, 465) as server:
                server.login(self.username, self.password)
                server.sendmail(self.username, self.recipient, msg.as_string())

            return True

        except Exception as e:
            logger.error(f"Email send failed: {e}")
            return False


class WebhookNotifier:
    """Sends notifications via webhook"""

    def __init__(self, url: str):
        self.url = url

    def is_configured(self) -> bool:
        return bool(self.url)

    def send(self, notification: Notification) -> bool:
        """Send webhook"""

        if not self.is_configured():
            return False

        try:
            import urllib.request

            payload = json.dumps(notification.format_webhook()).encode()

            req = urllib.request.Request(
                self.url,
                data=payload,
                headers={"Content-Type": "application/json"}
            )

            response = urllib.request.urlopen(req, timeout=10)
            return response.status in [200, 201, 204]

        except Exception as e:
            logger.error(f"Webhook send failed: {e}")
            return False


# ─────────────────────────────────────────
# EXAMPLE USAGE
# ─────────────────────────────────────────

if __name__ == "__main__":
    print("=== NOVA NOTIFICATIONS ===\n")

    # Configure
    config = {
        "enabled": True,
        "level": "critical_only",
        "telegram_token": "YOUR_TOKEN",
        "telegram_chat_id": "YOUR_CHAT_ID",
        "notify_on_completion": True
    }

    notifier = NovaNotifications(config)

    # Test finding notification
    finding = {
        "title": "SQL Injection Found",
        "description": "Critical SQLi in search parameter",
        "severity": "CRITICAL",
        "target": "target.com"
    }

    print("Testing notification system...")
    print("(Set telegram_token and chat_id to receive real alerts)\n")

    result = notifier.notify_finding(finding)
    print(f"Notification sent: {result}")

    # Format preview
    notification = Notification(
        title="SQL Injection Found",
        message="Critical SQLi in /api/search",
        severity="CRITICAL",
        target="target.com"
    )

    print("\nTelegram format preview:")
    print(notification.format_telegram())
