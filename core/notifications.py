import ipaddress
import json
import smtplib
import time
from email.message import EmailMessage
from pathlib import Path
from typing import Any, Optional

import requests


class NotificationHub:
    """Centralized alerting hub for Slack, Email, and Telegram notifications."""

    def __init__(self, config: dict[str, Any]) -> None:
        self.config = config
        self.cooldown_seconds = int(config.get("cooldown_seconds", 300))
        self._last_sent: dict[tuple[str, str], float] = {}

    def _can_send(self, channel: str, dedupe_key: str) -> bool:
        now = time.time()
        key = (channel, dedupe_key)
        last = self._last_sent.get(key, 0.0)
        if now - last < self.cooldown_seconds:
            return False
        self._last_sent[key] = now
        return True

    def send_slack(self, message: str, dedupe_key: str = "global") -> bool:
        webhook = self.config.get("slack_webhook")
        if not webhook:
            return False
        if not self._can_send("slack", dedupe_key):
            return False

        payload = {"text": f"SHADOW-TOOLZ ALERT: {message}"}
        try:
            response = requests.post(webhook, json=payload, timeout=5)
            response.raise_for_status()
            return True
        except Exception as exc:
            print(f"[notifications] slack delivery failed: {exc}")
            return False

    def send_email(self, subject: str, body: str, dedupe_key: str = "global") -> bool:
        email_user = self.config.get("email_user")
        email_pass = self.config.get("email_pass")
        admin_email = self.config.get("admin_email")
        smtp_host = self.config.get("smtp_host", "smtp.gmail.com")
        smtp_port = int(self.config.get("smtp_port", 465))
        smtp_timeout = int(self.config.get("smtp_timeout", 10))

        if not email_user or not email_pass or not admin_email:
            return False
        if not self._can_send("email", dedupe_key):
            return False

        msg = EmailMessage()
        msg.set_content(body)
        msg["Subject"] = f"SHADOW-TOOLZ: {subject}"
        msg["From"] = email_user
        msg["To"] = admin_email

        try:
            with smtplib.SMTP_SSL(smtp_host, smtp_port, timeout=smtp_timeout) as smtp:
                smtp.login(email_user, email_pass)
                smtp.send_message(msg)
            return True
        except Exception as exc:
            print(f"[notifications] email delivery failed: {exc}")
            return False

    def send_telegram(self, message: str, dedupe_key: str = "global") -> bool:
        bot_token = self.config.get("telegram_bot_token")
        chat_id = self.config.get("telegram_chat_id")

        if not bot_token or not chat_id:
            return False
        if not self._can_send("telegram", dedupe_key):
            return False

        url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
        payload = {
            "chat_id": chat_id,
            "text": f"SHADOW-TOOLZ ALERT: {message}",
            "disable_web_page_preview": True,
        }

        try:
            response = requests.post(url, json=payload, timeout=5)
            response.raise_for_status()
            return True
        except Exception as exc:
            print(f"[notifications] telegram delivery failed: {exc}")
            return False


class BusinessNotificationHub:
    """Multi-tenant notification hub for MSSP operations.
    
    Routes alerts to business-specific contacts based on IP address matching
    against registered network ranges in the targets registry.
    """

    def __init__(
        self, 
        targets_file: str = "data/targets.json",
        fallback_config: Optional[dict] = None
    ) -> None:
        """
        Initialize multi-tenant hub.
        
        Args:
            targets_file: Path to targets.json registry
            fallback_config: Fallback NotificationHub config (e.g., for global alerts)
        """
        self.targets_file = targets_file
        self.targets: dict[str, Any] = {}
        self.fallback_hub = NotificationHub(fallback_config or {})
        self._load_targets()

    def _load_targets(self) -> None:
        """Load targets registry from JSON file."""
        try:
            with open(self.targets_file, 'r') as f:
                self.targets = json.load(f)
            print(f"[business-hub] Loaded {len(self.targets)} targets from {self.targets_file}")
        except Exception as exc:
            print(f"[business-hub] Failed to load targets: {exc}")
            self.targets = {}

    def get_business_for_ip(self, ip_str: str) -> tuple[Optional[str], Optional[dict]]:
        """
        Match an IP address to a registered business.
        
        Returns:
            (business_name, business_config) or (None, None) if no match
        """
        if not ip_str:
            return None, None

        try:
            ip = ipaddress.ip_address(ip_str)
        except ValueError:
            return None, None

        for business_name, config in self.targets.items():
            if not config.get("enabled", True):
                continue
            try:
                network = ipaddress.ip_network(config.get("network_range", ""), strict=False)
                if ip in network:
                    return business_name, config
            except ValueError:
                print(f"[business-hub] Invalid network range for {business_name}: {config.get('network_range')}")
                continue

        return None, None

    def get_business_for_packet(
        self,
        module_name: str,
        payload: Optional[dict[str, Any]] = None,
    ) -> tuple[Optional[str], Optional[dict]]:
        """Match a telemetry packet to a business by IP, then by module mapping."""
        payload = payload or {}
        ip_address = payload.get("ip") or payload.get("source_ip") or payload.get("target_ip")
        if ip_address:
            business_name, business_config = self.get_business_for_ip(str(ip_address))
            if business_name and business_config:
                return business_name, business_config

        module_key = str(module_name).lower()
        for business_name, config in self.targets.items():
            if not config.get("enabled", True):
                continue
            modules = [str(m).lower() for m in config.get("modules", [])]
            if module_key in modules:
                return business_name, config

        return None, None

    def send_business_alert(
        self,
        business_name: str,
        business_config: dict,
        subject: str,
        message: str,
        event_data: dict,
        dedupe_key: str = "global",
        send_slack: bool = True,
        send_email: bool = True,
        send_telegram: bool = False,
    ) -> dict[str, bool]:
        """
        Send alert to a specific business across all configured channels.
        
        Returns dict with channel delivery status.
        """
        results = {"email": False, "slack": False, "telegram": False}

        # Email to all registered contacts
        if send_email:
            contacts = business_config.get("contacts", [])
            for contact in contacts:
                results["email"] |= self._send_email_to(
                    contact,
                    subject,
                    f"Business: {business_name}\n\n{message}",
                    dedupe_key=dedupe_key
                )

        # Slack to business channel
        if send_slack:
            slack_channel = business_config.get("slack_channel")
            if slack_channel:
                results["slack"] |= self._send_slack_to(
                    slack_channel,
                    f"**[{business_name}]** {message}",
                    dedupe_key=dedupe_key
                )

        # Telegram (optional, uses fallback config)
        if send_telegram:
            results["telegram"] |= self.fallback_hub.send_telegram(
                f"[{business_name}] {message}",
                dedupe_key=dedupe_key
            )

        return results

    def _send_email_to(self, recipient: str, subject: str, body: str, dedupe_key: str = "global") -> bool:
        """Send email to specific recipient using fallback config credentials."""
        email_user = self.fallback_hub.config.get("email_user")
        email_pass = self.fallback_hub.config.get("email_pass")
        smtp_host = self.fallback_hub.config.get("smtp_host", "smtp.gmail.com")
        smtp_port = int(self.fallback_hub.config.get("smtp_port", 465))
        smtp_timeout = int(self.fallback_hub.config.get("smtp_timeout", 10))

        if not email_user or not email_pass:
            return False

        msg = EmailMessage()
        msg.set_content(body)
        msg["Subject"] = f"SHADOW-TOOLZ: {subject}"
        msg["From"] = email_user
        msg["To"] = recipient

        try:
            with smtplib.SMTP_SSL(smtp_host, smtp_port, timeout=smtp_timeout) as smtp:
                smtp.login(email_user, email_pass)
                smtp.send_message(msg)
            return True
        except Exception as exc:
            print(f"[business-hub] email delivery to {recipient} failed: {exc}")
            return False

    def _send_slack_to(self, channel: str, message: str, dedupe_key: str = "global") -> bool:
        """Send Slack message to specific channel (requires per-channel webhook or bot token)."""
        # For now, use the global webhook (this can be enhanced with per-business webhooks)
        webhook = self.fallback_hub.config.get("slack_webhook")
        if not webhook:
            return False

        payload = {
            "channel": channel,
            "text": f"SHADOW-TOOLZ ALERT: {message}"
        }
        try:
            response = requests.post(webhook, json=payload, timeout=5)
            response.raise_for_status()
            return True
        except Exception as exc:
            print(f"[business-hub] slack delivery to {channel} failed: {exc}")
            return False

    def reload_targets(self) -> None:
        """Reload targets from file (useful for hot updates)."""
        self._load_targets()

    def list_targets(self) -> dict[str, Any]:
        """Return all configured targets."""
        return self.targets
