"""One n8n-authorized test mail; encrypted settings stay out of queue payloads."""

import smtplib
import ssl
from email.message import EmailMessage
from email.utils import formatdate, make_msgid
from typing import Any

from cve_common.smtp_settings import SMTPConfig, SMTPKeyring

from scripts.database import manage as db
from scripts.infrastructure.manage import Config


def deliver(
    settings: SMTPConfig,
    credentials: dict[str, Any],
    recipients: list[str],
    identity: str,
    *,
    capture_host: str | None = None,
) -> str | None:
    client = None
    sending = False
    authenticating = False
    try:
        client = smtplib.SMTP(
            capture_host if settings.is_mailhog and capture_host else settings.host,
            settings.port,
            timeout=10,
        )
        client.ehlo()
        if not settings.is_mailhog:
            client.starttls(context=ssl.create_default_context())
            client.ehlo()
            authenticating = True
            client.login(credentials["username"], credentials["password"])
            authenticating = False
        message = EmailMessage()
        message["From"] = settings.sender
        message["To"] = ", ".join(recipients)
        message["Subject"] = "CVE Monitor: SMTP-Testmail"
        message["Date"] = formatdate(localtime=False)
        message["Message-ID"] = make_msgid(idstring=identity, domain="cve-monitor.local")
        message.set_content(
            "Die gespeicherten SMTP-Einstellungen wurden erfolgreich "
            "getestet.\nDiese Nachricht wurde manuell über den CVE Monitor angefordert.\n"
        )
        sending = True
        refused = client.send_message(message, from_addr=settings.sender, to_addrs=recipients)
        return "SMTP_REJECTED" if refused else None
    except smtplib.SMTPAuthenticationError:
        return "SMTP_AUTHENTICATION_FAILED"
    except smtplib.SMTPNotSupportedError:
        return "SMTP_AUTHENTICATION_FAILED" if authenticating else "SMTP_TLS_FAILED"
    except ssl.SSLError:
        return "SMTP_TLS_FAILED"
    except (smtplib.SMTPResponseException, smtplib.SMTPRecipientsRefused):
        return "SMTP_REJECTED"
    except (OSError, smtplib.SMTPException):
        return "SMTP_OUTCOME_UNKNOWN" if sending else "SMTP_CONNECTION_FAILED"
    finally:
        if client:
            client.close()


def process(config: Config) -> None:
    from scripts.automation_executor.agent import exclusive

    with exclusive(config):
        with db.connect(config, "dashboard_admin") as s:
            claimed = s.execute("SELECT automation.claim_smtp_test() AS id").fetchone()
            if not claimed or claimed["id"] is None:
                return
            test = s.execute(
                "SELECT * FROM automation.smtp_tests WHERE id=%s", (claimed["id"],)
            ).fetchone()
            assert test
            saved = s.execute(
                "SELECT * FROM automation.smtp_configs WHERE id=%s", (test["configuration_id"],)
            ).fetchone()
            assert saved
            latest = s.execute(
                "SELECT id FROM automation.smtp_configs WHERE owner_id IS NOT "
                "DISTINCT FROM %s ORDER BY version DESC LIMIT 1",
                (saved["owner_id"],),
            ).fetchone()
        error: str | None = "SMTP_SETTINGS_CHANGED"
        if (
            latest
            and latest["id"] == saved["id"]
            and saved["state"] == "applied"
            and saved["configuration"]["enabled"]
        ):
            try:
                ring = SMTPKeyring(
                    config.secrets_base / "services" / config.project / "smtp-keys.json"
                )
                credentials = ring.decrypt(
                    saved["id"], saved["key_id"], bytes(saved["credentials"])
                )
                settings = SMTPConfig.model_validate(
                    {k: v for k, v in saved["configuration"].items() if k != "mode"}
                )
                from scripts.application.manage import peer

                capture_host = (
                    peer(config, "cve-mailhog", "cve_outbound") if settings.is_mailhog else None
                )
                if settings.is_mailhog and not capture_host:
                    error = "SMTP_CONNECTION_FAILED"
                else:
                    error = deliver(
                        settings,
                        credentials,
                        test["recipients"],
                        str(test["id"]),
                        capture_host=capture_host,
                    )
            except Exception:
                # Never log credentials, SMTP replies, or raw exception messages.
                error = "SMTP_OUTCOME_UNKNOWN"
        with db.connect(config, "dashboard_admin") as s:
            s.execute(
                "SELECT automation.finish_smtp_test(%s,%s,%s)",
                (test["id"], test["lease_token"], error),
            )
