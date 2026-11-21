"""Mandatory STARTTLS client certificate; DATA ambiguity is never automatically retried."""

import re
import smtplib
import ssl
from dataclasses import dataclass
from email.message import EmailMessage
from pathlib import Path
from typing import Literal


@dataclass(frozen=True)
class Outcome:
    status: Literal[
        "relay_accepted", "retryable_failure", "permanent_failure", "submission_uncertain"
    ]
    code: str
    queue_id: str | None = None
    smtp_code: int | None = None


class Adapter:
    def __init__(
        self,
        *,
        ca: Path,
        certificate: Path,
        key: Path,
        host: str = "cve-mail-relay",
        port: int = 2525,
        timeout: float = 5,
    ) -> None:
        if host != "cve-mail-relay" or port != 2525 or not 0 < timeout <= 10:
            raise ValueError("Only the internal Postfix relay is allowed")
        self._tls_files = (ca, certificate, key)
        self.context = self.tls_context()
        self.host, self.port, self.timeout = host, port, timeout

    def tls_context(self) -> ssl.SSLContext:
        files = getattr(self, "_tls_files", None)
        if files is None:
            return self.context
        ca, certificate, key = files
        context = ssl.create_default_context(cafile=str(ca))
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(str(certificate), str(key))
        return context

    def submit(
        self,
        message: EmailMessage,
        *,
        envelope_sender: str | None = None,
        recipients: list[str] | None = None,
    ) -> Outcome:
        in_data = False
        client: smtplib.SMTP | None = None
        try:
            # The host maintains these mounted certificates. Each submission
            # sees renewals without restarting this process or its container.
            context = self.tls_context()
            client = smtplib.SMTP(host="cve-mail-submit", port=self.port, timeout=self.timeout)
            # Route on the internal bridge; retain the certificate's canonical TLS identity.
            client._host = self.host  # type: ignore[attr-defined]
            client.ehlo()
            client.starttls(context=context)
            client.ehlo()
            for method, value in [
                (client.mail, envelope_sender or str(message["From"])),
                *[(client.rcpt, address) for address in (recipients or [str(message["To"])])],
            ]:
                code, _ = method(value)
                if code >= 400:
                    return Outcome(
                        "retryable_failure" if code < 500 else "permanent_failure",
                        "envelope_rejected",
                        smtp_code=code,
                    )
            # The durable attempt has already been committed by the dispatcher.
            in_data = True
            code, reply = client.data(message.as_bytes())
            if code != 250:
                return Outcome(
                    "retryable_failure" if 400 <= code < 500 else "permanent_failure",
                    "data_rejected",
                    smtp_code=code,
                )
            match = re.search(rb"queued as ([A-Za-z0-9]{5,64})", reply, re.I)
            return Outcome(
                "relay_accepted",
                "postfix_accepted",
                match[1].decode("ascii") if match else None,
                code,
            )
        except smtplib.SMTPDataError as error:
            return Outcome(
                "retryable_failure" if 400 <= error.smtp_code < 500 else "permanent_failure",
                "data_rejected",
                smtp_code=error.smtp_code,
            )
        except ssl.SSLError:
            return Outcome("permanent_failure", "tls_validation_failed")
        except smtplib.SMTPResponseException as error:
            return Outcome(
                "retryable_failure" if 400 <= error.smtp_code < 500 else "permanent_failure",
                "smtp_rejected",
                smtp_code=error.smtp_code,
            )
        except (TimeoutError, OSError, smtplib.SMTPException):
            return Outcome(
                "submission_uncertain" if in_data else "retryable_failure", "smtp_connection_lost"
            )
        finally:
            # QUIT failures cannot turn a confirmed DATA acceptance into a retry.
            if client is not None:
                client.close()
