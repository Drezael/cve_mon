"""Internal SMTP submission; TLS verification always enabled, no SMTP debug transcript."""

import json
import smtplib
import ssl
import sys
from typing import Any

value = json.load(sys.stdin)
result: dict[str, Any] = {}
try:
    with smtplib.SMTP(value.get("host", "cve-mail-relay"), 2525, timeout=5) as smtp:
        code, _ = smtp.ehlo()
        result["ehlo"] = code
        if value.get("tls", True):
            context = ssl.create_default_context(cafile="/client/client-ca.crt")
            if value.get("cert", "notification") != "none":
                name = value.get("cert", "notification")
                context.load_cert_chain("/client/" + name + ".crt", "/client/" + name + ".key")
            smtp.starttls(context=context)
            smtp.ehlo()
        if value.get("probe", False):
            result["starttls"] = True
        else:
            sender = value.get("sender", "alerts@notifications.invalid")
            recipient = value.get("recipient", "recipient@example.invalid")
            message = value.get(
                "message",
                "From: alerts@notifications.invalid\r\nTo: "
                + recipient
                + "\r\nSubject: isolated test\r\n\r\nprivate-body-marker\r\n",
            )
            if value.get("mail_only"):
                result["code"] = smtp.mail(sender)[0]
            else:
                smtp.sendmail(sender, [recipient], message)
                result["accepted"] = True
except Exception as error:
    result = {"error": type(error).__name__}
    if isinstance(error, smtplib.SMTPResponseException):
        result["code"] = error.smtp_code
    if isinstance(error, smtplib.SMTPRecipientsRefused):
        result["code"] = next(iter(error.recipients.values()))[0]
print(json.dumps(result))
