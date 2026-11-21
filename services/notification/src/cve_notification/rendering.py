"""Data-only German multipart templates with a finite HTML vocabulary and no resources."""

import html
from datetime import datetime
from email.message import EmailMessage
from email.policy import SMTP
from html.parser import HTMLParser
from string import Template as Substitution
from typing import TYPE_CHECKING, Any, Literal
from urllib.parse import urlsplit
from zoneinfo import ZoneInfo

if TYPE_CHECKING:
    from cve_notification.contracts import Template

VARIABLES = frozenset({"title", "items", "link"})


class SafeHTML(HTMLParser):
    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag not in {"p", "a", "ul", "li", "strong", "br", "h2"}:
            raise ValueError("Unsupported HTML element")
        if attrs and not (tag == "a" and attrs == [("href", "${link}")]):
            raise ValueError("Only fixed dashboard links are supported")

    def handle_endtag(self, tag: str) -> None:
        if tag not in {"p", "a", "ul", "li", "strong", "br", "h2"}:
            raise ValueError("Unsupported HTML element")

    def handle_decl(self, decl: str) -> None:
        raise ValueError("HTML declarations are not supported")


def validate_template(template: "Template") -> None:
    if any(ord(c) < 32 or ord(c) == 127 for c in template.subject):
        raise ValueError("Invalid subject header")
    if not set(Substitution(template.subject).get_identifiers()) <= {"title"}:
        raise ValueError("Only a single-line title may appear in subjects")
    for value in [template.subject, template.text, template.html]:
        substitution = Substitution(value)
        if not substitution.is_valid() or not set(substitution.get_identifiers()) <= VARIABLES:
            raise ValueError("Unsupported template variable")
    parser = SafeHTML(convert_charrefs=True)
    parser.feed(template.html)
    parser.close()


def dashboard(base: str) -> str:
    parsed = urlsplit(base)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
        or parsed.path not in {"", "/"}
    ):
        raise ValueError("Fixed HTTPS dashboard origin required")
    return base.rstrip("/")


EVENT_LABELS = {
    "created": "Neues Finding",
    "confirmed_affected": "Betroffenheit bestätigt",
    "potentially_affected": "Mögliche Betroffenheit",
    "reopened": "Finding wiedereröffnet",
    "priority_changed": "Priorität geändert",
    "resolved": "Technische Behebung nachgewiesen",
    "closed": "Finding geschlossen",
    "assigned": "Zuständigkeit geändert",
    "deadline_approaching": "Bearbeitungsfrist nähert sich",
    "overdue": "Bearbeitungsfrist überschritten",
    "exception_approved": "Risikoausnahme genehmigt",
    "exception_approaching": "Risikoausnahme läuft ab",
    "exception_expired": "Risikoausnahme abgelaufen",
    "exception_revoked": "Risikoausnahme widerrufen",
}


def finding_line(finding: dict[str, Any], event: str, timezone: str = "UTC") -> str:
    basis = finding.get("priority_basis") or {}
    cvss = basis.get("cvss") or {}
    epss = basis.get("epss") or {}
    current_epss = epss.get("score") if not epss.get("is_stale", True) else None
    detected = finding.get("first_seen_at")
    displayed = (
        detected.astimezone(ZoneInfo(timezone)).isoformat()
        if isinstance(detected, datetime)
        else "unbekannt"
    )
    return (
        f"{EVENT_LABELS.get(event, event)}: {finding[('cve_id')]} | Server: {
            finding[('server_name')]
        } | "
        f"Finding: {finding['id']} | Priorität: {finding['current_priority']} | "
        f"Status: {finding['status']} | CVSS: {cvss.get('calculated_score', 'unbekannt')} | "
        f"KEV: {basis.get('kev_status', 'unknown')} | "
        f"EPSS: {current_epss if current_epss is not None else 'unbekannt'} | "
        f"Erkannt: {displayed} | "
        f"Datenbasis: {'veraltet' if finding.get('is_stale') else 'aktuell'}"
    )


def message(
    template: "Template",
    *,
    notification_id: str,
    sender: str,
    recipient: str,
    base: str,
    items: list[str],
    section: Literal["findings", "status"] = "findings",
) -> EmailMessage:
    from cve_notification.rules import address

    if not address(sender, []) or not address(recipient, []):
        raise ValueError("Invalid envelope")
    link = dashboard(base) + "/" + section
    values = {"title": "Sicherheitsbenachrichtigung", "items": "\n".join(items), "link": link}
    subject = Substitution(template.subject).substitute(values)
    if any(ord(c) < 32 or ord(c) == 127 for c in subject):
        raise ValueError("Unsafe subject")
    result = EmailMessage(policy=SMTP)
    result["From"], result["To"], result["Subject"] = sender, recipient, subject
    result["Message-ID"] = f"<{notification_id}@cve-monitoring.invalid>"
    result["X-CVE-Notification-ID"] = notification_id
    result.set_content(Substitution(template.text).substitute(values))
    result.add_alternative(
        Substitution(template.html).substitute(
            {k: html.escape(v, quote=True) for k, v in values.items()}
        ),
        subtype="html",
    )
    return result
