"""Complete report mail content, safe HTML and bounded delivery with a lossless attachment."""

import io
import zipfile
from email.message import EmailMessage

from cve_notification.reports import render_report


def message() -> EmailMessage:
    mail = EmailMessage()
    mail["From"] = "monitor@example.test"
    mail["To"] = "owner@example.test"
    mail["Subject"] = "Original"
    mail["Message-ID"] = "<report@example.test>"
    mail.set_content("Original")
    return mail


def test_server_report_preserves_all_findings_and_escapes_server_names() -> None:
    mail = message()
    lines = [
        "Server: clean <script> | Aktuelle Schwachstellen: 0",
        "Keine aktuellen Findings vorhanden.",
        "Server: affected | Aktuelle Schwachstellen: 2",
        "CVE-2026-12345 | Hoch",
        "CVE-2026-12346 | Kritisch",
    ]
    assert render_report(mail, "Wochenbericht", lines, "https://dashboard.example.test")
    plain_part = mail.get_body(preferencelist=("plain",))
    html_part = mail.get_body(preferencelist=("html",))
    assert plain_part is not None and html_part is not None
    plain = plain_part.get_content()
    html = html_part.get_content()
    assert all(line in plain for line in lines)
    assert "<script>" not in html and "&lt;script&gt;" in html
    assert mail["Message-ID"] == "<report@example.test>"


def test_large_report_contains_all_cves_in_a_single_compressed_attachment() -> None:
    mail = message()
    lines = ["Server: complete | Aktuelle Schwachstellen: 3000"] + [
        f"CVE-2026-{i:05} | Betroffen | Bedrohung: Hoch | CVSS: 8.1 | EPSS: 10.0 %"
        for i in range(3000)
    ]
    assert render_report(mail, "Wochenbericht", lines, "https://dashboard.example.test")
    attachments = list(mail.iter_attachments())
    assert len(attachments) == 1 and attachments[0].get_filename() == "cve-bericht.zip"
    payload = attachments[0].get_payload(decode=True)
    assert isinstance(payload, bytes)
    with zipfile.ZipFile(io.BytesIO(payload)) as archive:
        body = archive.read("cve-bericht.txt").decode()
    assert all(line in body for line in lines)
    assert len(mail.as_bytes()) < 1048576
