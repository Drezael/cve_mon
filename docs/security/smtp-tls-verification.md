# Externe SMTP-TLS-Identität

Relayhost ist der Netzwerkpfad `[cve-egress-proxy]:1587`. Die Identität ist der explizite
Provider-FQDN aus der Betreiberpolicy: native TLS-Policy `secure match=FQDN servername=FQDN`.
Mit Provider-CA prüfen, Mindestversion TLS1.2, niemals zu Klartext zurückfallen.
AUTH PLAIN/LOGIN nur nach verifiziertem TLS. Falscher Name, CA, Ablauf, TLS1.1 oder
fehlendes STARTTLS lassen die Nachricht in Postfix zur Wiederholung zurück.
Ein Zertifikat ausschließlich für Envoy ist selbst bei vertrauenswürdiger CA ungültig.
[Testmatrix](../testing/phase-05-test-matrix.md), [Details](postfix-security.md).
