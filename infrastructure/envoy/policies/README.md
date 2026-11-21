# Egress-Policy

Versionierte Host-/Port-/Protokoll-/Client-/Methoden-Allowlist, Default Deny. Schema und
zusätzliche semantische Prüfung in scripts/infrastructure/envoy.py. Keine Wildcards, IP-Literale
oder impliziten unbekannten Clientgruppen. CLI: make envoy-policy-check.
SMTP ist bis zur ausdrücklichen Angabe eines echten Betreiber-Smarthosts deaktiviert.
Die Policy ist keine alleinige Sicherheitsgrenze: tatsächliche DNS-Ziele werden durch nft in
eigenen Netznamespaces blockiert. Die Runtime-Suite beweist die Wirkung an echten Sockets.
