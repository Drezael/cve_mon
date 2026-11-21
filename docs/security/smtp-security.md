# SMTP-Sicherheit

Vier unabhängige Grenzen: Netzzugang, CA-validierter Client mit SHA256-Pin,
explizite Sender/Empfänger, verifizierter Provider vor AUTH. Keine Netzwerk-
Relayfreigabe, keine öffentlichen SMTP-Ports, keine direkten externen Verbindungen.
[Implementierte Schutzmaßnahmen](postfix-security.md),
[Negativtestmatrix](../testing/phase-05-test-matrix.md).
