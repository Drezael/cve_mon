# Phase-5-Testmatrix

`make mail-test`: echte isolierte Postfix-/Envoy-Container, private Test-CAs,
eigener DNS und SMTP-Provider; keine externen Empfänger oder Providerkonten.
Eigene Projektlabels, keine Hostports, Namespacefilter ausschließlich eigener Container.
Cleanup entfernt nur eigene Fixturecontainer, Testvolume und Netzwerke; normale Daten bleiben erhalten.

| Bereich | Reproduzierbarer Nachweis |
|---|---|
| Build/Policy/Compose | `tests/test_mail_policy.py`: Lock, keine Wildcards/Injektion, gehärtetes Modell |
| Positiver Versand | `test_submission.py`: mTLS → Queue → Envoy → Provider, echtes SNI/TLS/AUTH/DATA |
| Interner Missbrauch | keine/ungültige/fremde/abgelaufene Zertifikate, nicht gepinnte CA-Clients, unzulässige Sender/Empfänger/Header, Nullsender, Übergröße |
| Externes TLS | `test_reliability.py`: falscher Name (nur Envoy!), fremde CA, Ablauf, TLS1.1, kein STARTTLS; keine AUTH-/DATA-Weitergabe |
| Ausfall | AUTH-Fehler, 450, Verbindungsabbruch, fehlendes Banner, EHLO-Timeout, ungültiges Banner; native Deferred-Queue und Recovery |
| Dauerhafter Fehler | 550, nativer leerer Bounce-Sender, keine Originalbody-Kopie |
| Persistenz | konkrete Queue-ID nach echtem Restart und anderem Container nach Recreate vorhanden, danach zugestellt |
| Kapazität/Health | künstlich unerfüllbare Freiplatzreserve, keine Annahme, Health schlägt fehl, Rückkehr nach Korrektur |
| Vertraulichkeit | keine Body-/Adressmarker oder Credentialwerte im Dienstlog |
| Rotation | `test_operations.py`: alter Pin entzogen, neuer akzeptiert; Providerpasswort ohne Nachrichtenverlust gewechselt |
| Backup/Restore | gestoppte native Queue, private Archive, nichtleere Queue abgelehnt, frische Queue wiederhergestellt und zugestellt |
| Netzgrenzen | direkter SMTP-Connect abgewiesen; Einlieferung über Egressinterface abgewiesen |

Zusätzlich verpflichtend `make check`, `make infra-test`, `make db-test`, `make envoy-test`.
SMTP-Test-Provider verwendet absichtlich ungültige Namen und private Zertifikate;
keine produktiven Secrets nötig. Eine echte Providerfreigabe bleibt Betreiberaufgabe.

Weitere native Nachweise: Health bei nicht schreibbarem incoming-Verzeichnis,
Retry ohne manuellen Flush, Envoy-Ausfall bei weiterhin gesundem Queue-Dienst,
Queue-Lebensdauer einschließlich begrenztem unzustellbarem Bounce, sowie erwartetes
Duplikat bei Abbruch nach DATA vor 250. `test_postfix_config.py` prüft effektive
Parameter, Dienstports, Paketversion, Laufzeit-Dateirechte und Container-Härtung.

Das separate Provider-Testnetz ist ebenfalls als Docker-internal angelegt. Es gibt
keine Default-Internetroute; die öffentliche Testadresse ist ausschließlich ein
Loopback-Alias im eigenen Provider-Namespace mit expliziter Route im eigenen Envoy.
Damit kann auch während eines Recreate kein Retry versehentlich ein reales SMTP-Ziel erreichen.
