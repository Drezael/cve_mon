# SMTP-Sicherheitsgrenzen

Die vollständige Kette ist interner mTLS-Client → Postfix → Envoy TCP → externes
STARTTLS/AUTH. CA-Prüfung und Zertifikatpin sind unabhängige Voraussetzungen.
`mynetworks` und `relay_domains` sind leer; keine netzweite Relayfreigabe.
Der Paket-Master benötigt root und exakt CHOWN, DAC_OVERRIDE, FOWNER, SETUID,
SETGID, KILL. SMTP-, Queue- und TLS-Worker wechseln zu postfix. Kein NET_ADMIN,
NET_RAW, privilegierter Betrieb, Hostnetz oder Docker-Socket. Read-only Rootfilesystem,
private tmpfs für generierte Schlüssel-/AUTH-Maps. Siehe ADR-0023.

Envoy akzeptiert root ausschließlich für den exakt bezeichneten Phase-5-Mailcontainer
mit passenden Projektlabels, Image und sechs Capabilities; unverändert restriktive
Prüfung aller anderen Clients. Der Client-OUTPUT-Filter erlaubt ausschließlich Envoy
SMTP und Docker-DNS sowie Antworten. Zusätzlich ist INPUT auf den internen
SMTP-Listener begrenzt. Ein Container-Neustart erneuert die Bootbindung und sperrt
bis zur erneuten Guardinstallation. Keine Änderung der Host-Firewall.

TLS `encrypt` allein genügt extern nicht: `secure` mit explizitem Provider-`match`
verhindert die Verwechslung des TCP-Zwischenhosts mit der TLS-Identität.
Credentials existieren nur in privaten Secretdateien und der privaten Postfix-Map.
Envoy besitzt weder TLS-Terminierung noch diese Mounts. Logs redigieren per Allowlist.
Keine Roh-SMTP-Ausgabe im Produktbetrieb. SMTP-Ende-zu-Ende-Verschlüsselung schützt
nicht die Queue auf dem Datenträger: verschlüsselte Host-/Backup-Datenträger vorsehen.

Primärquellen: [TLS](https://www.postfix.org/TLS_README.html),
[Parameter](https://www.postfix.org/postconf.5.html),
[Restriktionsklassen](https://www.postfix.org/RESTRICTION_CLASS_README.html).
