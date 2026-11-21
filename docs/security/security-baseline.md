# Sicherheitsbaseline Phase 23

Erfasst am 10.11.2026 vor Anwendungsänderungen: 13 gesunde Dienste, 4 fremde Nextcloud-Container, 364 Pythonquelldateien und vollständige Hashes von 150 Anwendungstabellen. Quelle: `.runtime/test-reports/phase-23-before.json`.

Nginx ist einziger veröffentlichter Eingang; PostgreSQL, n8n, SMTP und Envoy-Admin besitzen keine öffentlichen Hostports. Python/Envoy/Nginx/n8n laufen unprivilegiert, alle Rootdateisysteme sind read-only, Capabilities standardmäßig entfernt. PostgreSQL- und Postfix-Startausnahmen sind dienstspezifisch. Docker meldet Seccomp builtin und AppArmor default. Ressourcen-, PID-, Datei- und Loglimits sind vorhanden. Die Auflösung beider Composevarianten wird bereits streng validiert.

Authentifizierung besitzt Passwortverifikatoren, verschlüsselte MFA-Geheimnisse, kurzlebige serverseitige Sessions, Origin/CSRF, frische MFA-Bestätigung und aktuelle Rechteprüfung. Es gibt keine zweite Authentifizierung und keine Autorisierung aus Browserheadern. Maschinenzugang verlangt mTLS und zertifikats-/servergebundene Tokens. Uploadparser besitzen Schema-, Tiefen-, Größen-, Zeit- und Prozesslimits. Datenbankrollen sind getrennt, Runtime führt keine Migration aus. Audit und Evidenz sind append-only.

Offene Ausgangslücken: generische kleine JSON-Requests erlaubten die Standardparser-Mehrdeutigkeit doppelter Schlüssel; PostgreSQL war nicht in allen uniformen Compose-Namespace-/Security-Opt-Guards enthalten; Backups waren privat und gehasht, aber ohne integrierten authentifizierten Dateiumschlag. Die neue Baseline machte JIT-Kompilation und Vollprojektion vor Pagination sichtbar. Image-Sicherheitsbefunde wurden erstmals vollständig erfasst; ihr Status ist kein Beleg für Ausnutzbarkeit, aber auch kein Anlass für automatische Entwarnung.

Anwendungsdependencies sind exakt/hashgebunden, Frontend besitzt package-lock. Die bestehende CI ist auf Commitdigests gepinnt; Scanner/SBOM und Herkunftsnachweis werden in dieser Phase ergänzt. Weder bestehende Secrets noch Versandfreigaben werden verändert.
