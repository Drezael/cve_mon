# Wartung und Prüfsequenz

```bash
make check
make compose-check
CVE_DOCKER_SUDO=1 make infra-test
```

make check benötigt Compose-CLI, aber keinen Daemon und keine privaten Zertifikate.
make infra-test benötigt Daemonzugriff und erzeugt eigene kurzlebige Test-PKI, Projekt-/Netznamen
und freie Loopbackports. Es prüft auch Security-Fälle; infra-security ist die gezielte Teilmenge.
Shell-Einstiege: scripts/infrastructure/test-tls.sh, test-mtls.sh, test-network-isolation.sh.
Ein ausdrücklich angeforderter Docker-Lauf wird bei fehlendem Daemon nicht als Skip-Erfolg ausgegeben.

Start/Stop/Reload über infra-up/infra-down/infra-reload; Restart kann kontrolliert über
Compose erfolgen. Reloads/Renderaktionen eines Projekts nacheinander durchführen.
Keine Prune-, globale Restart- oder fremde Compose-Befehle. Test-Cleanup prüft zusätzlich
Eigentümerlabels und entfernt ausschließlich selbst angelegte Testobjekte.

Imageupdate: offiziellen Versions-/Digeststand prüfen, beide Compose-Modelle, Module,
TLS/mTLS, Routing, Limits, Rotation, Netzwerk und gesamte Qualitätsprüfung erneut ausführen.
Rollback: vorherigen versionierten Image-/Konfigurationsstand und gesichertes gültiges TLS-Paar
bereitstellen, nginx -t und Health prüfen. Keine automatischen Änderungen am Produktivsystem.

Logs über docker compose logs, begrenzt mit json-file max-size 10m/max-file 3,
Entwicklung max-size 5m. Access-/HTTP-Fehlerlogs sind JSON mit Request-ID, Zeit, Host,
Methodenkategorie, sanitierter Routenkategorie, Status, Dauer und Upstreamfeldern.
Querystrings, Authorization, Cookies, Zertifikate und Bodies werden nicht geloggt.
Native Requestfehlerlogs sind deaktiviert, weil deren Kontext ungefilterte Request-URIs
enthalten kann. HTTP-Fehler stehen stattdessen strukturiert im Accesslog;
nginx -t/Preflight melden Konfigurationsfehler mit nicht erfolgreichem Exit-Code.
Die CLI rahmt Betriebsfehler als JSON-Diagnosen, ohne Schlüssel-/Tokenwerte auszugeben.

Vor produktivem Betrieb Host-/Egress-Regeln und PKI betreiberseitig abschließen.
[Fehlerbehebung](../operations/nginx-troubleshooting.md), [Netzwerk](../security/network-isolation.md).
