# Tests und vollständige QA

`make check` prüft Python-Linting, Formatierung, Typen, die Standardauswahl von
Pytest, Repositoryverträge und Secrets. Die Standardauswahl schließt die in
[pyproject.toml](../../pyproject.toml) aufgeführten Integrationsmarker aus.
Ein erfolgreicher Lauf ersetzt daher keine vollständige Integrationsprüfung.

Für den vollständigen Python-Nachweis:

```bash
make qa-full
```

Der [Kampagnenrunner](../../scripts/testing/campaign.py) führt alle Testmodule aus,
mit explizit leerer Markerauswahl und getrennten, nacheinander laufenden Sitzungen.
Integrationsmodule erhalten jeweils eigene Sitzungen, damit ihre Labore, Queues
und Docker-Netze vor dem nächsten Modul abgebaut werden. Er meldet Fehler, Setupfehler und
übersprungene Fälle getrennt in privaten Logs, JUnit-XML und `summary.json` unter
`.runtime/test-reports/campaign-*`. Keine fremden Container oder Netze werden
bereinigt. Ein fehlender Docker-Daemon oder fehlende Voraussetzungen führen zum
Fehler, nicht zu einem erfolgreichen Skip. Vor den Deploymentmodulen werden
Release-Regressionsberichte aus den tatsächlich gelaufenen JUnit-Dateien
abgeleitet. Weitere Freigabevoraussetzungen bleiben gesondert geprüft; fehlende
Nachweise werden ausdrücklich als NO_GO dokumentiert.

Nach einer Korrektur kann das vollständige betroffene Modul erneut laufen.
Der [Abgleich](../../scripts/testing/reconcile.py) akzeptiert ausschließlich
vollständig bestandene Wiederholungen mit denselben Testidentitäten und
expliziter Begründung sowie SHA-256 beider JUnit-Dateien. Er erzeugt eine neue
Gesamtauswertung samt Herkunftsnachweis; die ursprünglichen Fehlerberichte
bleiben erhalten. Unvollständige Kampagnen, veränderte Berichte und ausgelassene
oder weiterhin fehlerhafte Fälle werden abgewiesen.

Voraussetzungen: eingerichtete Python-3.12-Umgebung (`make setup`), Docker Compose,
Netzwerkzugriff zum initialen Bezug gepinnter Images und Pakete sowie die
Hostwerkzeuge für isolierte Netzwerkprüfungen (`ip`, `nft`, `nsenter`, OpenSSL und
gegebenenfalls passwortloses `sudo` für diese Werkzeuge). Eigene Entwicklungsdaten
und Testprojekte benötigen ausreichend freien Speicher und Netzwerkkapazität.
`CVE_ENV_FILE` wählt standardmäßig `configuration/examples/development.env`.
Ungeteilte Aufrufe von `pytest -m ''` halten mehrere sessionweite Labore zugleich
und können auf gemeinsam genutzten Docker-Daemons den Adresspool erschöpfen.

Die Integrationsfixtures vergeben kleine `/28`-Subnetze aus `10.240.0.0/12`.
Vorher prüfen sie vorhandene Docker-Netze und lokale IPv4-Routen auf
Überschneidungen. `CVE_TEST_NETWORK_POOL` wählt bei VPN-/Firmennetzen einen
anderen privaten Pool; `CVE_TEST_COMPACT_NETWORKS=0` verwendet ausdrücklich die
Dockerdefaults. Diese Testergänzung gilt ausschließlich für isolierte
Testprojektnamen und ändert weder die Produktkonfiguration noch den Daemon.

Frontend separat mit der gepinnten lokalen Node-Version prüfen:

```bash
make dashboard-check
make dashboard-build
```

`make security-dependencies` prüft die gesperrten Bibliotheken;
`make security-images` prüft die tatsächlichen sieben Deploymentartefakte mit
Trivy. Beide Gates gehören zum Freigabenachweis. Browser-, Mail-, Restore- und
Recoveryprüfungen sind in den expliziten Integrationsbereichen enthalten.
Prüfprotokolle bleiben lokal unter `.runtime/test-reports/` und werden nicht veröffentlicht.
