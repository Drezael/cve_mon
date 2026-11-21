# Übernahme nach GitHub

Das Repository ist für einen eigenständigen Import vorbereitet. Es benötigt keinen
zweiten Ansible-Checkout. Zentraler Einstieg ist `./cve_mon`; Beispiele und
Prüfkonfigurationen liegen in Unterverzeichnissen.

## Lokale Prüfungen

```sh
./cve_mon setup
CVE_ENV_FILE=configuration/examples/development.env make check
make github-check inventory-collect-syntax
make dashboard-check
```

`github-check` prüft dieselbe Dateiauswahl, die Git übernehmen kann, einschließlich
neuer Dateien. Auch bereits versionierte, später ignorierte private Dateien
werden abgewiesen. Die Secret-Prüfung bleibt ein separater Teil von `make check`.

Die `.env`, `.venv`, `.runtime`, Tool-Caches, Datenbanken, Zertifikate, private
Schlüssel und lokale Sicherungen werden nicht veröffentlicht. Ein Repository-
Import ist kein Laufzeitbackup; Betriebsdaten werden getrennt verwaltet.

## Repository anlegen und Quellstand übernehmen

Auf GitHub ein leeres Repository ohne zusätzlich erzeugte README oder Lizenz
anlegen. Sichtbarkeit bewusst wählen. Dieses Projekt enthält bereits seine
Lizenz und Dokumentation. Danach die eigene Repository-URL verwenden:

```sh
git add .
git diff --cached --stat
git status --short
git commit -m "Initial import of CVE Monitor"
git remote add origin URL_DES_EIGENEN_REPOSITORYS
git push -u origin main
```

Vor dem Commit die vorgemerkten Dateien prüfen. Lokale Geheimnisse nicht mit
`git add -f` übernehmen. Existiert bereits ein Remote oder eine Git-Historie,
die vorhandene Konfiguration statt eines neuen Initialimports verwenden.

## GitHub-Konfiguration

- Pull Requests und Pushes führen Python-/Vertrags-/Secret-Prüfungen und
  Dashboard-Prüfungen aus. Actions und Werkzeugversionen sind festgelegt.
- Docker-, Ansible-SSH-, Datenbank- und Supply-Chain-Tests lassen sich über
  **Actions → Integration → Run workflow** gezielt starten.
- Private Vulnerability Reporting im Repository aktivieren und einen privaten
  Kontaktweg sowie einen Kontakt für kommerzielle Lizenzanfragen bereitstellen.
- Nach einem erfolgreichen ersten CI-Lauf die Quality-Jobs als erforderliche
  Prüfungen für Änderungen an `main` konfigurieren.

Die [PolyForm-Noncommercial-Lizenz](../../LICENSE) erlaubt keine allgemeine
kommerzielle Nutzung. Eine separate kommerzielle Vereinbarung wird durch einen
GitHub-Import nicht ersetzt. [Lizenzierungsmodell](../legal/licensing.md).

Die Integrations- und Scanprüfungen sind technische Nachweise. Ein erfolgreicher
Quellimport erteilt keine Produktionsfreigabe und hebt bestehende Befunde nicht auf.

Die alten Entwicklungspläne unter `docs/history/plans/` und
`docs/development/phase-*-plan.md` bleiben lokal und sind vom GitHub-Import
ausgeschlossen. Der veröffentlichte Checkout benötigt diese Dateien nicht.
