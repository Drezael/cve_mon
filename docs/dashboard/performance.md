# Performance

Routen werden mit React.lazy geladen. Build ohne Sourcemaps, alle Ressourcen lokal, Gzip am bestehenden Nginx-Edge aktiviert. Statische gehashte Dateien: ein Jahr immutable; HTML und APIs: no-store. Requests haben acht Sekunden Frist und werden beim Wechsel abgebrochen. Kein unbeschränktes Hintergrundpolling; Sessionprüfung höchstens einmal pro Minute bei sichtbarem Tab. Fachlisten sind serverseitig paginiert. SQL aggregiert im Scope und lädt Listenmitgliedschaften/Finding-Zusammenfassungen gebündelt statt pro Zeile.

Reproduzierbare Baseline: make dashboard-check und CVE_DOCKER_SUDO=1 make dashboard-performance. Buildgrößen stehen in .runtime/test-reports/phase-20-dashboard-build.log; Browsermessungen und Screenshots im gleichen Reportverzeichnis. Keine externen Analytics.

Phase 21: Verwaltungsbereich wird als eigener Chunk nachgeladen. Selektoren und Verwaltungslisten laden 25 Einträge pro Seite (serverseitig maximal 100); Historien werden erst nach expliziter Auswahl geladen. Sortierungen über 100 Elemente verwenden relative Verschiebungen, niemals eine abgeschnittene Gesamt-Ersetzung. Uploadstatus pollt höchstens zwölfmal in fünfsekündigem Abstand. Kein Polling von Audit-/Benutzerlisten. Build-, Browser- und Messberichte: .runtime/test-reports/phase-21-*.
