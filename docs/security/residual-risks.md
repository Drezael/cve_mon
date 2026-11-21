# Restrisiken und Freigabegrenzen Phase 23

Die abschließenden 13 Image- und fünf Dependencygraphscans enthalten keine blockierenden HIGH-/CRITICAL-/UNKNOWN-Befunde. Native Komponentenproben prüfen zusätzlich die vom ersten Alpine-Scan nicht hinreichend erfassten eingebetteten Bibliotheken. Es bestehen keine genehmigten Ausnahmen und keine pauschale Risikoakzeptanz. Die 694 früheren Fundstellen sind historische Ausgangsnachweise; aktuelle Daten stehen im [Befundregister](phase-23-image-findings.md) und [Behebungsnachweis](phase-23-remediation.md).

Architekturgrenzen bleiben: Ein kompromittierter API-Prozess kann mehrere dort benötigte Kontextcredentials erreichen; getrennte Pools sind keine Prozessisolation. Ein kompromittierter Inventarcontroller kann seinen erlaubten Inhalt fälschen. Zulässige externe Quellen können inhaltlich falsch sein. SMTP kann bei Quittungsverlust keine sichere Aussage über die externe Zustellung liefern. Status ist kein unabhängiger externer Beobachter. Ohne Quellfristen bleibt Freshness UNKNOWN. Host-/DB-Owner werden als vertrauenswürdige Betreiber vorausgesetzt.

Backupverlust ist ohne separat wiederherstellbaren Schlüssel nicht behebbar. Lokale Restore-/Lastzeiten sind keine zugesagte Produktionskapazität. Reale RPO/RTO benötigen Betriebsanforderungen, Offsite-Speicherung und Schlüsselzuständigkeit. Physische PostgreSQL-Portabilität ist für die geprüften eingebauten Anwendungslocales nachgewiesen; abweichende libc-Anwendungslocales erfordern einen eigenen Plan.

Phase 23 erlaubt die Prüfung in Phase 24; eine Produktionsfreigabe erfolgt daraus nicht automatisch. Scan- und Komponentenbelege sind an Zeitpunkt, Quellen, Policy und genaue Artefakte gebunden. Neue Herstellerbefunde erfordern erneute Bewertung und gegebenenfalls Korrektur.
