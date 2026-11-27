# Ende-zu-Ende-Prüfungen

Die Anwendung besitzt reale PostgreSQL-, TLS-, Browser-, n8n-, Mail- und
Workerprüfungen. Die ausführbaren Szenarien liegen bei ihren Fachbereichen unter
`tests/inventory_upload`, `tests/dashboard`, `tests/dashboard_administration`,
`tests/orchestration`, `tests/notifications`, `tests/findings` und
`tests/managed_ansible`. Sie verwenden isolierte Testprojekte und synthetische
Daten. Der vollständige Einstieg ist `make qa-full`; Voraussetzungen und die
Abgrenzung zu `make check` stehen in [Tests und QA](../../docs/testing/README.md).
