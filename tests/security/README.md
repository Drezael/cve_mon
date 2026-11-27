# Sicherheitsprüfungen

`make security` prüft Repositorydateien auf Secrets. Laufzeitgrenzen werden mit
den Markern `security` und dem jeweiligen Integrationsmarker geprüft, etwa:

```bash
CVE_ENV_FILE=configuration/examples/development.env .venv/bin/python -m pytest \
  -m 'authentication and security' tests/authentication/integration
```

Der vollständige Python-Nachweis läuft über `make qa-full`. Er umfasst negative
RBAC-, Eigentümer-, CSRF-, TLS-, Upload-, Netzwerk- und Datenbankrechteprüfungen.
`make security-dependencies` und `make security-images` prüfen Bibliotheken und
Container separat. Voraussetzungen und private Testartefakte sind in
[Tests und QA](../../docs/testing/README.md) dokumentiert.
