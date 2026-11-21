# REST-Verträge T00.04.01–06

[openapi.yaml](openapi.yaml) ist OpenAPI 3.1.0. Es spezifiziert die geplante API,
keine bereits implementierten Endpunkte. Inventar-JSON verweist direkt auf das versionierte
[Inventarschema](../inventory/inventory-v1.schema.json); keine zweite abweichende Kopie.

[Konventionen](../../docs/api/conventions.md) und
[Authentifizierungsgrenzen](../../docs/api/authentication-boundaries.md) sind verbindlich.
Jede Operation enthält security, x-permission, x-object-scope, x-owner und x-ingress.
Die x-Felder dokumentieren erforderliche Laufzeitprüfungen; OpenAPI erzwingt sie nicht selbst.

Öffentliche APIs beginnen mit /api/v1. Technisches Submit, Dashboard-Upload und administrative
/dashboard/admin-Operationen sind getrennt. /internal/v1 und /health sind ausschließlich
interne, dienstauthentifizierte Wege auf den im Vertrag angegebenen Service-Origins.
`make validate` prüft OpenAPI-Semantik, lokale Referenzen und die zentralen Sicherheitsinvarianten.
