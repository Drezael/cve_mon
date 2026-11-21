# Sicherheitsverträge

[service-access-v1.json](service-access-v1.json) ist ein überprüfbarer Architekturvertrag,
keine produktive Container- oder Firewallkonfiguration. Er hält Komponenten, Netzzuordnung,
Datenbankrollen und die erlaubte administrative Gruppenschreibrolle fest.

Verbindlich ergänzend: [interne Vertrauensgrenzen](../../docs/architecture/internal-trust.md),
[Authentifizierung](../../docs/security/authentication.md),
[Autorisierung](../../docs/security/authorization.md) und
[Datenbankrechte](../../docs/database/access-matrix.md).

Version 1.1 erweitert gemäß Phase 2/ADR-0020 ausschließlich Nginx-Publishing auf 80/443.
Die übrigen Vertrauensgrenzen bleiben erhalten; konkrete Infrastruktur wird separat validiert.
