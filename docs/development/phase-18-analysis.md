# Analyse Phase 18

Ausgangsbasis: Phase 17, Head 00023, zehn eigene Dienste. Legacy findings.findings war noch
komponentenbezogen und an cve.records/matching.results gebunden. Die neue fachliche Grundlage
ist matching.result_revisions mit current_version und is_current. Deshalb model_version=2
im vorhandenen Finding-Modell statt Datenlöschung oder blindem Umbiegen alter Fremdschlüssel.

API 0.11.1 verfügte bereits über verifizierte Browser-Sessions, MFA, CSRF, RBAC und explizite
findings_read/findings_manage-ACLs. Diese werden erweitert, keine zweite Authentifizierung.
Die neue API 0.18.0 teilt die Finding-Verträge mit dem Worker. Keine impliziten neuen
Analystrechte. Vorheraufnahme: .runtime/test-reports/phase-18-before.json, private und dauerhaft.

Phase 17 beansprucht keine vollständige globale Negativabdeckung für Inventory 1.1. Daher
keine selbst erfundene automatische Resolution, OVAL-, CPE-, Container- oder Git-Evidenz.
Der Fixpfad ist implementiert und benötigt eine explizit freigegebene passende Policy.
