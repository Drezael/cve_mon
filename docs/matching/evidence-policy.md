# Evidenzpolitik matching-1

Jede Komponentenentscheidung enthält Komponenten-ID, Installationskontext, unveränderte
installierte Version, Regel-ID, Vergleichsadapter, Grundcode und die tatsächlich geprüfte
Affected-Aussage einschließlich Source-Revisions-ID und JSON-Pointer. Der vollständige
NVD-Ausdruck bleibt nachvollziehbar. Matching-Ergebnisse referenzieren zusätzlich genau
Snapshot, Server, CVE, Enrichment-Revision und Regelversion.

Identitätsbeweis geht Versionsvergleich voraus. Eine zur Distribution und zum Release
passende Fixinformation schränkt generische Upstream-Regeln ein. Gleichwertige Widersprüche
werden erhalten und ergeben Unsicherheit, keine Quellenabstimmung. CVSS, dynamischer KEV-
Status und EPSS bestimmen keine technische Betroffenheit und gehen nicht in den
Matching-Fingerprint ein. Keine unkalibrierte numerische Konfidenz.

Affected-Belege werden als Provenienz, Enrichment-JSON-Pointer und SHA-256 der unveränderlichen Aussage referenziert. Dadurch bleiben Originalbaum und Vergleichsgrenzen vollständig prüfbar, ohne denselben großen Quellausdruck je Installation zu duplizieren. Der tatsächlich verglichene Operand steht separat neben der unveränderten Installationsversion.
