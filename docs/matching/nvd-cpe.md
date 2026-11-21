# CNA, NVD und dreiwertige Logik

CNA benötigt explizite Vendor-/Produktidentität. Versionslisten, passende versionType-
Adapter, lessThan/lessThanOrEqual, changes und defaultStatus werden im Produktkontext
geprüft. Unbekannte Vergleichsverfahren erhalten keinen universellen Fallback.

CPE 2.3 verarbeitet elf Attribute einschließlich Update, Edition und Zielplattform.
ANY (*) und NA (-) bleiben verschieden; unbekannte Zielattribute erfüllen keine konkrete
Voraussetzung. Versionsgrenzen benötigen einen ausdrücklich belegten Vergleichsadapter.
Alle vier inklusiven/exklusiven Grenzen bleiben erhalten. Keine Paketname→CPE-Erfindung.

AND, OR, verschachtelte nodes/children und negate verwenden dreiwertige Logik. FALSE
dominiert AND, TRUE dominiert OR; NOT unknown bleibt unknown. vulnerable=false bezeichnet
Kontext, beweist selbst keine Verwundbarkeit. Ein bestätigtes Ergebnis benötigt zusätzlich
einen nachgewiesenen verwundbaren Blattknoten. Inventar 1.1 ist keine exhaustive CPE-Liste;
fehlende Plattformen bleiben unbekannt. Ausdruckslimit: Tiefe 32, maximal 4096 Knoten/Blätter.
[NIST CPE Name Matching 2.3](https://csrc.nist.gov/pubs/ir/7696/final).

Affected-Belege werden als Provenienz, Enrichment-JSON-Pointer und SHA-256 der unveränderlichen Aussage referenziert. Dadurch bleiben Originalbaum und Vergleichsgrenzen vollständig prüfbar, ohne denselben großen Quellausdruck je Installation zu duplizieren. Der tatsächlich verglichene Operand steht separat neben der unveränderten Installationsversion.
