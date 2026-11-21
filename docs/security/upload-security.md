# Uploadprüfung Phase 23

Der vorhandene 10-MiB-Vertrag und beide Authwege bleiben erhalten. Der Inventarparser lehnt doppelte Schlüssel, ungültige Unicode-/Schema-/Zahlwerte, zu tiefe/umfangreiche Strukturen und administrative Felder vor Staging ab. Prozessgrenzen 256 MiB/12 CPU-Sekunden und 15 Sekunden Wallzeit sowie maximal ein Parser bleiben erhalten. Aktuelle Server-/Token-/Zertifikatsbindung und persistente Quotas werden zusätzlich geprüft.

Die Lastprüfung verarbeitet 100/1000/10000 Pakete über tatsächliche Annahme und den vorhandenen gefencten Processor; Paketanzahl und Findingevidenz werden in PostgreSQL nachgeprüft. Kein Paket wird für Geschwindigkeit übersprungen. 202 ist kein Healthy-/Processing-success-Signal. Umfangreiche parallele Upload-/Wiederholungs-/Multipartfälle laufen in der vorhandenen Regression.
