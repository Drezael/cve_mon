# ADR-0023 – Nativer Postfix mit begrenztem Master und eigener Queue

Status: angenommen, 06.11.2026.

Postfix 3.10.13 aus gesperrten Debian-Artefakten übernimmt SMTP, TLS, AUTH, Retry,
Queue und Bounce. Keine Python-Transportqueue. Der native Master läuft als root mit
sechs expliziten Prozess-/Dateicapabilities, Worker unter postfix. Die Phase-4-Regel
für ausschließlich nichtprivilegierte Proxyclients erhält dafür eine eng geprüfte
Mailcontainer-Ausnahme (Projekt, Phase, Image, Benutzer, exakte Capabilities).
Netzwerkprivilegien bleiben beim bereits eingeführten Hostoperator in ausschließlich
eigenen Namespaces. Neue Boot-/Namespacebindung verhindert ungefilterte Neustarts.

Listener an interner IP, ausgehende Verbindung durch Kernelrouting an Egressinterface.
Persistente native Queue als separates Named Volume. Private Laufzeitmaps auf tmpfs;
Secrets niemals im Image oder Envoy. Ausgehend TLS secure mit echtem Provider-Match
und SNI, eingehend CA-validierter und explizit gepinnter Client mit Senderrestriktion.

Folge: Start/Recreate/Rotation über Mailoperator statt rohem Compose-Up; zusätzliche
Startautomation nach Hostneustart erforderlich. Backup muss Postfix anhalten; Restore
nur auf leere Queue. SMTP-Duplikate nach unklarem DATA-Ausgang bleiben möglich.

Fortführung in Phase 23: aktuelle Postfix-3.11.7-/Alpine-Laufzeit aus festen signierten Paketen. Native Queue-/SMTP-Verantwortung, die sechs Capabilities und die enge Clientausnahme bleiben bestehen; nur der geprüfte Imagebezug wird aktualisiert. UID/GID und Queuebesitz bleiben kompatibel. Details: [Behebung](../../security/phase-23-remediation.md).
