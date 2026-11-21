# Software und Bereich eines Findings

Die Findings-Übersicht und die Detailansicht zeigen Paketname, installierte Version
und den Bereich **Host** oder **Container: Name**. Die technische Einschätzung wird
je Komponente ausgewiesen. Mehrere Komponenten oder Container derselben Server/CVE-
Kombination bleiben getrennt sichtbar, ohne zusätzliche Findings zu erzeugen.

Die Anzeige verwendet den unveränderlichen Inventarstand des zugrunde liegenden
Matching-Ergebnisses. Bestehende Hostbefunde werden über die gespeicherte Paket-ID
aufgelöst; dafür ist kein erneuter Scan erforderlich. Container werden über ihren
Snapshot und ihre Container-ID zugeordnet. Die Softwareidentität stammt aus den
persistierten SBOM-Belegen, nicht aus dem Image-Tag.

Nicht zuordenbare Komponenten werden ausdrücklich als unbekannt angezeigt. Es
werden keine Produktnamen aus der CVE-Beschreibung geraten. Eine möglicherweise
betroffene oder nicht betroffene Komponente bleibt entsprechend gekennzeichnet.

Die API ergänzt `affected_software` an Listen-, Detail- und Änderungsantworten.
Die Komponenten werden erst nach der ACL-Prüfung für die sichtbaren Findings in
einer zusätzlichen Sammelabfrage geladen. Fremde Finding-IDs liefern weiterhin 404.
Das Lesen erzeugt keine Jobs und verändert weder Findings noch Inventare.
