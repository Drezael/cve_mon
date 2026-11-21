# Beiträge zu CVE Monitor

Die [README](../README.md) beschreibt Architektur und Start. Der Quellcode steht
unter [PolyForm Noncommercial 1.0.0](../LICENSE); kommerzielle Nutzung benötigt
eine separate Vereinbarung. Beiträge übertragen keine Urheberrechte oder
zusätzlichen kommerziellen Lizenzrechte automatisch.

## Lokal arbeiten

```sh
./cve_mon setup
make check
make inventory-collect-syntax
```

Für Dashboard-Änderungen zusätzlich `make dashboard-check` ausführen. Echte
Infrastruktur- oder SSH-Tests gezielt mit den dokumentierten Make-Zielen starten;
sie benötigen Docker und verwenden eigene Testprojekte beziehungsweise Testcontainer.

Änderungen klein halten und Problem, Verhalten und ausgeführte Prüfungen im PR
beschreiben. Interne Architekturwerte werden im Repository gepflegt. Die `.env`
enthält ausschließlich externe Angaben. Für Ansible ausschließlich die lokalen,
lesenden Playbooks verwenden; kein anderes Repository bearbeiten.

Keine echten Inventare, Zugangsdaten, privaten Schlüssel, lokalen `.env`-Dateien,
Datenbank-Dumps oder Laufzeitordner einreichen. Beispiele mit synthetischen Daten
gehören nach `examples/` beziehungsweise `configuration/examples/`.
