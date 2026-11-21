# Debian und Ubuntu

Der Adapter dpkg-1 vergleicht numerische Epoch, vollständige Upstream-Version und letzte
Distributionsrevision nach Debian-Regeln. Fehlende Revision entspricht 0. Tilde sortiert
vor dem leeren Segment; Buchstaben und sonstige erlaubte Zeichen haben unterschiedliche
Sortierung. Numerische Segmente ignorieren führende Nullen. Keine Versionsverkürzung.
Die Operanden sind ASCII und höchstens 512 Zeichen lang. Ungültige Werte bleiben unsicher.

Das Testoracle ist das lokal installierte dpkg --compare-versions, ausschließlich mit
Argumentlisten in isolierten Tests. Die Laufzeit führt keine Subprozesse aus.
[Normative Debian Policy](https://www.debian.org/doc/debian-policy/ch-controlfields.html#version).
