# RPM EVR

rpm-1 trennt Epoch, Version und Release. Fehlende Epoch entspricht 0. Numerische Segmente
sortieren numerisch und nach alphabetischen Segmenten. Separatoren trennen ohne eigene
Priorität. Tilde sortiert vor dem Basisrelease; Caret nach dem Basisrelease und vor einer
weiteren normalen Versionskomponente. Release bleibt Teil des Vergleichs.

Die Regressionen vergleichen gegen rpmvercmp der nativen librpm, unabhängig vom Python-
Adapter. Entwicklungsabhängigkeit: sudo apt-get install librpm9 (auf Ubuntu ggf. t64-Paket).
Der Matchercontainer braucht librpm nicht. Versionsvergleich allein beweist keine passende
Vendor-Sicherheitskorrektur. Ohne Vendor-/Produktkontext bleibt die Entscheidung offen.
[Offizielle RPM-Semantik](https://rpm.org/docs/6.0.x/man/rpm-version.7).
