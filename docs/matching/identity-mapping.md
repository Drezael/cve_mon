# Identitätszuordnung

Kandidaten sind Suchtreffer und keine positive Betroffenheit. Schlüssel unterscheiden
OSV-Ökosystem/Paket, Source-Paket, Produkt/Vendor, PURL und CPE. dpkg allein genügt nicht:
Ubuntu beziehungsweise Debian stammt aus der persistierten Distribution. npm und Cargo
haben eigene Ökosysteme; pip bezeichnet PyPI, dessen Versionsbereiche nicht als SemVer
ausgewertet werden. Architektur und jede Paketinstallations-ID bleiben erhalten.

Ubuntu-Source-Pakete benötigen inventory.packages.source_package. Der gleichnamige
Binärname dient ausschließlich als konservativer Kandidat. Vendor/Product und CPE werden
nur aus vorhandener expliziter Identität übernommen. Keine CPE-/PURL-Erzeugung aus Namen.
PURLs behalten Typ, Namespace und Qualifier. NVD-Konfigurationen bleiben Ausdrucksbäume.

Inventar 1.1 enthält keine umfassende verifizierte CPE-/Vendor-Produktzuordnung und keine
Container-SBOM. Ohne solche Daten bleiben entsprechende Aussagen unsicher. Laufender
Kernel ist ein eigener Kontext; ein installiertes Kernelpaket beweist keinen Kernelwechsel.
Container besitzen eigene IDs und Digests; mutable Tags erzeugen keine Paketversion.
