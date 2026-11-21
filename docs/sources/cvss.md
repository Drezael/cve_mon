# CVSS-Verarbeitung

Verwendet wird die exakt gepinnte Bibliothek cvss 3.6 von
[Red Hat Product Security](https://github.com/RedHatProductSecurity/cvss).
Sie unterstützt CVSS 2.0/3.0/3.1/4.0 und wird upstream anhand offizieller Testvektoren geprüft.
Keine eigene Scoring Engine. Paket und Hashes stehen in den Runtime-/Dev-Locks.

Alle Bewertungen behalten Version, Provider, Source-Assessment, Vektor, gelieferten Score,
Validierungsstatus und Provenienz. Unterstützte Status: valid, incomplete, invalid_vector,
score_mismatch und unsupported_version. Doppelte/ungültige Vektormetriken werden abgelehnt.
Ein fehlender Score kann mit der geprüften Bibliothek aus dem vollständigen Vektor ermittelt
werden; fehlende Bewertung wird niemals 0. Gelieferte widersprüchliche Scores bleiben
nachvollziehbar und werden nicht bevorzugt.

Versionspräferenz: 4.0, 3.1, 3.0, 2.0. Innerhalb einer Version gilt die dokumentierte
Quellen-/Providerreihenfolge. Alle anderen gültigen oder fehlerhaften Bewertungen bleiben
sichtbar. v4-Nomenklatur unterscheidet CVSS-B/BT/BE/BTE aus den tatsächlich gelieferten
Metriken; keine Umweltwerte werden aus Serverdaten erfunden. Severity bleibt versionsbezogen;
v2 besitzt keine zusätzliche erfundene Critical-Kategorie. Kein organisationsbezogener Risikoindex.

Bei v4 bleiben Base Score und der Score des vollständig gelieferten BT-/BE-/BTE-Vektors
getrennt (base_score/context_score). Die Base-Prüfung verwendet die Base-Metriken,
die Kontextprüfung ausschließlich gelieferte Threat-/Environmental-Metriken. Beide
Berechnungen übernimmt die geprüfte Bibliothek; keine erfundenen Server-Umweltwerte.
