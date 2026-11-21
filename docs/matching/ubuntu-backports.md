# Ubuntu und Backports

Der vollständige installierte Source-Paketstand wird gegen die passende Fixversion geprüft;
ohne eigene Source-Version bleibt die Bewertung source_version_unproven. Eine Binärversion ersetzt diese nicht. Die bekannten Releasebindungen 20.04/focal, 22.04/jammy und 24.04/noble sind explizit hinterlegt.
Distribution, Release, belegte Source-Zuordnung, relevante Architektur und Sicherheitskanal
müssen passen. Andere Releases oder unbekannte Kanäle liefern keinen Negativnachweis.
released/fixed unterhalb der Fixversion bedeutet affected; needed/vulnerable benötigt den
passenden Kontext. ignored, pending, deferred und needs_evaluation entwarnen nicht.

Phase 15/16 importiert die Ubuntu Security API, keine verifizierten OVAL-Daten. Deshalb
werden API-basierte negative Aussagen ausdrücklich eingeschränkt. Auch ein rechnerisch
gefixter Backport ergibt in der Produktionspipeline potentially_affected mit
ubuntu_api_requires_verified_negative. Der reine Regeladapter kann verifizierte Evidenz
auswerten, doch der Worker aktiviert diesen Modus nicht anhand untrusted Quellflags.
Eine spätere explizite Quellenphase muss OVAL oder gleichwertige verifizierte Evidenz
bereitstellen. Phase 17 führt keinen zusätzlichen externen Import ein.

Eine generische Upstream-Aussage darf einen passenden Backportnachweis nicht stillschweigend
überschreiben. Widersprüche und die negative Quellenbeschränkung bleiben in Konflikten sichtbar.
