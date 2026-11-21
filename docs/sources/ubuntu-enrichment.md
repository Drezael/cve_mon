# Ubuntu-Evidenz

Eingang bleibt die in Phase 15 freigegebene Ubuntu-Security-Methode. Rohrevisionen werden
nicht geändert oder erneut im Internet abgefragt. packages, release_packages und releases
bleiben als strukturierte Assertions mit Release, Quell-/Binärpaket, Kanal, Status und
Originalversion erhalten. Zum Beispiel bleibt 1:2.4.58-1ubuntu8.4 vollständig erhalten.

Keine Verkürzung auf Upstream-Versionen, keine naive String-/Semver-Gleichsetzung, kein
Versionsvergleich und keine Aussage über installierte Serverpakete. Fehlende Angaben
bleiben unbekannt. Eine Ubuntu-Meldung mit mehreren CVE-Referenzen wird nicht zu einer
CVE-Gleichheitsbeziehung. Für spätere produktive Matchingregeln müssen Qualitätsgrenzen der
Ubuntu-API und gegebenenfalls offizielle OVAL-Evidenz gesondert berücksichtigt werden.
