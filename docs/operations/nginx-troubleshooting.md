# Nginx-Fehlerbehebung

- Docker permission denied: normalen Daemonzugang bereitstellen oder ausdrücklich
  CVE_DOCKER_SUDO=1 mit eingerichtetem passwortlosem sudo für Docker verwenden.
- Zertifikat fehlt/läuft ab: TLS-Dateien und CA prüfen, Entwicklungs-PKI bei Bedarf bewusst
  erzeugen; keine Zertifikatsverifikation abschalten.
- Permission denied beim Schlüssel: 0600, passender Eigentümer und NGINX_UID. Kein chmod 777.
- Port belegt: ss -ltn lesen, eigene freie Loopbackports wählen; fremde Container nicht stoppen.
- Ungültiger Host/SNI: --resolve und URL-Domain müssen übereinstimmen, CA/SANs prüfen.
- 403 am technischen Host: gültiges Clientzertifikat/Key/CA und Zeit prüfen; Headerfälschung hilft nicht.
- 503 bei gültigem HTTPS: erwarteter Zustand der noch fehlenden Backends, kein erfolgreicher Upload.
- 404: Route in diesem Host nicht freigegeben. Adminroute auf technischem Host wird nie aktiviert.
- 429/413: Limits prüfen, keine globale Deaktivierung als Fehlerbehebung.
- Reload fehlgeschlagen: Preflight/nginx -t-Diagnose lesen. Snapshot wird bei Fehlern zurückgesetzt;
  alte Worker bleiben aktiv. Neue Quelldateien sichern und gültiges Paar bereitstellen.
- Netzwerk-Kontrolltest extern fehlgeschlagen: Internet aus externem Testnetz unabhängig prüfen;
  nicht als bestandene interne Isolation ausgeben.

Konfiguration prüfen: make compose-check, danach mit gültigen Quellen make nginx-check.
Betrieb/Logs nur auf das eindeutig gewählte Projekt beziehen. Keine Docker-Prune-/Host-Firewall-
Änderungen und keine TLS-Bypass-Anleitung. Gehostete CI ist erst nach autorisiertem Push nachweisbar.
