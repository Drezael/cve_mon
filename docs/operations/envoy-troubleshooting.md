# Envoy-Fehlerbehebung

- Container wartet ohne Listener: fehlender/frischer Namespacefilter. `envoy-up` mit den
  passenden Client-/Policydateien ausführen. Kein Löschen der Gates oder Starten eines offenen Proxys.
- Fehlende nsenter-/nft-Rechte: autorisierten passwortlosen sudo-Zugang nutzen. Envoy erhält
  dafür weder NET_ADMIN noch einen Docker-Socket. Hostregeln nicht ersatzweise pauschal öffnen.
- Policyprüfung rot: JSON-Schemafehler, doppelte Regeln, Client-/Port-/Methoden-/Hostnamekombination
  berichtigen; keine Wildcards oder Privatnetz-Ausnahmen als Fehlerbehebung hinzufügen.
- HTTP 403/CONNECT verweigert: konkrete Clientbindung und exakte Zielregel prüfen. Redirecthosts
  benötigen eigene genehmigte Regeln. Fehlende Regel ist kein Grund für Direktfallback.
- TCP-Timeout vor SMTP-Banner: fehlende mail-relay-Bindung, deaktiviertes SMTP, unerreichbarer
  fixer Upstream oder DNS-/Adresssperre prüfen. Nicht autorisierte Clients dürfen gerade keinen
  Upstream-Accept auslösen. Spätere Mails bleiben in der Postfix-Queue.
- HTTPS/STARTTLS-Zertifikatsfehler: externen Namen/CA/Gültigkeit berichtigen. TLS-Verifikation
  nicht abschalten und interne Envoynamen nicht als externe Zertifikatsidentität verwenden.
- DNSfehler: Resolveradresse, enge DNS-Ausnahme, Querytimeout/Refresh und Quelle prüfen. Private
  DNS-Antworten werden absichtlich verworfen; vorher gültige öffentliche Ziele bleiben stets gefiltert.
- Health grün, Quelle offline: /healthz beschreibt Envoys Bereitschaft, nicht jede externe Quelle.
  /metrics zeigt getrennte DNS-/Upstream-/Timeout-/Circuitbreakerwerte.
- Nach Client-Recreate: Proxy stoppen, aktuelle Endpoints vollständig neu binden, `envoy-up`.
  Keine alte IP/MAC-Freigabe kopieren. Bereits installierte Clientfilter bleiben bei Proxy-Ausfall zu.
- Limit erreicht: aktive Tunnel/Verbindungen und FDs/Heap beobachten, Ursache beseitigen; erst
  nach Tests bewusst dimensionieren. Keine unbegrenzten Verbindungen als dauerhafte Reparatur.

Privilegierte Wartung darf die generierten guard.nft/guard.installed.nft und die ausschließlich
containerlokalen Regeln lesen. Keine Credentials, vollständigen Requests oder SMTP-Nutzdaten
in Tickets kopieren. Testartefakte liegen unter .runtime/envoy mit eindeutigem Testprojektnamen;
nur selbst erzeugte gelabelte Ressourcen entfernen, keine globale Dockerbereinigung.
