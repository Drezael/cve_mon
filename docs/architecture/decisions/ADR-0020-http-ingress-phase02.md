# ADR-0020: HTTP-Weiterleitung und konkrete Ingress-Grenze in Phase 2

Status: accepted  
Entscheidungsdatum: 05.11.2026  
Anforderungen: Phase-2-Konzept 2.4, T02.04.04, INF-01/03/12/13/20.

## Kontext und Problem

Phase 0 beschrieb zunächst ausschließlich veröffentlichtes HTTPS/443. Das nachgereichte
Phase-2-Konzept verlangt zusätzlich TCP/80 für kontrollierte HTTPS-Weiterleitung.
Die konkrete Vorgabe muss sichtbar mit dem früheren Portvertrag abgeglichen werden.

## Betrachtete Alternativen

Nur HTTPS/443 würde die explizite Phase-2-Anforderung nicht erfüllen. Freies HTTP oder
Redirects auf ungeprüfte Hostheader sind unzulässig.

## Entscheidung

Nginx darf als einziger Ingress 80 und 443 veröffentlichen. HTTP verarbeitet nur GET/HEAD
auf bekannte Hosts und leitet auf eine fest konfigurierte HTTPS-Authority weiter.
Unsichere Methoden erhalten 426, unbekannte Hosts 421. Keine fachliche Uploadannahme über HTTP.
Entwicklung bindet ausschließlich Loopback und verwendet standardmäßig 8080/8443.
Container intern: 8080/8443; Health 8081 ohne Portpublishing.

## Begründung

Die explizite Phase-2-Vorgabe wird umgesetzt, HTTPS bleibt für geschützte Funktionen zwingend.

## Auswirkungen

Ergänzt die Portaspekte von ADR-0006/ADR-0005, ohne die Grundentscheidung für Nginx/Compose
zu ersetzen. Aktualisiert service-access-v1.json auf Version 1.1 sowie Netz-/Ingressbeschreibung.
Das Proxy-Backend bleibt deaktiviert; mTLS-Identität wird noch nicht an Dienste weitergegeben.
Host-Firewall-/Egress-Regeln bleiben vor Produktivfreigabe nachzuweisen; keine automatische Hoständerung.

## Zugehörige Nachweise

Aufgelöste Compose-Modelle, Redirect-/Host-/SNI-Negativtests, effektive Netzwerkmitgliedschaft,
Portprüfung und TLS-/mTLS-Tests in tests/infrastructure.
