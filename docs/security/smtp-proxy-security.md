# SMTP-Vertrag für Phase 5

Envoy-Listener `cve-egress-proxy:1587` verbindet ausschließlich den in der Policy festgelegten
Smarthost und Port (typisch 587). Keine MX-Auflösung je Empfängerdomain, keine CONNECT-Zielwahl,
keine alternative Relayauswahl durch SMTP-Befehle. Auslieferungsdefault ist deaktiviert mit dem
klaren Platzhalter smtp.example.invalid; der Betreiber muss vor produktivem Postfix-Anschluss
einen tatsächlichen Host ausdrücklich konfigurieren. Die Funktion ist mit einem festen eigenen
Testsmarthost bereits vollständig geprüft, einschließlich echter STARTTLS-Aushandlung.

SMTP ist server-first. `upstream_connect_mode: IMMEDIATE` wird ausdrücklich gesetzt; Banner
wird ohne vorangehende Clientdaten geliefert. Eine Daten-RBAC-Prüfung allein wäre hierbei zu spät.
Der Namespace-INPUT-Filter und die Source-Filterkettenauswahl verweigern unberechtigte Clients
vor Erzeugen des TCP-Proxyfilters. Die Test-Acceptzähler am SMTP-Upstream bleiben dabei unverändert.

Envoy transportiert Bytes unverändert. STARTTLS und SMTP AUTH enden zwischen Postfix und dem
externen Smarthost. Envoy besitzt weder SMTP-Zugangsdaten noch eine Mailqueue und ersetzt
Postfix nicht. Ausfall verzögert später den Versand über dessen persistente Queue.
Keine direkte externe SMTP-Ausweichverbindung und kein Abschalten der TLS-Prüfung.

Für die gepinnte Postfix-Version in Phase 5 nachweisen:

1. nexthop intern Envoy:1587; TLS-Policy-Lookup für exakt diesen Nexthop.
2. Externe CA-Kette UND externer Smarthost-FQDN als Zertifikatsidentität prüfen; niemals nur den
   internen Namen cve-egress-proxy akzeptieren.
3. STARTTLS verpflichtend, falsches/abgelaufenes/nicht vertrauenswürdiges Zertifikat und fehlendes
   STARTTLS führen zur Queue, nicht zum unverschlüsselten Versand.
4. AUTH-Credentials ausschließlich in restriktiven Postfix-Secretdateien, nicht in Envoy oder Logs;
   keine ungeschützte Weitergabe vor erfolgreichem TLS.
5. Persistente Queue, begrenzte Wiederholungen, Größen-/Alterschwellen und kontrollierter Wiederanlauf.

Die korrekte Postfix-TLS-Policy-Syntax wird erst gegen das tatsächliche Phase-5-Image festgelegt.
Die Phase-4-Testclients beweisen Transparenz und aktive Zertifikatsprüfung; sie sind keine
Behauptung bereits implementierter produktiver Postfix-Konfiguration.
