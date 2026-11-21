# Verbindlicher Envoy-SMTP-Pfad

Der vorhandene Phase-5-Pfad bleibt verbindlich: Postfix verwendet den kontrollierten
TCP-Transport über den Envoy-Port 1587 zum ausdrücklich erlaubten Smarthost und validiert
dessen TLS-Identität sowie die bestehende SMTP-AUTH-Konfiguration. Ein HTTP_PROXY-Parameter
wird nicht als vermeintlicher Postfix-CONNECT-Support eingesetzt.

Notification verbindet ausschließlich zum internen Relay. n8n hat keine SMTP-Freigabe.
Envoy-Ausfall erzeugt nach Relayannahme ausschließlich Postfix-Queue-Retries, keinen neuen
Anwendungssubmit. Kein direkter Smarthost-Zugriff oder Internet-Fallback. Integrationstests
verwenden einen synthetischen Smarthost samt DNS-/Routingfixture im eigenen Compose-Projekt.
Normale Envoy- und Mail-Policies bleiben unverändert.
