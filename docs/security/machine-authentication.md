# Maschinenidentitäten Phase 23

Technische Clients registrieren weder Server noch Gruppen und erzeugen keine ACLs. Vor jeder Annahme müssen mTLS-Zertifikat, aktiver Principal, Tokenverifikator, Zertifikatsbindung, ausschließlich erlaubter Uploadscope, registrierte Server-UUID und Ablauf stimmen. Widerruf und Quotas werden aktuell aus PostgreSQL geprüft.

Replay desselben Inhalts wird über persistente Identität/Idempotenz erkannt; HTTP 202 belegt die Annahme ins Staging und keine Verarbeitungsgarantie. Dashboard-Upload verwendet Session/CSRF und denselben Parser/Processor. tests/inventory_upload/integration prüft beide Wege, Rotation, falsche Identität, Replay, fremde UUID und manipulierte Nutzdaten. Keine echte Ansible-Zielausführung.
