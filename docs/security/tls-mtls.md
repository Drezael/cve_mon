# TLS und mTLS Phase 23

Bestehender HTTPS-Eingang, verify-full PostgreSQL, n8n-/Notification-TLS und Postfix-STARTTLS behalten vollständige Ketten-/Namensprüfung. Interne lokale Healthsignale sind kein Beleg externer Fachverfügbarkeit. Es wird kein verify=false oder Zertifikatsfallback eingeführt.

Maschinenzugang prüft Nginx-verifizierte Zertifikate über private Gatewayidentität, CA/CRL, EKU, Lebensdauer, Fingerprint und gebundenen Token. Browser kann Zertifikats- und Identitätsheader nicht als Rechtequelle einschleusen. Unbekanntes/abgelaufenes/widerrufenes Zertifikat, falscher Server/Scope und widerrufener Token sind durch bestehende negative Transport-/Uploadtests abgedeckt. Rotation wird mit ausschließlich synthetischem Material geprüft; vorhandene Produktivschlüssel werden nicht ersetzt.
