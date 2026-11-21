# Zustellstatus

planned, suppressed, deferred und ready unterscheiden Entscheidung, Ausschluss, Aufschub
und Bereitschaft. leased reserviert vor Submit. submitting ist vor Netzwerkzugriff dauerhaft
committed. relay_accepted bedeutet ausschließlich bestätigte Postfix-250-Antwort nach DATA.
Die Queue-ID wird erfasst, sofern die Antwort sie enthält; sie ist zusammen mit der
persistenten Relay-Instanzreferenz und stabilen Message-ID zu interpretieren.

retryable_failure ist sicher vor erneuter Annahme wiederholbar. permanent_failure ist
begrenzt beendet. submission_uncertain bedeutet mögliche Annahme und blockiert automatische
Resubmits. upstream_accepted belegt nur den folgenden SMTP-Server. bounced benötigt einen
vertrauenswürdigen Transportnachweis. delivery_confirmed verlangt einen gesondert geprüften
DSN-Nachweis; weder n8n-Erfolg noch Relay-/Smarthostannahme setzen diesen Status automatisch.
Historie und Versuchsresultate sind append-only. cancelled ist ein kontrolliertes Ende.
