# Vertrauenswürdige Zustellnachweise

scripts.notifications.manage reconcile-postfix liest ausschließlich den eigenen gelabelten
Postfix-Container und dessen Queue. Message-ID-Logs korrelieren Queue-IDs mit Intent-UUIDs.
status=sent beweist upstream_accepted, status=bounced einen Bounce. Die begrenzte SQL-
Beobachtungsfunktion verlangt einen vorhandenen eigenen SMTP-Versuch und passende Relay-/
Queue-Referenzen. Duplicate Evidence-IDs sind idempotent. Es gibt keine Queue-Löschrechte.

Queue-Messungen sind mit Zeitpunkt und Instanzreferenz append-only. Nach fünf Minuten ist
ein nicht erneuerter Wert unbekannt; null wird nicht als leere Queue ausgegeben. Der Operator
kann diesen passiven Befehl regelmäßig ausführen. Ohne neue vertrauenswürdige Beobachtung
bleibt submission_uncertain gesperrt. Das ist ein ehrlicher Zustellzustand, kein Datenverlust.

Zusätzlich kann ein Administrator nach frischer MFA über transport-evidence einen geprüften
Postfix-/DSN-Nachweis mit Begründung attestieren. Beliebige eingehende E-Mails oder ungesicherte
Bounce-Callbacks sind keine Datenquelle. delivery_confirmed entsteht nur durch explizit
geprüften DSN-Nachweis, niemals durch Postfix-/Smarthost-250 oder n8n-Erfolg allein.
