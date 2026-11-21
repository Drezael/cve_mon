# n8n-Recovery

Ein n8n-Ausfall löscht weder Intents noch SMTP-Versuche. Offene Workflow-Runs verfallen nach
fünf Minuten, sichere ready-Intents werden durch persistente Maintenance-Jobs neu angestoßen.
Ein abgelaufener SMTP-Lease wird dagegen unklar und niemals blind wiederholt. Zeitpläne
sind ausschließlich Anstöße; persistente Fälligkeiten sind die maßgebliche Wahrheit.

Nach Containerneustart make notifications-up bzw. scripts.notifications.manage guard:
Proof und Regeln müssen zum tatsächlichen neuen Namespace und den aktuellen eigenen
Peer-Adressen passen. DNS kann beide gemeinsamen Netzwerkadressen liefern; freigegeben
werden genau diese eigenen Peers, keine Subnetze. Credentials/Encryption Key nicht neu
initialisieren. Backup umfasst beide Datenbanken und die separat geschützten Runtime-Secrets.
