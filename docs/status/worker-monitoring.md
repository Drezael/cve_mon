# Worker, Heartbeats und Leases

Die vorhandenen privaten /health/live- und /health/ready-Endpunkte prüfen den echten Workerloop, dessen letzten Tick, laufende Task und Datenbankbereitschaft. Zusätzliche Indizien kommen aus realen Job-Heartbeat- und Leasefeldern. Idle ohne fällige Arbeit ist zulässig. Ausgefallene Lease oder ein zu alter fälliger Rückstand ist keine normale Ruhephase. Der Statusdienst erzeugt keine fremden Heartbeats und führt keine fachliche Verarbeitung aus.
