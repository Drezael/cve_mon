# Rollen und ACLs betreiben

```bash
CVE_DOCKER_SUDO=1 make authorization-check
CVE_DOCKER_SUDO=1 .venv/bin/python scripts/security/inspect-role-permissions.py
CVE_DOCKER_SUDO=1 .venv/bin/python scripts/security/inspect-server-acls.py --server-id <uuid>
CVE_DOCKER_SUDO=1 .venv/bin/python scripts/security/verify-last-admin.py
```

Prüfung vergleicht exakt die vier Systemrollen mit der endlichen Matrix. Keine automatisch
neu verteilten Adminrechte beim Deployment. Zusätzliche Rollen nur nichtadministrativ,
kein Wildcard-/Gruppen-/Sortierrecht, Revisionen bei Änderungen. Native Rollen-RLS und
nondelegable-Trigger bleiben wirksam; kein Superuser oder dynamisches SET ROLE in Runtime.

ACL-GET liefert Set-Version und begrenzte Metadaten; PUT ersetzt das ganze Set atomar.
Eigene neue ACL-Grants sind untersagt; zweiter Admin muss eigene Uploadfreigaben verantworten.
Rollen-/ACL-Änderungen invalidieren Sessions. Betreiberinspektion gibt weder Passwordhashes
noch Faktor-/Sessionverifikatoren aus. Die tatsächliche Server-/Gruppenverwaltung folgt Phase 10.
