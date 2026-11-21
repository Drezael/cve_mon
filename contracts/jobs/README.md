# Jobvertrag v1

[job-envelope-v1.schema.json](job-envelope-v1.schema.json) beschreibt die technische
Hülle. Payload muss zusätzlich dem explizit registrierten Pydantic-Typ entsprechen.
Maximal 16 KiB JSON, keine Geheimnisse, ausführbaren Felder oder freien Ziel-URLs.
Idempotenzscope bindet Produzentenrolle, Jobtyp, Scope und Schlüssel. Kein öffentlicher
Job-HTTP-Endpunkt. [Semantik](../../docs/architecture/background-jobs.md).
