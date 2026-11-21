# Revisionsfeste fachliche Historie

Audit, Beobachtungen, Episodenöffnungen/-abschlüsse, Reviews, Zuweisungen, Notizen, Ausnahmen,
Prioritäten und Fristen sind append-only. state_history projiziert den Zustand aus derselben
Auditkette statt einer divergierenden zweiten Schreibimplementierung. Benutzeraktionen
referenzieren die tatsächliche Session und User-ID; technische Jobs erscheinen als
findings_writer mit NULL-Mensch. Der DB-Actor-Guard verhindert gefälschte menschliche Aktionen.

Jeder model_version=2-Commit benötigt einen Audit-Eintrag auf seiner aktuellen Zeilenversion.
Der deferred Constraint prüft den finalen Zustand des atomaren Fachcommits. Die gemeinsame
version-Guard verhindert Lost Updates; API-Kommandos erfordern If-Match. Audit und Outbox
werden zusammen gespeichert. Append-only PostgreSQL ist kein kryptografischer Schutz gegen
einen privilegierten DBA; diese stärkere Behauptung wird nicht gemacht.
