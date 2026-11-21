# Dashboard-Sicherheit

CSP: default-src none; script/style/img/font/connect ausschließlich self; frame-ancestors/base-uri/object-src none; form-action self. Keine unsafe-inline-Ausnahme und keine gefährlichen HTML-Sinks. Hostgebundene Cookies, Same-Origin, bestehende Origin-/Gateway-/Forwarded-Prüfungen und HSTS-Strategie bleiben bestehen. Fachwerte werden nie in Template-HTML interpoliert. Zod verhindert stillschweigende Interpretation ungültiger API-Antworten. Kein Node-Prozess, Docker-Socket, Datenbanktreiber oder Secret im Produktivbuild.

Node-Archiv und SHA256 sind in toolchain.toml festgelegt. npm ci verwendet package-lock.json. Das gezielte minimatch-Override auf 11.0.1 schließt die vom Audit gemeldete Entwicklungsabhängigkeitslücke. npm audit und bestehender Repository-Secretscan gehören zur Abnahme. Keine normalbetrieblichen Testkonten oder Versandfreigaben.
