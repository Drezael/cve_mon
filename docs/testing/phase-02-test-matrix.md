# Phase-2-Testmatrix

Alle 40 unten benannten Fälle sind als echte Docker-/TLS-/Netzwerktests erfolgreich ausgeführt.
Voraussetzung: eigener erreichbarer Docker-Daemon, OpenSSL, Compose, lokale kurzlebige Test-PKI.
Verfahren: CVE_DOCKER_SUDO=1 make infra-test (sudo nur nach ausdrücklicher Freigabe).
Erwartung: die in der jeweiligen Testfunktion formulierten positiven und negativen Assertions;
tatsächlich: alle Assertions bestanden, keine Fehler, keine Skips.

Zusätzlich 142 Tests im Standardlauf make check; die 40 Runtimefälle sind dort absichtlich
deselected und separat vollständig ausgeführt. Konfigurations-/Template-/Injection-Mutationen
prüfen absichtlich unsichere Modelle, die verworfen werden müssen.

| Test-ID | Testverfahren / Knoten | Erwartet | Tatsächlich / Status | Fehler |
|---|---|---|---|---|
| RT02-01 | tests/infrastructure/test_ingress_security.py::test_hosts_without_backends_and_without_client_certificate[dashboard.example.test] | Assertions erfolgreich | bestanden | keine |
| RT02-02 | tests/infrastructure/test_ingress_security.py::test_hosts_without_backends_and_without_client_certificate[api.example.test] | Assertions erfolgreich | bestanden | keine |
| RT02-03 | tests/infrastructure/test_ingress_security.py::test_hosts_without_backends_and_without_client_certificate[n8n.example.test] | Assertions erfolgreich | bestanden | keine |
| RT02-04 | tests/infrastructure/test_ingress_security.py::test_mtls_rejects_invalid_clients[None] | Assertions erfolgreich | bestanden | keine |
| RT02-05 | tests/infrastructure/test_ingress_security.py::test_mtls_rejects_invalid_clients[untrusted-client] | Assertions erfolgreich | bestanden | keine |
| RT02-06 | tests/infrastructure/test_ingress_security.py::test_mtls_rejects_invalid_clients[expired-client] | Assertions erfolgreich | bestanden | keine |
| RT02-07 | tests/infrastructure/test_ingress_security.py::test_valid_mtls_reaches_only_unavailable_backend | Assertions erfolgreich | bestanden | keine |
| RT02-08 | tests/infrastructure/test_ingress_security.py::test_forged_headers_cannot_replace_mtls | Assertions erfolgreich | bestanden | keine |
| RT02-09 | tests/infrastructure/test_ingress_security.py::test_technical_host_has_no_admin_unknown_or_health_route[/api/v1/dashboard/admin/servers] | Assertions erfolgreich | bestanden | keine |
| RT02-10 | tests/infrastructure/test_ingress_security.py::test_technical_host_has_no_admin_unknown_or_health_route[/unknown] | Assertions erfolgreich | bestanden | keine |
| RT02-11 | tests/infrastructure/test_ingress_security.py::test_technical_host_has_no_admin_unknown_or_health_route[/healthz] | Assertions erfolgreich | bestanden | keine |
| RT02-12 | tests/infrastructure/test_ingress_security.py::test_upload_routes_remain_separate | Assertions erfolgreich | bestanden | keine |
| RT02-13 | tests/infrastructure/test_ingress_security.py::test_unknown_sni_and_host_mismatches_are_rejected | Assertions erfolgreich | bestanden | keine |
| RT02-14 | tests/infrastructure/test_ingress_security.py::test_no_sni_is_rejected | Assertions erfolgreich | bestanden | keine |
| RT02-15 | tests/infrastructure/test_ingress_security.py::test_redirects_are_fixed_and_plaintext_uploads_not_accepted | Assertions erfolgreich | bestanden | keine |
| RT02-16 | tests/infrastructure/test_ingress_security.py::test_obsolete_tls_rejected[769] | Assertions erfolgreich | bestanden | keine |
| RT02-17 | tests/infrastructure/test_ingress_security.py::test_obsolete_tls_rejected[770] | Assertions erfolgreich | bestanden | keine |
| RT02-18 | tests/infrastructure/test_ingress_security.py::test_current_tls_supported[771] | Assertions erfolgreich | bestanden | keine |
| RT02-19 | tests/infrastructure/test_ingress_security.py::test_current_tls_supported[772] | Assertions erfolgreich | bestanden | keine |
| RT02-20 | tests/infrastructure/test_ingress_security.py::test_security_headers_and_no_development_hsts | Assertions erfolgreich | bestanden | keine |
| RT02-21 | tests/infrastructure/test_ingress_security.py::test_body_limit | Assertions erfolgreich | bestanden | keine |
| RT02-22 | tests/infrastructure/test_ingress_security.py::test_rate_limit_is_effective_before_missing_backend | Assertions erfolgreich | bestanden | keine |
| RT02-23 | tests/infrastructure/test_ingress_security.py::test_health_is_not_public | Assertions erfolgreich | bestanden | keine |
| RT02-24 | tests/infrastructure/test_ingress_security.py::test_logs_do_not_include_authentication_or_query_secrets | Assertions erfolgreich | bestanden | keine |
| RT02-25 | tests/infrastructure/test_ingress_security.py::test_effective_container_hardening | Assertions erfolgreich | bestanden | keine |
| RT02-26 | tests/infrastructure/test_ingress_security.py::test_production_hsts_policy_with_isolated_test_certificate | Assertions erfolgreich | bestanden | keine |
| RT02-27 | tests/infrastructure/test_ingress_security.py::test_missing_host_header_rejected | Assertions erfolgreich | bestanden | keine |
| RT02-28 | tests/infrastructure/test_network_isolation.py::test_live_network_isolation | Assertions erfolgreich | bestanden | keine |
| RT02-29 | tests/infrastructure/test_nginx_configuration.py::test_image_version_and_modules | Assertions erfolgreich | bestanden | keine |
| RT02-30 | tests/infrastructure/test_nginx_configuration.py::test_nginx_configuration_is_valid | Assertions erfolgreich | bestanden | keine |
| RT02-31 | tests/infrastructure/test_nginx_configuration.py::test_pki_is_private_and_not_overwritten | Assertions erfolgreich | bestanden | keine |
| RT02-32 | tests/infrastructure/test_nginx_configuration.py::test_invalid_replacement_certificates_fail[expired-server] | Assertions erfolgreich | bestanden | keine |
| RT02-33 | tests/infrastructure/test_nginx_configuration.py::test_invalid_replacement_certificates_fail[wrong-host] | Assertions erfolgreich | bestanden | keine |
| RT02-34 | tests/infrastructure/test_nginx_configuration.py::test_invalid_replacement_certificates_fail[untrusted-server] | Assertions erfolgreich | bestanden | keine |
| RT02-35 | tests/infrastructure/test_nginx_configuration.py::test_missing_and_mismatched_key_fail | Assertions erfolgreich | bestanden | keine |
| RT02-36 | tests/infrastructure/test_nginx_configuration.py::test_reload_and_certificate_rotation | Assertions erfolgreich | bestanden | keine |
| RT02-37 | tests/infrastructure/test_nginx_configuration.py::test_bad_config_does_not_replace_running_workers | Assertions erfolgreich | bestanden | keine |
| RT02-38 | tests/infrastructure/test_nginx_configuration.py::test_restart_and_idempotent_start | Assertions erfolgreich | bestanden | keine |
| RT02-39 | tests/infrastructure/test_nginx_configuration.py::test_production_rejects_development_ca | Assertions erfolgreich | bestanden | keine |
| RT02-40 | tests/infrastructure/test_nginx_configuration.py::test_header_timeout_returns_408 | Assertions erfolgreich | bestanden | keine |

## Zusätzliche Betriebs- und Sicherheitsnachweise

- Offizieller Registry-Digest und nginx -V: Version 1.30.6, TLS-SNI, http_ssl_module.
- make compose-check und make nginx-check erfolgreich, wiederholtes Up/Restart/Reload geprüft.
- Privater Default-Entwicklungsstack nach zusätzlichem Reload mit infra-down gestoppt.
- Netzwerkfall nochmals erweitert geprüft: externer Probe-Client kann private Internal-/Data-
  Testserver nicht erreichen; gleiche interne Netze funktionieren und Internet-Kontrolle gelingt.
- Shellwrapper bash -n und Auswahl der TLS-/mTLS-/Netztests per --collect-only geprüft.
- Test-Cleanup: keine verbliebenen Testcontainer/-netze; vier fremde Nextcloud-Container unverändert.
- Keine manuelle Host-Firewall-, Gruppen-, Socketberechtigungs- oder Truststoreänderung.
- Hosted-CI nicht ausgeführt (keine Remote/kein Push); Workflow enthält jetzt make infra-test.

Host-Firewall/Egress und echte Produktiv-PKI bleiben gemäß Konzept vor Produktivfreigabe offen;
sie werden nicht als getestete Schutzwirkung ausgegeben. Laufende Backend-/API-/Auth-Integration
ist ausdrücklich Aufgabe späterer Phasen.
