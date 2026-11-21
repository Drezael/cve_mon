# Mailrelay-Architektur

```mermaid
flowchart LR
    N[Notification mit privatem Clientkey] -->|2525 STARTTLS + CA + Pin| P[Postfix]
    P --- Q[(Native persistente Queue)]
    P -->|1587 TCP intern| E[Envoy]
    E -->|festes Ziel 587| S[Provider STARTTLS + AUTH]
```

Postfix liegt ausschließlich in cve_internal/cve_egress_internal, Envoy in beiden
Egressnetzen. Postfix prüft den tatsächlichen Provider-Namen trotz TCP-Zwischenhost.
Keine MX-Zustellung und keine zweite Transportqueue. N ist ein späterer Fachservice.
[ADR-0023](decisions/ADR-0023-postfix-phase05.md),
[Integration](../deployment/postfix.md), [Übergabe](../development/phase-05-handover.md).
