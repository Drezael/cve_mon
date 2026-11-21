"""Envoy-Policy, endliche DNS-Cluster und fail-closed Namespacefilter."""

import argparse
import copy
import hashlib
import ipaddress
import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

import yaml
from jsonschema import Draft202012Validator
from jsonschema.exceptions import ValidationError

from scripts.infrastructure.images import REFERENCES
from scripts.infrastructure.manage import (
    Config,
    compose,
    docker_command,
    load_config,
    run,
    service_image,
)

ROOT = Path(__file__).resolve().parents[2]
IMAGE = REFERENCES["envoy"]
CLIENT_SERVICES = {
    "sources": "cve-processing",
    "importer": "cve-processing",
    "enricher": "cve-processing",
    "n8n": "cve-n8n",
    "mail-relay": "cve-mail-relay",
    "status": "cve-service-status",
}
BLOCKED_V4 = [
    "0.0.0.0/8",
    "10.0.0.0/8",
    "100.64.0.0/10",
    "127.0.0.0/8",
    "169.254.0.0/16",
    "172.16.0.0/12",
    "192.0.0.0/24",
    "192.0.2.0/24",
    "192.88.99.0/24",
    "192.168.0.0/16",
    "198.18.0.0/15",
    "198.51.100.0/24",
    "203.0.113.0/24",
    "224.0.0.0/4",
    "240.0.0.0/4",
]


class EnvoyDumper(yaml.SafeDumper):
    """Reproduzierbare lesbare YAML, auch für lange Protobuf-Typnamen."""

    def increase_indent(self, flow: bool = False, indentless: bool = False) -> None:
        super().increase_indent(flow, False)


def represent_string(dumper: EnvoyDumper, value: str) -> yaml.ScalarNode:
    style = ">" if len(value) > 70 and value.startswith("type.googleapis.com/") else None
    return dumper.represent_scalar("tag:yaml.org,2002:str", value, style=style)


EnvoyDumper.add_representer(str, represent_string)


def yaml_text(value: dict[str, Any]) -> str:
    return yaml.dump(value, Dumper=EnvoyDumper, sort_keys=False, width=90)


def directory(config: Config) -> Path:
    return config.secrets_base / "envoy" / config.project


def policy(path: Path | None = None) -> dict[str, Any]:
    "Keine impliziten Hosts, Wildcards, IP-Literale oder unbekannten Client-/Methodenkombinationen."
    value = yaml.safe_load(
        (path or ROOT / "infrastructure/envoy/policies/egress-policy.yml").read_text()
    )
    schema = json.loads(
        (ROOT / "infrastructure/envoy/policies/egress-policy.schema.json").read_text()
    )
    Draft202012Validator(schema).validate(value)
    names = [rule["id"] for rule in value["rules"]]
    identities = [(r["client"], r["host"], r["port"], r["protocol"]) for r in value["rules"]]
    if len(names) != len(set(names)) or len(identities) != len(set(identities)):
        raise ValueError("Doppelte Regel oder Client-/Zielkombination")
    ipaddress.IPv4Address(value["dns"]["address"])
    for rule in value["rules"]:
        if rule["client"] not in value["clients"]:
            raise ValueError("Unbekannter Client")
        methods = set(rule["methods"])
        if (rule["protocol"] == "https" and (rule["port"] != 443 or methods != {"CONNECT"})) or (
            rule["protocol"] == "http"
            and (rule["port"] != 80 or not methods <= {"GET", "HEAD", "POST"})
        ):
            raise ValueError("Protokoll, Port oder Methoden widersprechen der expliziten Policy")
    return dict(value)


def log_config(listener: str, client: str) -> list[dict[str, Any]]:
    """Logge Konfigurations- und Streamwerte ohne unkontrollierte Requestfelder."""
    return [
        {
            "name": "envoy.access_loggers.stdout",
            "typed_config": {
                "@type": (
                    "type.googleapis.com/envoy.extensions.access_loggers.stream.v3.StdoutAccessLog"
                ),
                "log_format": {
                    "json_format": {
                        "time": "%START_TIME%",
                        "listener": listener,
                        "client": client,
                        "target_rule": "%ROUTE_NAME%",
                        "upstream": "%UPSTREAM_HOST%",
                        "status": "%RESPONSE_CODE%",
                        "flags": "%RESPONSE_FLAGS%",
                        "duration_ms": "%DURATION%",
                        "bytes_received": "%BYTES_RECEIVED%",
                        "bytes_sent": "%BYTES_SENT%",
                        "correlation_id": "%CONNECTION_ID%",
                    }
                },
            },
        }
    ]


def address(host: str, port: int) -> dict[str, Any]:
    return {"socket_address": {"address": host, "port_value": port}}


def dns_cluster(name: str, host: str, port: int, value: dict[str, Any]) -> dict[str, Any]:
    limits = value["limits"]
    dns = value["dns"]
    return {
        "name": name,
        "type": "STRICT_DNS",
        "connect_timeout": "2s",
        "dns_lookup_family": "V4_ONLY",
        "dns_refresh_rate": str(dns["refresh_seconds"]) + "s",
        "respect_dns_ttl": True,
        "dns_failure_refresh_rate": {"base_interval": "1s", "max_interval": "5s"},
        "dns_resolution_config": {
            "dns_resolver_options": {"use_tcp_for_dns_lookups": False},
            "resolvers": [address(dns["address"], dns["port"])],
        },
        "typed_dns_resolver_config": {
            "name": "envoy.network.dns_resolver.cares",
            "typed_config": {
                "@type": (
                    "type.googleapis.com/envoy.extensions.network.dns_resolver."
                    "cares.v3.CaresDnsResolverConfig"
                ),
                "resolvers": [address(dns["address"], dns["port"])],
                "dns_resolver_options": {"use_tcp_for_dns_lookups": False},
                "query_timeout_seconds": dns["timeout_seconds"],
                "query_tries": 1,
            },
        },
        "circuit_breakers": {
            "thresholds": [
                {
                    "max_connections": limits["max_connections"],
                    "max_pending_requests": limits["max_pending_requests"],
                    "max_requests": limits["max_requests"],
                    "max_retries": 0,
                }
            ]
        },
        "load_assignment": {
            "cluster_name": name,
            "endpoints": [{"lb_endpoints": [{"endpoint": {"address": address(host + ".", port)}}]}],
        },
    }


def hcm(
    client: str, routes: list[dict[str, Any]], value: dict[str, Any], health: bool = False
) -> dict[str, Any]:
    limits = value["limits"]
    filters = []
    if not health:
        filters.append(
            {
                "name": "envoy.filters.http.buffer",
                "typed_config": {
                    "@type": "type.googleapis.com/envoy.extensions.filters.http.buffer.v3.Buffer",
                    "max_request_bytes": limits["max_request_bytes"],
                },
            }
        )
    filters.append(
        {
            "name": "envoy.filters.http.router",
            "typed_config": {
                "@type": "type.googleapis.com/envoy.extensions.filters.http.router.v3.Router",
                "suppress_envoy_headers": True,
            },
        }
    )
    return {
        "name": "envoy.filters.network.http_connection_manager",
        "typed_config": {
            "@type": (
                "type.googleapis.com/envoy.extensions.filters.network."
                "http_connection_manager.v3.HttpConnectionManager"
            ),
            "stat_prefix": "health" if health else "http_" + client,
            "codec_type": "HTTP1",
            "use_remote_address": True,
            "internal_address_config": {"cidr_ranges": []},
            "generate_request_id": True,
            "preserve_external_request_id": False,
            "stream_idle_timeout": str(limits["idle_timeout_seconds"]) + "s",
            "request_timeout": str(limits["request_timeout_seconds"]) + "s",
            "request_headers_timeout": "5s",
            "max_request_headers_kb": 16,
            "http_protocol_options": {"allow_absolute_url": True},
            "common_http_protocol_options": {
                "headers_with_underscores_action": "REJECT_REQUEST",
                "idle_timeout": str(limits["idle_timeout_seconds"]) + "s",
                "max_requests_per_connection": 100,
            },
            "upgrade_configs": []
            if health
            else [{"upgrade_type": "CONNECT", "filters": [filters[-1]]}],
            "route_config": {
                "name": "routes_" + client,
                "virtual_hosts": [
                    {
                        "name": client,
                        "domains": ["*"],
                        "request_headers_to_remove": [
                            "proxy-authorization",
                            "x-envoy-original-dst-host",
                            "x-envoy-upstream-rq-timeout-ms",
                            "x-envoy-upstream-rq-per-try-timeout-ms",
                            "x-envoy-internal",
                            "x-forwarded-for",
                            "x-forwarded-host",
                            "x-original-url",
                        ],
                        "routes": routes
                        + [
                            {
                                "name": "default-deny",
                                "match": {"prefix": "/"},
                                "direct_response": {"status": 403},
                            }
                        ],
                    }
                ],
            },
            "http_filters": filters,
            "access_log": log_config("health" if health else "http", client),
        },
    }


def generate(value: dict[str, Any], bindings: dict[str, dict[str, Any]]) -> dict[str, Any]:
    """Exakte statische Routen; DNS ist dynamisch, Zielwahl niemals vom Client überschreibbar."""
    clusters = []
    http_chains = []
    for client, binding in sorted(bindings.items()):
        if client not in {"importer", "enricher", "sources", "n8n"}:
            continue
        routes = []
        for rule in value["rules"]:
            if not rule["enabled"] or rule["client"] != client:
                continue
            name = "target_" + rule["id"]
            clusters.append(dns_cluster(name, rule["host"], rule["port"], value))
            authorities = [rule["host"] + ":" + str(rule["port"])]
            if rule["protocol"] == "http":
                authorities.append(rule["host"])
            for authority in authorities:
                for method in rule["methods"]:
                    match: dict[str, Any] = {
                        "headers": [
                            {"name": ":authority", "string_match": {"exact": authority}},
                            {"name": ":method", "string_match": {"exact": method}},
                        ]
                    }
                    route = {
                        "cluster": name,
                        "timeout": str(value["limits"]["request_timeout_seconds"]) + "s",
                    }
                    if method == "CONNECT":
                        match["connect_matcher"] = {}
                        route["upgrade_configs"] = [
                            {"upgrade_type": "CONNECT", "connect_config": {}}
                        ]
                        route["timeout"] = "0s"
                    else:
                        match["prefix"] = "/"
                    routes.append({"name": rule["id"], "match": match, "route": route})
        http_chains.append(
            {
                "filter_chain_match": {
                    "source_prefix_ranges": [{"address_prefix": binding["ip"], "prefix_len": 32}]
                },
                "filters": [hcm(client, routes, value)],
            }
        )
    reject = {
        "filters": [
            {
                "name": "envoy.filters.network.direct_response",
                "typed_config": {
                    "@type": (
                        "type.googleapis.com/envoy.extensions.filters.network."
                        "direct_response.v3.Config"
                    )
                },
            }
        ]
    }
    listeners = [
        {
            "name": "http_forward",
            "address": address("0.0.0.0", 3128),
            "per_connection_buffer_limit_bytes": 65536,
            "filter_chains": http_chains,
            "default_filter_chain": reject,
        }
    ]
    smtp = value["smtp"]
    smtp_chains = []
    if smtp["enabled"]:
        clusters.append(dns_cluster("smtp_smarthost", smtp["host"], smtp["port"], value))
    else:
        clusters.append(
            {
                "name": "smtp_smarthost",
                "type": "STATIC",
                "connect_timeout": "1s",
                "load_assignment": {"cluster_name": "smtp_smarthost", "endpoints": []},
            }
        )
    if "mail-relay" in bindings:
        smtp_chains = [
            {
                "filter_chain_match": {
                    "source_prefix_ranges": [
                        {"address_prefix": bindings["mail-relay"]["ip"], "prefix_len": 32}
                    ]
                },
                "filters": [
                    {
                        "name": "envoy.filters.network.tcp_proxy",
                        "typed_config": {
                            "@type": (
                                "type.googleapis.com/envoy.extensions.filters.network."
                                "tcp_proxy.v3.TcpProxy"
                            ),
                            "stat_prefix": "smtp",
                            "cluster": "smtp_smarthost",
                            "upstream_connect_mode": "IMMEDIATE",
                            "idle_timeout": str(value["limits"]["idle_timeout_seconds"]) + "s",
                            "max_connect_attempts": 1,
                            "access_log": log_config("smtp", "mail-relay"),
                        },
                    }
                ],
            }
        ]
    listeners.append(
        {
            "name": "smtp_tcp",
            "address": address("0.0.0.0", 1587),
            "filter_chains": smtp_chains,
            "default_filter_chain": reject,
        }
    )
    # Dedicated, source-pinned listeners isolate each user's upstream transport.
    for route in smtp.get("routes", []):
        name = "smtp_user_" + str(route["listen_port"])
        clusters.append(dns_cluster(name, route["host"], route["port"], value))
        listener: dict[str, Any] = copy.deepcopy(listeners[1])
        listener["name"] = name
        listener["address"] = address("0.0.0.0", route["listen_port"])
        for chain in listener["filter_chains"]:
            chain["filters"][0]["typed_config"]["cluster"] = name
        listeners.append(listener)
    # Unix-Adminsocket: nur zwei vorgegebene GET-Routen, keine generische Adminweiterleitung.
    clusters.append(
        {
            "name": "local_admin",
            "type": "STATIC",
            "connect_timeout": "1s",
            "load_assignment": {
                "cluster_name": "local_admin",
                "endpoints": [
                    {
                        "lb_endpoints": [
                            {"endpoint": {"address": {"pipe": {"path": "/tmp/envoy-admin.sock"}}}}
                        ]
                    }
                ],
            },
        }
    )
    health_routes = []
    for path, rewrite in [("/healthz", "/ready"), ("/metrics", "/stats/prometheus")]:
        health_routes.append(
            {
                "name": "internal" + path,
                "match": {
                    "path": path,
                    "headers": [{"name": ":method", "string_match": {"exact": "GET"}}],
                },
                "route": {"cluster": "local_admin", "prefix_rewrite": rewrite, "timeout": "2s"},
                "response_headers_to_add": [
                    {"header": {"key": "cache-control", "value": "no-store"}}
                ],
            }
        )
    sources = [{"address_prefix": "127.0.0.1", "prefix_len": 32}]
    if "status" in bindings:
        sources.append({"address_prefix": bindings["status"]["ip"], "prefix_len": 32})
    listeners.append(
        {
            "name": "internal_health",
            "address": address("0.0.0.0", 9901),
            "filter_chains": [
                {
                    "filter_chain_match": {"source_prefix_ranges": sources},
                    "filters": [hcm("status", health_routes, value, health=True)],
                }
            ],
            "default_filter_chain": reject,
        }
    )
    return {
        "node": {"id": "cve-egress-proxy", "cluster": "cve-egress"},
        "admin": {
            "access_log": [],
            "address": {"pipe": {"path": "/tmp/envoy-admin.sock", "mode": 384}},
        },
        "static_resources": {"listeners": listeners, "clusters": clusters},
        "overload_manager": {
            "refresh_interval": "0.25s",
            "resource_monitors": [
                {
                    "name": "envoy.resource_monitors.global_downstream_max_connections",
                    "typed_config": {
                        "@type": (
                            "type.googleapis.com/envoy.extensions.resource_monitors."
                            "downstream_connections.v3.DownstreamConnectionsConfig"
                        ),
                        "max_active_downstream_connections": value["limits"]["max_connections"],
                    },
                },
                {
                    "name": "envoy.resource_monitors.fixed_heap",
                    "typed_config": {
                        "@type": (
                            "type.googleapis.com/envoy.extensions.resource_monitors."
                            "fixed_heap.v3.FixedHeapConfig"
                        ),
                        "max_heap_size_bytes": 134217728,
                    },
                },
            ],
            "actions": [
                {
                    "name": "envoy.overload_actions.stop_accepting_requests",
                    "triggers": [
                        {"name": "envoy.resource_monitors.fixed_heap", "threshold": {"value": 0.95}}
                    ],
                }
            ],
        },
    }


def inspect_container(name: str) -> dict[str, Any]:
    return dict(json.loads(run([*docker_command(), "inspect", name]).stdout)[0])


def bind_clients(config: Config, clients: dict[str, str]) -> dict[str, dict[str, Any]]:
    bindings = {}
    for role, name in clients.items():
        if role not in CLIENT_SERVICES:
            raise ValueError("Unbekannte Clientrolle")
        item = inspect_container(name)
        labels = item["Config"].get("Labels", {})
        networks = item["NetworkSettings"]["Networks"]
        host = item["HostConfig"]
        if (
            labels.get("com.docker.compose.project") != config.project
            or labels.get("com.docker.compose.service") != CLIENT_SERVICES[role]
        ):
            raise ValueError("Client gehört nicht zum autorisierten Projekt/Dienst")
        mail_master = (
            role == "mail-relay"
            and item["Config"].get("Image")
            == service_image(
                config,
                "cve-mail-relay",
                REFERENCES["mail"],
            )
            and labels.get("org.cve-monitoring.managed") == "phase-05"
            and item["Config"].get("User") == "0:0"
            and {cap.removeprefix("CAP_") for cap in host.get("CapAdd", [])}
            == {"CHOWN", "DAC_OVERRIDE", "FOWNER", "SETUID", "SETGID", "KILL"}
        )
        if (
            not item["State"]["Running"]
            or host.get("Privileged")
            or (host.get("CapAdd") and not mail_master)
            or set(host.get("CapDrop", [])) != {"ALL"}
        ):
            raise ValueError("Client benötigt geprüfte minimale Capabilities ohne Netzwerkrechte")
        if not mail_master and (
            not item["Config"].get("User") or item["Config"]["User"].split(":")[0] in {"0", "root"}
        ):
            raise ValueError(
                "Proxyclients benötigen Nicht-Root; nur der geprüfte Postfix-Master ist ausgenommen"
            )
        if any(
            n
            not in {
                config.project + "_" + zone
                for zone in ("cve_internal", "cve_data", "cve_egress_internal")
            }
            for n in networks
        ):
            raise ValueError("Client besitzt unerlaubtes zusätzliches Netz")
        endpoint = networks.get(config.project + "_cve_egress_internal")
        if not endpoint:
            raise ValueError("Client ist nicht im internen Egressnetz")
        ip = str(ipaddress.IPv4Address(endpoint["IPAddress"]))
        mac = endpoint["MacAddress"]
        if not re.fullmatch(r"(?:[0-9a-f]{2}:){5}[0-9a-f]{2}", mac):
            raise ValueError("Ungültige Endpoint-MAC")
        bindings[role] = {
            "container_id": item["Id"],
            "endpoint_id": endpoint["EndpointID"],
            "ip": ip,
            "mac": mac,
        }
    return bindings


def render(config: Config, value: dict[str, Any], bindings: dict[str, dict[str, Any]]) -> Path:
    target = directory(config)
    target.mkdir(parents=True, exist_ok=True, mode=0o755)
    model = generate(value, bindings)
    (target / "envoy.yaml").write_text(yaml_text(model))
    bootstrap = json.loads(json.dumps(model))
    bootstrap["static_resources"]["listeners"] = []
    smtp_clusters = [
        c for c in bootstrap["static_resources"]["clusters"] if c["name"].startswith("smtp_")
    ]
    bootstrap["static_resources"]["clusters"] = [
        c for c in bootstrap["static_resources"]["clusters"] if not c["name"].startswith("smtp_")
    ]
    publish_smtp_cluster(target, smtp_clusters)
    bootstrap["static_resources"]["clusters"].append(
        {
            "name": "guarded_listener_configuration",
            "type": "STATIC",
            "connect_timeout": "1s",
            "load_assignment": {
                "cluster_name": "guarded_listener_configuration",
                "endpoints": [
                    {
                        "lb_endpoints": [
                            {
                                "endpoint": {
                                    "address": {
                                        "pipe": {"path": "/etc/cve-envoy/listener-discovery.sock"}
                                    }
                                }
                            }
                        ]
                    }
                ],
            },
        }
    )
    bootstrap["dynamic_resources"] = {
        "lds_config": {
            "api_config_source": {
                "api_type": "REST",
                "transport_api_version": "V3",
                "cluster_names": ["guarded_listener_configuration"],
                "refresh_delay": "1s",
                "request_timeout": "30s",
            },
            "resource_api_version": "V3",
            "initial_fetch_timeout": "0s",
        }
    }
    bootstrap["dynamic_resources"]["cds_config"] = {
        "path": "/etc/cve-envoy/smtp-cluster.json",
        "resource_api_version": "V3",
    }
    (target / "bootstrap.yaml").write_text(yaml_text(bootstrap))
    (target / "bindings.json").write_text(json.dumps(bindings, indent=2))
    (target / "policy.json").write_text(json.dumps(value, indent=2))
    for path in target.iterdir():
        if path.is_file():
            path.chmod(0o644)
    return target / "envoy.yaml"


def publish_smtp_cluster(target: Path, cluster: dict[str, Any] | list[dict[str, Any]]) -> None:
    """Native filesystem CDS changes only the configured SMTP cluster, never a container."""
    import uuid

    payload = {
        "version_info": str(uuid.uuid4()),
        "type_url": "type.googleapis.com/envoy.config.cluster.v3.Cluster",
        "resources": [
            {"@type": "type.googleapis.com/envoy.config.cluster.v3.Cluster", **item}
            for item in (cluster if isinstance(cluster, list) else [cluster])
        ],
    }
    temporary = target / "smtp-cluster.pending"
    temporary.write_text(json.dumps(payload))
    temporary.chmod(0o644)
    temporary.replace(target / "smtp-cluster.json")


def check(config: Config, path: Path | None = None) -> None:
    from scripts.hardening.runtime_images import build

    if not config.compose_overrides:
        build(config, "envoy")
    file = path or directory(config) / "envoy.yaml"
    if not file.is_file():
        raise ValueError("Envoy-Konfiguration fehlt")
    model = yaml.safe_load(file.read_text())
    if not isinstance(model, dict):
        raise ValueError("Envoy-Konfiguration muss ein Objekt sein")
    listeners = model.get("static_resources", {}).get("listeners", [])
    if {
        listener.get("name")
        for listener in listeners
        if not str(listener.get("name", "")).startswith("smtp_user_")
    } != {
        "http_forward",
        "smtp_tcp",
        "internal_health",
    }:
        raise ValueError("Vorgeschriebene Listener fehlen oder sind erweitert")
    if model.get("admin", {}).get("address") != {
        "pipe": {"path": "/tmp/envoy-admin.sock", "mode": 384}
    }:
        raise ValueError("Admin darf ausschließlich den privaten Unix-Socket verwenden")
    run(
        [
            *docker_command(),
            "run",
            "--rm",
            "--network",
            "none",
            "--read-only",
            "--cap-drop",
            "ALL",
            "--user",
            "65532:65532",
            "--security-opt",
            "no-new-privileges:true",
            "--entrypoint",
            "/usr/local/bin/envoy",
            "-v",
            str(file) + ":/etc/envoy/checked.yaml:ro",
            service_image(config, "cve-egress-proxy", IMAGE),
            "--mode",
            "validate",
            "--log-level",
            "error",
            "-c",
            "/etc/envoy/checked.yaml",
        ]
    )


def netns(config: Config) -> tuple[str, int]:
    name = compose(config, ["ps", "-q", "cve-egress-proxy"]).stdout.strip()
    if not name:
        raise ValueError("Envoy-Container fehlt")
    item = inspect_container(name)
    if (
        item["Config"]["Image"] != service_image(config, "cve-egress-proxy", IMAGE)
        or item["Config"]["Labels"].get("org.cve-monitoring.project") != config.project
    ):
        raise ValueError("Fremder Container darf nicht gefiltert werden")
    if set(item["NetworkSettings"]["Networks"]) != {
        config.project + "_cve_egress_internal",
        config.project + "_cve_egress_external",
    }:
        raise ValueError("Envoy besitzt unerlaubte Netzzuordnung")
    pid = int(item["State"]["Pid"])
    if pid <= 1:
        raise ValueError("Ungültiger Namespace-Prozess")
    return name, pid


def namespace_command(pid: int, args: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
    "Hostwerkzeug ausschließlich im expliziten Container-Netznamespace; kein Mount-/PID-Wechsel."
    prefix = [] if os.geteuid() == 0 else ["sudo", "-n"]
    return run([*prefix, "nsenter", "--target", str(pid), "--net", "--", *args], **kwargs)


def guard_rules(
    internal_ip: str,
    internal_interface: str,
    bindings: dict[str, dict[str, Any]],
    value: dict[str, Any],
    host_addresses: list[str],
) -> str:
    lines = [
        "table inet cve_egress {",
        " chain input { type filter hook input priority 0; policy drop;",
        " ct state established,related accept",
        ' iifname "lo" ip daddr 127.0.0.1 tcp dport 9901 accept',
    ]
    for role, b in sorted(bindings.items()):
        ports = (
            [3128]
            if role in {"importer", "enricher", "sources", "n8n"}
            else (
                ([1587] if value["smtp"]["enabled"] else [])
                + [r["listen_port"] for r in value["smtp"].get("routes", [])]
                if role == "mail-relay"
                else [9901]
            )
        )
        if role == "mail-relay" and not ports:
            continue
        lines.append(
            f' iifname "{internal_interface}" ip daddr {internal_ip} ip saddr {b["ip"]} '
            f"ether saddr {b['mac']} tcp dport {{ "
            + ",".join(map(str, ports))
            + " } counter accept"
        )
    lines += [
        " counter drop",
        " }",
        " chain forward { type filter hook forward priority 0; policy drop; counter drop; }",
        " chain output { type filter hook output priority -110; policy drop;",
        " ct state established,related accept",
        ' oifname "lo" ip daddr 127.0.0.1 tcp dport 9901 accept',
    ]
    dns = value["dns"]
    for protocol in ("udp", "tcp"):
        lines.append(f" ip daddr {dns['address']} {protocol} dport {dns['port']} accept")
    blocked = [
        str(n)
        for n in ipaddress.collapse_addresses(
            ipaddress.IPv4Network(n) for n in BLOCKED_V4 + host_addresses
        )
    ]
    lines.append(" ip daddr { " + ", ".join(blocked) + " } counter reject")
    # IPv6 including mapped-address evasions: V4_ONLY resolver, additionally kernel default deny.
    lines.append(" meta nfproto ipv6 counter reject")
    allowed_ports = {r["port"] for r in value["rules"] if r["enabled"]}
    if value["smtp"]["enabled"]:
        allowed_ports.add(value["smtp"]["port"])
    allowed_ports.update(r["port"] for r in value["smtp"].get("routes", []))
    if allowed_ports:
        lines.append(
            " meta nfproto ipv4 tcp dport { "
            + ", ".join(map(str, sorted(allowed_ports)))
            + " } counter accept"
        )
    lines += [" counter reject", " }", "}"]
    return "\n".join(lines) + "\n"


def install_guard(config: Config, value: dict[str, Any], clients: dict[str, str]) -> None:
    name, pid = netns(config)
    namespace = namespace_command(pid, ["readlink", "/proc/self/ns/net"]).stdout.strip()
    if namespace == os.readlink("/proc/self/ns/net"):
        raise ValueError("Host-Netznamespace ist verboten")
    bindings = bind_clients(config, clients)
    expected = json.loads((directory(config) / "bindings.json").read_text())
    if bindings != expected:
        raise ValueError("Clientbindung änderte sich während Start")
    internal = inspect_container(name)["NetworkSettings"]["Networks"][
        config.project + "_cve_egress_internal"
    ]["IPAddress"]
    host_addresses = []
    for interface in json.loads(run(["ip", "-j", "-4", "address", "show"]).stdout):
        for entry in interface.get("addr_info", []):
            host_addresses.append(str(ipaddress.IPv4Address(entry["local"])) + "/32")
    # Container identity binds the guard without a custom software entrypoint.
    import uuid

    boot = str(uuid.UUID(inspect_container(name)["Id"][:32]))
    if not re.fullmatch(r"[0-9a-f-]{36}", boot):
        raise ValueError("Ungültiger Bootnachweis")
    interfaces = json.loads(namespace_command(pid, ["ip", "-j", "-4", "address", "show"]).stdout)
    internal_interface = next(
        item["ifname"]
        for item in interfaces
        if any(a.get("local") == internal for a in item.get("addr_info", []))
    )
    if not re.fullmatch(r"[a-zA-Z0-9_.-]{1,15}", internal_interface):
        raise ValueError("Ungültige interne Netzschnittstelle")
    rules = guard_rules(internal, internal_interface, bindings, value, host_addresses)
    # Fresh namespace only: a second in-place replacement would retain old connections.
    namespace_command(pid, ["nft", "-c", "-f", "-"], input=rules)
    namespace_command(pid, ["nft", "-f", "-"], input=rules)
    if netns(config) != (name, pid):
        raise ValueError("Container wechselte während Guardinstallation")
    install_client_guards(config, bindings, internal)
    if bind_clients(config, clients) != bindings:
        raise ValueError("Clientbindung änderte sich während Guardinstallation")
    output = namespace_command(pid, ["nft", "list", "table", "inet", "cve_egress"]).stdout
    (directory(config) / "guard.nft").write_text(rules)
    (directory(config) / "guard.installed.nft").write_text(output)
    digest = hashlib.sha256((directory(config) / "envoy.yaml").read_bytes()).hexdigest()
    temporary = directory(config) / "guard.pending"
    temporary.write_text(namespace + " " + digest + " " + boot + "\n")
    temporary.chmod(0o644)
    temporary.replace(directory(config) / "guard.ready")


def install_client_guards(
    config: Config, bindings: dict[str, dict[str, Any]], internal: str | None
) -> None:
    """Default-deny sources before upstream Envoy starts; release only after its guard."""
    for role, binding in bindings.items():
        client = inspect_container(binding["container_id"])
        # The consolidated processing namespace has its own complete default-deny guard.
        if client["Config"].get("Labels", {}).get("com.docker.compose.service") == "cve-processing":
            continue
        client_pid = int(client["State"]["Pid"])
        if client_pid <= 1:
            raise ValueError("Ungültiger Client-Namespace")
        client_namespace = namespace_command(
            client_pid, ["readlink", "/proc/self/ns/net"]
        ).stdout.strip()
        if client_namespace == os.readlink("/proc/self/ns/net"):
            raise ValueError("Client teilt einen unerlaubten Netznamespace")
        port = (
            3128
            if role in {"importer", "enricher", "sources", "n8n"}
            else (1587 if role == "mail-relay" else 9901)
        )
        extra_rules = ""
        if role in {"importer", "enricher", "sources"}:
            extra_rules += " ip daddr 127.0.0.1 tcp dport { 8000, 8001 } accept\n"
            data_zone = config.project + "_cve_data"
            if data_zone in client["NetworkSettings"]["Networks"]:
                postgres_id = compose(config, ["ps", "-q", "cve-postgres"]).stdout.strip()
                postgres = inspect_container(postgres_id)
                labels = postgres["Config"].get("Labels", {})
                if (
                    labels.get("com.docker.compose.project") != config.project
                    or labels.get("com.docker.compose.service") != "cve-postgres"
                    or not postgres["State"]["Running"]
                ):
                    raise ValueError("Importer database endpoint must belong to its project")
                address = str(
                    ipaddress.IPv4Address(
                        postgres["NetworkSettings"]["Networks"][data_zone]["IPAddress"]
                    )
                )
                extra_rules += f" ip daddr {address} tcp dport 5432 accept\n"
        client_rules = (
            "table inet cve_clientegress {\n"
            " chain forward { type filter hook forward priority 0; policy drop; }\n"
            " chain output { type filter hook output priority -110; policy drop;\n"
            " ct direction reply accept\n"
            " ip daddr 127.0.0.11 udp dport 53 accept\n"
            " ip daddr 127.0.0.11 tcp dport 53 accept\n"
            + (
                f" ip daddr {internal} tcp dport {{ 1587, 20000-29999 }} accept\n"
                if internal and role == "mail-relay"
                else f" ip daddr {internal} tcp dport {port} accept\n"
                if internal
                else ""
            )
            + extra_rules
            + " counter reject\n }\n}\n"
        )
        existing = namespace_command(client_pid, ["nft", "list", "tables"]).stdout
        if "table inet cve_clientegress" in existing:
            client_rules = "delete table inet cve_clientegress\n" + client_rules
        namespace_command(client_pid, ["nft", "-c", "-f", "-"], input=client_rules)
        namespace_command(client_pid, ["nft", "-f", "-"], input=client_rules)


def wait_client_ready(config: Config, service: str, timeout: float = 60) -> None:
    """Wait for fresh health probes after guard release, including a cached unhealthy state."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        identifier = compose(config, ["ps", "-q", service]).stdout.strip()
        if identifier:
            state = inspect_container(identifier)["State"]
            if state.get("Running") and state.get("Health", {}).get("Status") == "healthy":
                return
        time.sleep(0.5)
    raise ValueError("Bounded client readiness deadline exceeded")


def start(config: Config, value: dict[str, Any], clients: dict[str, str]) -> None:
    bindings = bind_clients(config, clients)
    render(config, value, bindings)
    check(config)
    from scripts.infrastructure.listener_discovery import ListenerDiscovery

    listeners = generate(value, bindings)["static_resources"]["listeners"]
    with ListenerDiscovery(directory(config), listeners) as delivery:
        install_client_guards(config, bindings, None)
        compose(config, ["up", "-d", "--force-recreate", "cve-egress-proxy"])
        try:
            install_guard(config, value, clients)
            delivery.release(netns(config)[1])
            compose(
                config,
                ["up", "-d", "--no-recreate", "--wait", "--wait-timeout", "30", "cve-egress-proxy"],
            )
        except BaseException:
            compose(config, ["stop", "cve-egress-proxy"])
            raise


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=["policy-check", "render", "check", "up", "down"])
    parser.add_argument("--policy", type=Path)
    parser.add_argument(
        "--clients", type=Path, help="JSON-Mapping Rolle -> eigener laufender Container"
    )
    args = parser.parse_args()
    try:
        config = load_config()
        value = policy(args.policy)
        clients = json.loads(args.clients.read_text()) if args.clients else {}
        if args.action == "policy-check":
            pass
        elif args.action == "render":
            render(config, value, bind_clients(config, clients))
        elif args.action == "check":
            if not (directory(config) / "envoy.yaml").exists():
                render(config, value, {})
            check(config)
        elif args.action == "up":
            start(config, value, clients)
        elif args.action == "down":
            compose(config, ["stop", "cve-egress-proxy"])
        print(json.dumps({"action": args.action, "project": config.project, "result": "ok"}))
        return 0
    except (
        OSError,
        ValueError,
        subprocess.SubprocessError,
        ValidationError,
        yaml.YAMLError,
    ) as exc:
        print(
            json.dumps({"action": args.action, "result": "error", "code": type(exc).__name__}),
            file=sys.stderr,
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
