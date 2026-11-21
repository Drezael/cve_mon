"""Namespace firewall: only PostgreSQL and explicitly configured SSH endpoints."""

import ipaddress
import json

from cve_automation.service import destination

from scripts.database import manage as db
from scripts.infrastructure import network as net
from scripts.infrastructure.manage import Config


def install_guard(config: Config) -> None:
    from scripts.application.manage import identity, peer

    item = identity(config, "cve-sources")
    pid = int(item["State"]["Pid"])
    namespace = net.namespace_command(pid, ["readlink", "/proc/self/ns/net"]).stdout.strip()
    targets: set[tuple[str, int]] = set()
    with db.connect(config, "dashboard_admin") as session:
        profiles = session.execute(
            "SELECT DISTINCT p.host,p.port FROM inventory.ansible_profiles p J"
            "OIN inventory.servers s ON s.id=p.server_id WHERE s.status='activ"
            "e' AND inventory.ansible_owner_active(p.owner_id)"
        ).fetchall()
    for profile in profiles:
        try:
            address = destination(profile["host"], profile["port"])
            targets.add((address, profile["port"]))
        except (OSError, ValueError):
            continue
    rules = (
        "table inet cve_ssh {\n"
        " chain forward { type filter hook forward priority 0; policy drop; }\n"
        " chain output { type filter hook output priority -110; policy drop;\n"
        " ct direction reply accept\n ip daddr 127.0.0.1 accept\n"
        " ip daddr 127.0.0.11 udp dport 53 accept\n"
        " ip daddr 127.0.0.11 tcp dport 53 accept\n"
    )
    rules += f" ip daddr {db.address(config)} tcp dport 5432 accept\n"
    rules += "".join(
        f" {'ip6' if ipaddress.ip_address(host).version == 6 else 'ip'} "
        f"daddr {host} tcp dport {port} accept\n"
        for host, port in sorted(targets)
    )
    rules += (
        " counter reject\n }\n chain input { type filter hook input priority -110; policy drop;\n"
        ' ct state established,related accept\n iifname "lo" accept\n'
    )
    api_address = peer(config, "cve-api", "cve_data")
    if api_address:
        rules += f" ip saddr {api_address} tcp dport 8000 accept\n"
    rules += " }\n}\n"
    path = config.secrets_base / "ansible" / config.project / "network-proof.json"
    proof = {"namespace": namespace, "rules": rules}
    if path.exists() and json.loads(path.read_text()) == proof:
        return
    existing = net.namespace_command(pid, ["nft", "list", "tables"]).stdout
    apply = ("delete table inet cve_ssh\n" if "table inet cve_ssh" in existing else "") + rules
    net.namespace_command(pid, ["nft", "-c", "-f", "-"], input=apply)
    net.namespace_command(pid, ["nft", "-f", "-"], input=apply)
    path.write_text(json.dumps(proof))
    path.chmod(0o600)
