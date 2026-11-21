"""Postfix boot/config, native maps, health and sanitized logs; never an application mailqueue."""

import datetime
import hashlib
import json
import os
import pwd
import re
import shutil
import signal
import stat
import subprocess
import sys
import time
import uuid
from pathlib import Path
from typing import Any

RUN = Path("/run/postfix")
SOURCE = Path("/mail-state")
KEYS = Path("/mail-secrets")
QUEUE = Path("/var/spool/postfix")


def native(args: list[str]) -> str:
    return subprocess.run(args, check=True, capture_output=True, text=True, timeout=20).stdout


def protected(path: Path) -> str:
    if (
        path.is_symlink()
        or not path.is_file()
        or stat.S_IMODE(path.stat().st_mode) not in (0o400, 0o600)
    ):
        raise ValueError("protected secret required")
    value = path.read_text().removesuffix("\n")
    if not value or any(c in value for c in "\r\n\0"):
        raise ValueError("single nonempty secret required")
    return value


def fingerprint(path: Path) -> str:
    value = native(["openssl", "x509", "-in", str(path), "-fingerprint", "-sha256", "-noout"])
    return value.strip().split("=", 1)[1].upper()


def write(name: str, content: str, private: bool = False) -> None:
    path = RUN / name
    path.write_text(content)
    account = pwd.getpwnam("postfix")
    os.chown(path, 0, account.pw_gid)
    path.chmod(0o640 if private else 0o644)


def configure() -> dict[str, Any]:
    value = json.loads((SOURCE / "policy.json").read_text())
    RUN.mkdir(mode=0o750, parents=True, exist_ok=True)
    account = pwd.getpwnam("postfix")
    os.chown(RUN, 0, account.pw_gid)
    shutil.copytree("/etc/postfix.default", "/etc/postfix", dirs_exist_ok=True)
    for name in ("main.cf", "master.cf"):
        shutil.copyfile("/opt/cve-mail/" + name, "/etc/postfix/" + name)
    # Verify actual mount rights, not Compose's declarative Secret mode.
    username = protected(KEYS / "smtp_username")
    password = protected(KEYS / "smtp_password")
    key = KEYS / "server.key"
    if key.is_symlink() or stat.S_IMODE(key.stat().st_mode) not in (0o400, 0o600):
        raise ValueError("private key mode")
    for name in ("client-ca.crt", "upstream-ca.crt", "server.crt"):
        native(["openssl", "x509", "-in", str(SOURCE / name), "-checkend", "60", "-noout"])
        shutil.copyfile(SOURCE / name, RUN / name)
    native(
        [
            "openssl",
            "verify",
            "-CAfile",
            str(SOURCE / "client-ca.crt"),
            "-verify_hostname",
            "cve-mail-relay",
            str(SOURCE / "server.crt"),
        ]
    )
    cert = native(["openssl", "x509", "-in", str(SOURCE / "server.crt"), "-pubkey", "-noout"])
    public = native(["openssl", "pkey", "-in", str(key), "-pubout"])
    if cert != public:
        raise ValueError("certificate key mismatch")
    write("server.key", key.read_text(), True)
    hop = "[" + value["smarthost"] + "]:" + str(value["port"])
    native(["postconf", "-e", "relayhost = " + (hop if value["enabled"] else "[127.0.0.1]:1")])
    write("sasl-passwd", hop + " " + username + ":" + password + "\n", True)
    write(
        "tls-policy",
        hop + " secure match=" + value["smarthost"] + " servername=" + value["smarthost"] + "\n",
    )
    profile_path = SOURCE / "smtp-profiles.json"
    if profile_path.exists():
        profiles = json.loads(profile_path.read_text())
        credentials = json.loads(protected(KEYS / "smtp-profiles.json"))
        relays, auth, rewrites = [], [], []
        policies: dict[str, str] = {}
        for profile in profiles:
            hop = "[" + profile["host"] + "]:" + str(profile["port"])
            alias = profile["envelope_sender"]
            secret = credentials[alias]
            relays.append(alias + " " + hop)
            local_capture = profile["host"] == "mailhog.cve.test" and profile["port"] == 1025
            if not local_capture:
                auth.append(alias + " " + secret["username"] + ":" + secret["password"])
            policies[hop] = (
                hop + " none"
                if local_capture
                else hop + " secure match=" + profile["host"] + " servername=" + profile["host"]
            )
            rewrites.append(alias + " " + profile["sender"])
        write("sender-relays", "\n".join(relays) + "\n")
        write("sasl-passwd", "\n".join(auth) + "\n", True)
        write("tls-policy", "\n".join(policies.values()) + "\n")
        write("sender-rewrites", "\n".join(rewrites) + "\n")
        native(
            [
                "postconf",
                "-e",
                "sender_dependent_relayhost_maps = texthash:/run/postfix/sender-relays",
            ]
        )
        native(["postconf", "-e", "smtp_sender_dependent_authentication = yes"])
        native(["postconf", "-e", "smtp_generic_maps = texthash:/run/postfix/sender-rewrites"])
        # A removed personal route must never silently fall back to another user's SMTP.
        native(["postconf", "-e", "relayhost = [127.0.0.1]:1"])
    fingerprints = []
    classes = []
    declarations = []
    senders = set()
    for i, client in enumerate(value["clients"]):
        if not client["enabled"]:
            continue
        fp = client["fingerprint"].upper()
        name = "sender_policy_" + str(i)
        fingerprints.append(fp + " " + client["name"])
        classes.append(fp + " " + name)
        write(
            "senders_" + str(i), "\n".join(address + " OK" for address in client["senders"]) + "\n"
        )
        senders.update(client["senders"])
        declarations.append(
            name + " = check_sender_access texthash:/run/postfix/senders_" + str(i) + ", reject"
        )
    write("client-certificates", "\n".join(fingerprints) + "\n")
    write("client-senders", "\n".join(classes) + "\n")
    write("recipients", "\n".join(address + " OK" for address in value["recipients"]) + "\n")
    pattern = "|".join(re.escape(address) for address in sorted(senders)) or "NEVER_MATCH"
    write(
        "header-checks",
        "/^From:[ \\t]*<?(" + pattern + ")>?[ \\t]*$/ DUNNO\n"
        "/^From:/ REJECT unapproved header sender\n"
        "/^(Sender|Reply-To|Resent-From|Resent-Sender):/ REJECT unsupported identity header\n",
    )
    additions = [
        "smtpd_restriction_classes = "
        + ", ".join(
            "sender_policy_" + str(i) for i, c in enumerate(value["clients"]) if c["enabled"]
        ),
        *declarations,
    ]
    for key, setting in value["settings"].items():
        suffix = "s" if key.endswith(("_time", "_delay", "_lifetime")) else ""
        additions.append(key + " = " + str(setting) + suffix)
    main = Path("/etc/postfix/main.cf")
    replaced = {line.partition("=")[0].strip() for line in additions}
    original = [
        line
        for line in main.read_text().splitlines()
        if line.partition("=")[0].strip() not in replaced
    ]
    main.write_text("\n".join(original + additions) + "\n")
    # Initialize only native queue directories; never clear/recreate queued message files.
    for name in (
        "active",
        "bounce",
        "corrupt",
        "defer",
        "deferred",
        "flush",
        "hold",
        "incoming",
        "private",
        "saved",
        "trace",
        "health",
    ):
        path = QUEUE / name
        path.mkdir(exist_ok=True)
        os.chown(path, account.pw_uid, account.pw_gid)
        path.chmod(0o700)
    data = Path("/var/lib/postfix")
    os.chown(data, account.pw_uid, account.pw_gid)
    data.chmod(0o700)
    native(["postfix", "check"])
    return dict(value)


def health() -> bool:
    try:
        native(["postfix", "status"])
        if not any(p.read_text().strip() == "qmgr" for p in Path("/proc").glob("[0-9]*/comm")):
            return False
        for path in ("public/pickup", "private/rewrite", "public/postlog"):
            if not stat.S_ISSOCK((QUEUE / path).stat().st_mode):
                return False
        minimum = int(native(["postconf", "-h", "queue_minfree"]).strip())
        stats = os.statvfs(QUEUE)
        if stats.f_bavail * stats.f_frsize < minimum:
            return False
        pid = os.fork()
        if pid == 0:
            try:
                account = pwd.getpwnam("postfix")
                os.setgroups([])
                os.setgid(account.pw_gid)
                os.setuid(account.pw_uid)
                if not os.access(QUEUE / "incoming", os.W_OK | os.X_OK):
                    os._exit(1)
                probe = QUEUE / "health" / ("probe-" + uuid.uuid4().hex)
                fd = os.open(probe, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                os.write(fd, b"health")
                os.fsync(fd)
                os.close(fd)
                probe.unlink()
                os._exit(0)
            except BaseException:
                os._exit(1)
        return os.waitpid(pid, 0)[1] == 0
    except (OSError, subprocess.SubprocessError, ValueError):
        return False


def event(line: str) -> dict[str, Any]:
    """Raw SMTP responses, envelopes, IDs/headers supplied by callers never reach stdout."""
    component = re.search(r"(?:cve-postfix|postfix)/([a-z0-9_-]+)\[", line)
    queue = re.search(r"\]: ([A-F0-9]{5,32}):", line)
    status = re.search(r"\bstatus=(sent|deferred|bounced|expired)\b", line)
    severity = "error" if re.search(r"\b(fatal|panic):", line) else "info"
    result = {
        "time": datetime.datetime.now(datetime.UTC).isoformat(),
        "component": component.group(1) if component else "postfix",
        "event": status.group(1)
        if status
        else ("rejected" if "NOQUEUE: reject:" in line else "diagnostic"),
        "severity": severity,
    }
    dsn = re.search(r"\bdsn=([245]\.[0-9]{1,3}\.[0-9]{1,3})\b", line)
    if dsn:
        result["dsn"] = dsn.group(1)
    for category, tokens in {
        "configuration": ("fatal:", "panic:"),
        "capacity": ("insufficient disk space", "queue file write error"),
        "authentication": ("SASL authentication failed",),
        "certificate": ("certificate verification failed", "Server certificate not trusted"),
        "connection": ("Connection timed out", "Connection refused", "lost connection"),
    }.items():
        if any(token in line for token in tokens):
            result["reason"] = category
            break
    if queue:
        result["queue_id"] = queue.group(1)
    if "TLS connection established" in line:
        result["event"] = "tls_established"
    return result


def run() -> int:
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))
    signal.signal(signal.SIGINT, lambda *_: sys.exit(0))
    configure()
    boot = str(uuid.uuid4())
    (RUN / "boot").write_text(boot)
    namespace = os.readlink("/proc/self/ns/net")
    digest = hashlib.sha256((SOURCE / "policy.json").read_bytes()).hexdigest()
    while (
        not (SOURCE / "network.ready").is_file()
        or (SOURCE / "network.ready").read_text().strip() != namespace + " " + boot + " " + digest
    ):
        time.sleep(0.2)
    # Listen only on the intended internal interface; operator fixes address before releasing gate.
    address = (SOURCE / "listen-address").read_text().strip()
    native(["postconf", "-e", "inet_interfaces = " + address])
    # Return to the upstream init script: its supervisor starts native Postfix.
    return 0


if __name__ == "__main__":
    try:
        sys.exit(0 if health() else 1) if len(sys.argv) > 1 and sys.argv[
            1
        ] == "health" else sys.exit(run())
    except Exception as error:
        print(
            json.dumps({"component": "bootstrap", "event": "failed", "code": type(error).__name__}),
            flush=True,
        )
        sys.exit(1)
