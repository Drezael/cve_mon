"""No Node runtime service: verified local toolchain, build assets, Nginx-only serving."""

import argparse
import contextlib
import fcntl
import hashlib
import json
import os
import platform
import shutil
import subprocess
import tarfile
import tempfile
import time
import tomllib
import urllib.request
from pathlib import Path

from scripts.infrastructure.manage import Config, compose, load_config, render


def node(root: Path) -> Path:
    if platform.system() != "Linux" or platform.machine() not in {"x86_64", "amd64"}:
        raise ValueError(
            "Dashboard builds require Linux x86_64; use make dashboard-check on a supported host"
        )
    tool = tomllib.loads((root / "services/dashboard/toolchain.toml").read_text())
    directory = root / ".runtime/node"
    directory.mkdir(parents=True, exist_ok=True)
    binary = directory / str(tool["directory"]) / "bin"
    archive = directory / "node-verified.tar.xz"
    with (directory / "install.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        if not archive.is_file():
            pending = archive.with_suffix(".pending")
            try:
                with (
                    urllib.request.urlopen(tool["url"], timeout=30) as source,
                    pending.open("wb") as output,
                ):
                    shutil.copyfileobj(source, output)
                pending.replace(archive)
            finally:
                pending.unlink(missing_ok=True)
        if (
            archive.is_symlink()
            or hashlib.sha256(archive.read_bytes()).hexdigest() != tool["sha256"]
        ):
            raise ValueError("Node SHA256 differs from pinned official release")
        with tarfile.open(archive) as bundle:
            if not (binary / "node").is_file():
                bundle.extractall(directory, filter="data")
            for name in ("bin/node", "bin/npm", "lib/node_modules/npm/bin/npm-cli.js"):
                path = directory / str(tool["directory"]) / name
                member = bundle.extractfile(str(tool["directory"]) + "/" + name)
                if (
                    member is None
                    or hashlib.sha256(member.read()).digest()
                    != hashlib.sha256(path.read_bytes()).digest()
                ):
                    raise ValueError("Installed Node/npm differs from verified distribution")
    version = subprocess.run(
        [str(binary / "node"), "--version"], check=True, capture_output=True, text=True, timeout=10
    ).stdout.strip()
    if version != str(tool["version"]).removeprefix("node-"):
        raise ValueError("Installed Node version differs from the pinned toolchain")
    return binary


def npm(root: Path, *args: str) -> None:
    from scripts.dashboard import provenance

    building = args == ("run", "build")
    before = provenance.inputs(root) if building else {}
    if building:
        (root / ".runtime/dashboard-build.json").unlink(missing_ok=True)
    binary = node(root)
    env = dict(os.environ, PATH=str(binary) + os.pathsep + os.environ.get("PATH", ""))
    subprocess.run(
        [str(binary / "npm"), "--prefix", str(root / "services/dashboard"), *args],
        cwd=root,
        env=env,
        check=True,
    )
    if building:
        provenance.record(root, before)


def render_static(config: Config, *, available: bool | None = None) -> None:
    target = config.directory / "snippets/dashboard-static-routes.conf"
    dist = config.directory / "dashboard"
    if available is False or (available is None and not (dist / "index.html").is_file()):
        target.write_text(
            "location = / { root /etc/nginx/cve/empty; "
            "try_files /__backend_absent__ =503; }\nlocation / { return 404; }\n"
        )
        return
    headers = (
        "add_header Strict-Transport-Security '"
        + ("max-age=31536000" if config.values["APP_ENV"] == "production" else "")
        + "' always;\n"
        "add_header X-Content-Type-Options nosniff always;\n"
        "add_header Referrer-Policy same-origin always;\n"
        "add_header X-Frame-Options DENY always;\n"
        "add_header Content-Security-Policy \"default-src 'none'; script-src 'self'; "
        "style-src 'self'; img-src 'self'; font-src 'self'; connect-src 'self'; "
        "frame-ancestors 'none'; base-uri 'none'; form-action 'self'; object-src 'none'\" always;\n"
        "add_header X-Request-ID $request_id always;\n"
    )
    target.write_text(
        "location /api/ { return 404; }\nlocation /internal/ { return 404; }\n"
        "location ^~ /assets/ { root /etc/nginx/cve/dashboard; try_files $uri =404;\n"
        "gzip on; gzip_vary on; gzip_min_length 1024; gzip_types text/css application/javascript;\n"
        + headers
        + "add_header Cache-Control 'public, max-age=31536000, immutable'; }\n"
        "location = /index.html { root /etc/nginx/cve/dashboard; try_files $uri =503;\n"
        + headers
        + (
            "add_header Cache-Control no-store always; }\nlocati"
            "on = / { rewrite ^ /index.html last; }\nlocation /a"
            "dministration { rewrite ^ /index.html last; }\nloca"
            "tion /status { rewrite ^ /index.html last; }\nlocat"
            'ion ~ "^/(dashboard|dashboards|login|activate|mfa|servers|gro'
            'ups|findings|notifications|status|settings)(/[^/]+)*/?$" { re'
            "write ^ /index.html last; }\nlocation / { return 40"
            "4; }\n"
        )
    )


def activate(config: Config) -> None:
    source = config.root / "services/dashboard/dist"
    if not (source / "index.html").is_file():
        raise ValueError("Build the dashboard before activation")
    config.directory.mkdir(parents=True, exist_ok=True)
    with (config.directory / "dashboard-activation.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        _activate(config, source)


def _activate(config: Config, source: Path) -> None:
    target = config.directory / "dashboard"
    releases = config.directory / "dashboard-releases"
    releases.mkdir(exist_ok=True)
    previous = sorted(
        (p for p in releases.iterdir() if p.is_dir()), key=lambda p: p.stat().st_mtime, reverse=True
    )[:2]
    if target.is_dir() and not target.is_symlink():
        previous = [target, *previous][:2]
    release = Path(tempfile.mkdtemp(prefix="release-", dir=releases))
    release.chmod(0o755)
    snippet = config.directory / "snippets/dashboard-static-routes.conf"
    old_snippet = snippet.read_bytes() if snippet.exists() else None
    old_target = target.resolve() if target.is_symlink() else None
    pointer = config.directory / "dashboard.next"
    switched = False
    try:
        shutil.copytree(source, release, dirs_exist_ok=True)
        own_assets = [
            str(p.relative_to(source)) for p in (source / "assets").rglob("*") if p.is_file()
        ]
        (release / "assets.json").write_text(json.dumps(own_assets))
        for retained in previous:
            manifest = retained / "assets.json"
            retained_assets = (
                json.loads(manifest.read_text())
                if manifest.exists()
                else [
                    str(p.relative_to(retained))
                    for p in (retained / "assets").rglob("*")
                    if p.is_file()
                ]
            )
            for name in retained_assets:
                asset = Path(name)
                if asset.is_absolute() or ".." in asset.parts or asset.parts[0] != "assets":
                    raise ValueError("Invalid release asset manifest")
                dest = release / asset
                dest.parent.mkdir(parents=True, exist_ok=True)
                if not dest.exists():
                    shutil.copyfile(retained / asset, dest)
        # Validate the actual configuration before making any new HTML visible.
        render(config)
        render_static(config, available=True)
        compose(config, ["exec", "-T", "cve-nginx", "nginx", "-t"])
        if target.exists() and not target.is_symlink():
            old_target = releases / ("legacy-" + str(time.time_ns()))
            target.rename(old_target)
            previous = [old_target if p == target else p for p in previous]
        pointer.unlink(missing_ok=True)
        pointer.symlink_to(release.relative_to(config.directory), target_is_directory=True)
        pointer.replace(target)
        switched = True
        compose(config, ["exec", "-T", "cve-nginx", "nginx", "-s", "reload"])
    except BaseException:
        if switched or (old_target is not None and not target.exists()):
            if old_target is not None:
                pointer.symlink_to(
                    old_target.relative_to(config.directory), target_is_directory=True
                )
                pointer.replace(target)
            else:
                target.unlink(missing_ok=True)
        if old_snippet is not None:
            snippet.write_bytes(old_snippet)
        else:
            snippet.unlink(missing_ok=True)
        shutil.rmtree(release)
        with contextlib.suppress(Exception):
            compose(config, ["exec", "-T", "cve-nginx", "nginx", "-s", "reload"])
        raise
    finally:
        pointer.unlink(missing_ok=True)
    # Each release contains only the preceding two releases' original assets.
    keep = {release, *previous}
    for retired in releases.iterdir():
        if retired.is_dir() and retired not in keep:
            shutil.rmtree(retired)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=["build", "test", "check", "activate"])
    args = parser.parse_args()
    config = load_config()
    if args.action == "activate":
        activate(config)
        return
    npm(config.root, "ci", "--ignore-scripts")
    commands = {
        ("build"): [("build")],
        ("test"): [("test")],
        ("check"): [("typecheck"), ("lint"), ("test"), ("build")],
    }
    for command in commands[args.action]:
        npm(config.root, "run", command)


if __name__ == "__main__":
    main()
