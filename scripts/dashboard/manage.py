"""No Node runtime service: verified local toolchain, build assets, Nginx-only serving."""

import argparse
import hashlib
import os
import shutil
import subprocess
import tarfile
import tomllib
import urllib.request
from pathlib import Path

from scripts.infrastructure.manage import Config, compose, load_config, render


def node(root: Path) -> Path:
    tool = tomllib.loads((root / "services/dashboard/toolchain.toml").read_text())
    directory = root / ".runtime/node"
    binary = directory / str(tool["directory"]) / "bin"
    if not (binary / "node").is_file():
        directory.mkdir(parents=True, exist_ok=True)
        archive = directory / "node-verified.tar.xz"
        urllib.request.urlretrieve(tool["url"], archive)
        if hashlib.sha256(archive.read_bytes()).hexdigest() != tool["sha256"]:
            archive.unlink()
            raise ValueError("Node SHA256 differs from pinned official release")
        with tarfile.open(archive) as bundle:
            bundle.extractall(directory, filter="data")
        archive.unlink()
    return binary


def npm(root: Path, *args: str) -> None:
    binary = node(root)
    env = dict(os.environ, PATH=str(binary) + os.pathsep + os.environ.get("PATH", ""))
    subprocess.run(
        [str(binary / "npm"), "--prefix", str(root / "services/dashboard"), *args],
        cwd=root,
        env=env,
        check=True,
    )


def render_static(config: Config) -> None:
    target = config.directory / "snippets/dashboard-static-routes.conf"
    dist = config.directory / "dashboard"
    if not (dist / "index.html").is_file():
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
    target = config.directory / "dashboard"
    # Retain previous hashed chunks so open tabs survive an atomic HTML replacement.
    shutil.copytree(source / "assets", target / "assets", dirs_exist_ok=True)
    temporary = target / "index.html.new"
    shutil.copyfile(source / "index.html", temporary)
    temporary.replace(target / "index.html")
    render(config)
    compose(config, ["exec", "-T", "cve-nginx", "nginx", "-t"])
    compose(config, ["exec", "-T", "cve-nginx", "nginx", "-s", "reload"])


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
