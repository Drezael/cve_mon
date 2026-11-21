"""Audit Git's publication inputs without staging, committing or contacting GitHub."""

from pathlib import Path

from scripts.repository_files import repository_files

ROOT = Path(__file__).resolve().parents[1]
ROOT_FILES = {
    ".editorconfig",
    ".env.example",
    ".gitattributes",
    ".gitignore",
    "LICENSE",
    "Makefile",
    "README.md",
    "compose.yml",
    "cve_mon",
    "pyproject.toml",
}
ROOT_DIRECTORIES = {
    ".github",
    "configuration",
    "contracts",
    "database",
    "docs",
    "examples",
    "infrastructure",
    "integrations",
    "packages",
    "requirements",
    "scripts",
    "services",
    "tests",
    "workflows",
}
PRIVATE_NAMES = {".env", "credentials.json", "credentials-import.json", "agent-config.json"}
PRIVATE_SUFFIXES = {".key", ".pem", ".crt", ".p12", ".pfx", ".dump", ".backup"}


def private_development_plan(relative: Path) -> bool:
    return relative.is_relative_to("docs/history/plans") or relative.match(
        "docs/development/phase-*-plan.md"
    )


def publication_issues(root: Path) -> list[str]:
    errors = []
    for path in repository_files(root):
        relative = path.relative_to(root)
        if private_development_plan(relative):
            errors.append(
                "Privater Entwicklungsplan in der Git-Dateiauswahl: " + relative.as_posix()
            )
        if len(relative.parts) == 1:
            if relative.name not in ROOT_FILES:
                errors.append("Unerwartete Datei im Repo-Root: " + relative.as_posix())
        elif relative.parts[0] not in ROOT_DIRECTORIES:
            errors.append("Lokales oder unbekanntes Verzeichnis: " + relative.parts[0])
        if (
            path.name in PRIVATE_NAMES
            or path.name.startswith(".env.")
            and path.name != ".env.example"
            or path.suffix in PRIVATE_SUFFIXES
        ):
            errors.append("Private Datei in der Git-Dateiauswahl: " + relative.as_posix())
        if path.stat().st_size >= 100 * 1024 * 1024:
            errors.append("Datei überschreitet das GitHub-Dateilimit: " + relative.as_posix())
    for name in ("LICENSE", "README.md", ".github/SECURITY.md", ".github/CONTRIBUTING.md"):
        if not (root / name).is_file():
            errors.append("GitHub-Projektdatei fehlt: " + name)
    return errors


def main() -> int:
    errors = publication_issues(ROOT)
    if errors:
        print("\n".join(errors))
        return 1
    files = repository_files(ROOT)
    size = sum(path.stat().st_size for path in files)
    print(f"GitHub-Dateiauswahl OK: {len(files)} Dateien, {size / (1024 * 1024):.1f} MiB.")
    print("Lokale Konfiguration, Laufzeitdaten, Sicherungen und Tool-Caches sind ausgeschlossen.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
