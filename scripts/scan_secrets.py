"""Prüfe alle relevanten Repositorydateien, ohne die Baseline zu verändern."""

import argparse
import json
import subprocess
import sys
import tempfile
from pathlib import Path

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from scripts.repository_files import repository_files

ROOT = Path(__file__).resolve().parents[1]


def scan(root: Path) -> int:
    """Nutze detect-secrets-hook als Fehlerprüfung, nicht scan als Baseline-Update."""
    baseline_path = root / "configuration/quality/secrets.baseline"
    baseline_text = baseline_path.read_text(encoding="utf-8")
    baseline = json.loads(baseline_text)
    if not isinstance(baseline, dict) or not isinstance(baseline.get("results"), dict):
        raise ValueError("Ungültige Secret-Baseline")
    for findings in baseline["results"].values():
        if not isinstance(findings, list):
            raise ValueError("Ungültige Baseline-Fundliste")
        for finding in findings:
            if not isinstance(finding, dict) or finding.get("is_verified") is not False:
                raise ValueError("Baseline enthält ungeprüfte oder bestätigte Secrets.")
    files = [str(path.relative_to(root)) for path in repository_files(root)]
    status = 0
    hook = Path(sys.executable).parent / "detect-secrets-hook"
    # Der Hook kann selbst Zeilennummern/Versionen aktualisieren. Nur eine temporäre
    # Kopie übergeben, damit die versionierte Baseline auch dabei unverändert bleibt.
    with tempfile.TemporaryDirectory(prefix="cve-secret-check-") as directory:
        temporary_baseline = Path(directory) / ".secrets.baseline"
        temporary_baseline.write_text(baseline_text, encoding="utf-8")
        for offset in range(0, len(files), 100):
            result = subprocess.run(
                [
                    str(hook),
                    "--no-verify",
                    # A standalone JSON SHA256 field is public artifact metadata.
                    # Other fields and lines, including adjacent credentials, remain scanned.
                    "--exclude-lines",
                    r'^\s*"sha256": "[a-f0-9]{64}",?$',
                    "--baseline",
                    str(temporary_baseline),
                    *files[offset : offset + 100],
                ],
                cwd=root,
                check=False,
            )
            if result.returncode:
                status = 1
    if status == 0:
        print(f"Secret-Prüfung erfolgreich: {len(files)} Dateien; Baseline unverändert.")
    return status


def main() -> int:
    """Biete denselben lokalen und CI-Einstiegspunkt."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=ROOT)
    args = parser.parse_args()
    try:
        return scan(args.root.resolve())
    except (OSError, ValueError, KeyError, TypeError, subprocess.CalledProcessError) as exc:
        print(f"Secret-Prüfung fehlgeschlagen: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
