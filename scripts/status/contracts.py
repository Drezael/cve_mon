"""Export actual status routes and strict versioned data contracts."""

import json
from pathlib import Path

from cve_api.status.models import EntityRead, IncidentRead, Maintenance, Observation
from cve_api.status.router import router
from fastapi import FastAPI
from pydantic import BaseModel


def main() -> None:
    root = Path(__file__).resolve().parents[2]
    folder = root / "contracts/status"
    folder.mkdir(parents=True, exist_ok=True)
    models: list[tuple[str, type[BaseModel]]] = [
        ("service-check", Observation),
        ("service-status", EntityRead),
        ("pipeline-status", EntityRead),
        ("incident", IncidentRead),
        ("maintenance", Maintenance),
    ]
    for name, model in models:
        (folder / (name + ".schema.json")).write_text(
            json.dumps(model.model_json_schema(), indent=2) + "\n"
        )
    app = FastAPI(title="CVE internal status API", version="0.22.0")
    app.include_router(router)
    (root / "contracts/api/status.openapi.json").write_text(
        json.dumps(app.openapi(), indent=2) + "\n"
    )


if __name__ == "__main__":
    main()
