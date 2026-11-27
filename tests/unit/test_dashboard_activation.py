"""A failed config/reload keeps the old HTML; assets survive only a finite release window."""

from pathlib import Path
from typing import Any

import pytest

from scripts.dashboard import manage
from scripts.infrastructure.manage import Config


@pytest.mark.parametrize("failure", ["check", "reload", None])
def test_dashboard_activation_is_reversible_and_bounds_old_assets(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, failure: str | None
) -> None:
    config = Config(
        tmp_path, {"COMPOSE_PROJECT_NAME": "cve-test-dashboard", "APP_ENV": "development"}
    )
    target = config.directory / "dashboard"
    (target / "assets").mkdir(parents=True)
    (target / "index.html").write_text("old")
    (target / "assets/old.js").write_text("old")
    snippets = config.directory / "snippets"
    snippets.mkdir()
    (snippets / "dashboard-static-routes.conf").write_text("old-config")
    source = tmp_path / "services/dashboard/dist"
    (source / "assets").mkdir(parents=True)
    monkeypatch.setattr(manage, "render", lambda _: None)

    def compose(_config: Config, args: list[str]) -> Any:
        if (failure == "check" and args[-1] == "-t") or (
            failure == "reload" and args[-1] == "reload"
        ):
            raise ValueError("fixture config failure")

    monkeypatch.setattr(manage, "compose", compose)
    (source / "index.html").write_text("new")
    (source / "assets/new.js").write_text("new")
    if failure:
        with pytest.raises(ValueError, match="fixture"):
            manage.activate(config)
        assert (target / "index.html").read_text() == "old"
        assert (target / "assets/old.js").read_text() == "old"
        assert (snippets / "dashboard-static-routes.conf").read_text() == "old-config"
        return
    manage.activate(config)
    assert (target / "index.html").read_text() == "new"
    assert (target / "assets/old.js").is_file()
    for index in range(5):
        for path in (source / "assets").iterdir():
            path.unlink()
        (source / "assets" / f"{index}.js").write_text(str(index))
        manage.activate(config)
    assert len(list((config.directory / "dashboard-releases").iterdir())) == 3
    assert {path.name for path in (target / "assets").iterdir()} == {"2.js", "3.js", "4.js"}
