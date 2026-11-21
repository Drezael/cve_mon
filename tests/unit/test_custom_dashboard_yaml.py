"""YAML is bounded declarative data, including hostile input and schema evolution."""

from pathlib import Path

import pytest
from cve_api.custom_dashboards.schema import parse

EXAMPLE = """# Keep this comment on round trips.
version: 1
title: My board
widgets:
  - id: servers
    type: metric
    title: My servers
    metric: active_servers
"""


def test_example_defaults_and_published_configuration(repository_root: Path) -> None:
    config = parse(EXAMPLE)
    assert config.refresh_interval_seconds == 0
    assert config.layout.columns == 2
    assert config.widgets[0].span == 1
    example = parse(
        (repository_root / "configuration/dashboards/security-overview.yaml").read_text()
    )
    assert {w.type for w in example.widgets} == {
        "metric",
        "distribution",
        "servers",
        "findings",
        "text",
    }


@pytest.mark.parametrize(
    "document",
    [
        "!!python/object/apply:os.system ['touch /tmp/dashboard-injection']",
        "version: 1\ntitle: x\nwidgets: &items [*items]",
        "version: 1\ntitle: x\ntitle: replaced\nwidgets: []",
        EXAMPLE + "---\nversion: 1\n",
        "just text",
        EXAMPLE.replace("title: My board", 'title: "bad\\0title"'),
        EXAMPLE.replace("title: My board", 'title: "bad\\uD800title"'),
        EXAMPLE.replace("version: 1", "version: true"),
        EXAMPLE.replace("version: 1", "version: 2"),
        EXAMPLE.replace("type: metric", "type: sql"),
        EXAMPLE + "query: SELECT * FROM security.users\n",
        EXAMPLE + "owner_id: 00000000-0000-0000-0000-000000000000\n",
        EXAMPLE + "refresh_interval_seconds: 1\n",
        EXAMPLE + "refresh_interval_seconds: true\n",
        EXAMPLE.replace("metric: active_servers", "metric: password_hash"),
        EXAMPLE.replace(
            "metric: active_servers", "metric: active_servers\n    url: https://example.test"
        ),
        EXAMPLE.replace("metric: active_servers", "metric: active_servers\n    span: 3"),
        EXAMPLE.replace("metric: active_servers", "metric: active_servers\n    span: true"),
        EXAMPLE + "widgets: []\n",
        "x" * 32769,
        "version: 1\n" + "a: [" * 20 + "0" + "]" * 20,
        "version: 1\ntitle: test\nwidgets: []\n<<: {title: bypass}",
    ],
)
def test_rejects_executable_ambiguous_or_unbounded_yaml(document: str) -> None:
    with pytest.raises(ValueError):
        parse(document)


def test_widget_ids_are_unique_and_lists_and_filters_are_bounded() -> None:
    duplicate = EXAMPLE + "  - id: servers\n    type: text\n    title: Notes\n    text: Hello\n"
    with pytest.raises(ValueError, match="unique"):
        parse(duplicate)
    with pytest.raises(ValueError):
        parse(
            EXAMPLE.replace(
                "type: metric\n    title: My servers\n    metric: active_servers",
                "type: servers\n    title: Test\n    limit: 51",
            )
        )
    text = parse(
        EXAMPLE.replace(
            "type: metric\n    title: My servers\n    metric: active_servers",
            "type: text\n    title: Notes\n    text: '<script>alert(1)</script>'",
        )
    )
    assert text.widgets[0].type == "text"
