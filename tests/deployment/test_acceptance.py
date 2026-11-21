"""The acceptance gate must reject missing, failed, skipped and incomplete evidence."""

from pathlib import Path

import pytest

from scripts.deployment import acceptance
from scripts.deployment.contracts import read


@pytest.mark.parametrize(
    "body",
    [
        "<testsuite><testcase><failure/></testcase></testsuite>",
        "<testsuite><testcase><error/></testcase></testsuite>",
        "<testsuite><testcase><skipped/></testcase></testsuite>",
        "<testsuite/>",
    ],
)
def test_junit_evidence_is_fail_closed(tmp_path: Path, body: str) -> None:
    path = tmp_path / "tests.xml"
    path.write_text(body)
    with pytest.raises(ValueError):
        acceptance.junit(path, 1)


def test_acceptance_cannot_succeed_without_native_evidence(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(acceptance, "REPORTS", tmp_path)
    with pytest.raises(SystemExit) as result:
        acceptance.main()
    assert result.value.code == 1
    value = read(tmp_path / "phase-24-acceptance.json")
    assert value["technical_staging_accepted"] is False
    assert value["production_release"] is False
    assert value["accepted"] is False
