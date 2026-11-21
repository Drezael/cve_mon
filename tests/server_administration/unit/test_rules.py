"Hostile administrative inputs, personal memberships and preconditions."

from uuid import uuid4

import pytest
from cve_api.administration.versioning import check, etag, expected
from cve_api.authorization.errors import Denied
from cve_api.groups.personal import GroupWrite, MembershipWrite
from cve_api.groups.schemas import GroupCreate, Ordering
from cve_api.servers.schemas import ServerCreate, ServerPatch
from pydantic import ValidationError


@pytest.mark.parametrize(
    "field",
    [
        "id",
        "server_uuid",
        "primary_group_id",
        "group_ids",
        "display_order",
        "sort_order",
        "packages",
        "os",
        "inventory_hostname",
        "inventory_name",
        "roles",
        "acl",
        "status",
        "created_by",
    ],
)
def test_registration_rejects_identity_technical_and_uncontrolled_fields(field: str) -> None:
    with pytest.raises(ValidationError):
        ServerCreate.model_validate(
            {"display_name": "host", "request_id": str(uuid4()), field: "forbidden"}
        )


@pytest.mark.parametrize("value", ["", " ", "<script>", "a\x00b", "a\nb", "a\u202eb", "x" * 129])
def test_invalid_names(value: str) -> None:
    with pytest.raises(ValidationError):
        GroupCreate(name=value)


@pytest.mark.parametrize(
    "body", [{}, {"name": None}, {"status": "archived"}, {"sort_order": 1}, {"group_ids": []}]
)
def test_group_patch_allowlist(body: dict[str, object]) -> None:
    with pytest.raises(ValidationError):
        GroupWrite.model_validate(body)


@pytest.mark.parametrize(
    "body",
    [
        {},
        {"display_name": None},
        {"exposure": None},
        {"criticality": "severe"},
        {"exposure": "public"},
        {"primary_group_id": None},
        {"packages": []},
    ],
)
def test_server_patch_allowlist(body: dict[str, object]) -> None:
    with pytest.raises(ValidationError):
        ServerPatch.model_validate(body)


def test_normalization_and_explicit_nullable_metadata() -> None:
    assert GroupCreate(name="  Ｗｅｂ  ").name == "Web"
    assert ServerPatch(description=None).model_fields_set == {"description"}


def test_memberships_allow_many_groups_without_primary_and_reject_duplicates() -> None:
    a, b = uuid4(), uuid4()
    assert MembershipWrite(group_ids=[], version=0)
    assert MembershipWrite(group_ids=[a, b], version=1)
    for body in [
        {"group_ids": [a, a], "version": 1},
        {"group_ids": [a], "version": -1},
        {"group_ids": [a], "version": 0, "primary_group_id": a},
    ]:
        with pytest.raises(ValidationError):
            MembershipWrite.model_validate(body)


def test_relative_move_and_bounded_complete_order() -> None:
    a = uuid4()
    assert Ordering(move_id=a, before_id=None)
    assert Ordering(ids=[])
    for data in [
        {},
        {"ids": [a, a]},
        {"ids": [], "move_id": a},
        {"move_id": a, "before_id": a},
        {"ids": [uuid4() for _ in range(101)]},
    ]:
        with pytest.raises(ValidationError):
            Ordering.model_validate(data)


@pytest.mark.parametrize(
    "value", [None, "1", "*", 'W/"1"', '"0"', '"-1"', '"1", "2"', '"1000000000000000000"']
)
def test_strong_if_match_rejects_missing_and_ambiguous(value: str | None) -> None:
    with pytest.raises(Denied) as e:
        expected(value)
    assert e.value.status == (428 if value is None else 400)


def test_etag_staleness() -> None:
    assert expected(etag(2)) == 2
    check(2, '"2"')
    with pytest.raises(Denied) as e:
        check(3, '"2"')
    assert e.value.status == 412


@pytest.mark.parametrize("name", [None, 12, "ﬃ" * 64])
def test_normalized_name_length_and_types_are_validated(name: object) -> None:
    with pytest.raises(ValidationError):
        GroupCreate.model_validate({"name": name})
