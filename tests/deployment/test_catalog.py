"""DDL cast normalization must never hide changed predicates, constraints or ownership."""

import pytest

from scripts.database.catalog import equivalent, text_arrays

A = (
    "CHECK (((status)::text = ANY ((ARRAY['running'::character varying, "
    "'in_progress'::character varying])::text[])))"
)
B = (
    "CHECK (((status)::text = ANY (ARRAY[('running'::character varying)::text, "
    "('in_progress'::character varying)::text])))"
)


def test_postgres_reparse_distributes_only_lossless_literal_casts() -> None:
    assert text_arrays(A) == text_arrays(B)
    assert text_arrays(A) == text_arrays(text_arrays(A))
    actual = {"constraints": [{"nspname": "public", "definition": A}], "owner": "n8n_app"}
    expected = {"constraints": [{"nspname": "public", "definition": B}], "owner": "n8n_app"}
    assert equivalent("n8n", actual, expected)
    assert not equivalent("cve_monitoring", actual, expected)


@pytest.mark.parametrize(
    "changed",
    [
        B.replace("'running'", "'failed'"),
        B.replace(" = ANY", " <> ALL"),
        B.replace("character varying", "character varying(2)"),
    ],
)
def test_different_constraints_are_never_equivalent(changed: str) -> None:
    assert not equivalent(
        "n8n",
        {"constraints": [{"nspname": "public", "definition": A}]},
        {"constraints": [{"nspname": "public", "definition": changed}]},
    )


def test_ownership_and_permissions_remain_exact() -> None:
    a = {
        "constraints": [{"nspname": "public", "definition": A}],
        "owner": "n8n_app",
        "acl": "private",
    }
    for field, value in [("owner", "postgres_admin"), ("acl", "PUBLIC=ALL")]:
        b = {**a, field: value}
        assert not equivalent("n8n", a, b)


def test_literals_with_quotes_and_commas_preserve_their_value() -> None:
    original = "(ARRAY['a,b'::character varying, 'it''s'::character varying])::text[]"
    assert text_arrays(original) == "ARRAY['a,b'::text, 'it''s'::text]"


def test_cast_like_text_inside_sql_literals_and_identifiers_is_preserved() -> None:
    for definition in ["'" + A.replace("'", "''") + "'", '"' + A + '"']:
        assert text_arrays(definition) == definition
