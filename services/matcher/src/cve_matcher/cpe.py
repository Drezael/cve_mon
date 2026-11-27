"""CPE 2.3 bounded names and three-valued applicability expressions.

Unknown target attributes never satisfy a specific predicate. No generated CPEs;
version bounds require a comparator explicitly supplied by inventory identity.
"""

import re
from typing import Any

from cve_matcher.limits import cpe_leaves
from cve_matcher.versions import VersionError, compare

Truth = bool | None


def parts(name: str) -> list[str]:
    if not isinstance(name, str) or len(name) > 2048 or not name.startswith("cpe:2.3:"):
        raise ValueError("invalid_cpe")
    fields = re.split(r"(?<!\\):", name[8:])
    if len(fields) != 11 or any(not f for f in fields):
        raise ValueError("invalid_cpe")
    return fields


def attribute(source: str, target: str) -> Truth:
    if source == "*":
        return True
    if target == "*":
        return None
    if source == "-" or target == "-":
        return source == target
    # Tokenize wildcards, then use a bounded dynamic program, never a regex
    # constructed from source patterns (which could cause catastrophic backtracking).
    tokens: list[tuple[str, str]] = []
    escape = False
    for ch in source:
        if escape:
            tokens.append(("literal", ch.casefold()))
            escape = False
        elif ch == "\\":
            escape = True
        else:
            tokens.append((ch if ch in {"*", "?"} else "literal", ch.casefold()))
    if escape:
        raise ValueError("invalid_cpe")
    literal = re.sub(r"\\(.)", r"\1", target).casefold()
    previous = [True] + [False] * len(literal)
    for kind, ch in tokens:
        current = [previous[0] if kind == "*" else False]
        for index, char in enumerate(literal, 1):
            current.append(
                (previous[index] or current[-1])
                if kind == "*"
                else previous[index - 1] and (kind == "?" or ch == char)
            )
        previous = current
    return previous[-1]


def conjunction(values: list[Truth]) -> Truth:
    return False if False in values else None if None in values or not values else True


def disjunction(values: list[Truth]) -> Truth:
    return True if True in values else None if None in values or not values else False


def criterion(
    value: dict[str, Any],
    identities: list[dict[str, Any]],
    complete: bool,
    budget: list[int] | None = None,
) -> Truth:
    source = parts(value.get("criteria", ""))
    outcomes: list[Truth] = []
    for identity in identities:
        target = parts(identity.get("cpe", ""))
        if budget is not None:
            budget[0] -= max(
                1, sum(len(a) * len(b) for a, b in zip(source, target, strict=True)) // 16
            )
            if budget[0] < 0:
                return None
        base = conjunction([attribute(s, t) for s, t in zip(source, target, strict=True)])
        if base is False:
            outcomes.append(False)
            continue
        bounds: list[Truth] = [base]
        for key, direction, inclusive in [
            ("versionStartIncluding", 1, True),
            ("versionStartExcluding", 1, False),
            ("versionEndIncluding", -1, True),
            ("versionEndExcluding", -1, False),
        ]:
            if key not in value:
                continue
            if target[3] in {"*", "-"} or not identity.get("adapter"):
                bounds.append(None)
                continue
            try:
                d = compare(identity["adapter"], target[3], value[key]) * direction
                bounds.append(d >= 0 if inclusive else d > 0)
            except VersionError:
                bounds.append(None)
        outcomes.append(conjunction(bounds))
    if True in outcomes:
        return True
    if None in outcomes or not complete:
        return None
    return False


def configuration(
    tree: dict[str, Any],
    identities: list[dict[str, Any]],
    complete: bool = False,
    *,
    depth: int = 0,
    budget: list[int] | None = None,
) -> tuple[Truth, bool]:
    """Return applicability AND whether a vulnerable leaf is proven present.

    A true environmental-only expression cannot establish vulnerability. The
    original expression is retained by the caller in provenance/evidence.
    """
    if budget is None:
        cpe_leaves(tree)
        budget = [4096]
    budget[0] -= 1
    if depth > 32 or budget[0] < 0:
        return None, False
    op = tree.get("operator", "OR")
    children = tree.get("nodes", tree.get("children", []))
    leaves = tree.get("cpeMatch", [])
    if op not in {"AND", "OR"} or not isinstance(children, list) or not isinstance(leaves, list):
        return None, False
    if len(children) + len(leaves) > 4096:
        return None, False
    values: list[Truth] = []
    vulnerable = False
    try:
        for leaf in leaves:
            budget[0] -= 1
            if budget[0] < 0 or not isinstance(leaf, dict):
                return None, False
            truth = criterion(leaf, identities, complete, budget)
            values.append(truth)
            vulnerable |= truth is True and leaf.get("vulnerable") is True
        for child in children:
            if not isinstance(child, dict):
                return None, False
            truth, proven = configuration(
                child, identities, complete, depth=depth + 1, budget=budget
            )
            values.append(truth)
            vulnerable |= truth is True and proven
    except (ValueError, TypeError):
        return None, False
    truth = conjunction(values) if op == "AND" else disjunction(values)
    if tree.get("negate") is True:
        truth = None if truth is None else not truth
        vulnerable = False  # negation never proves installation of a vulnerable product
    return truth, vulnerable and truth is True
