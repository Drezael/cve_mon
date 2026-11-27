"""Shared fail-closed expression budgets."""

from typing import Any


class EvaluationLimit(ValueError):
    """The worker must fail rather than publish partial evidence or indices."""


MAX_DEPTH = 32
MAX_NODES = 4096


def cpe_leaves(value: object) -> list[dict[str, Any]]:
    """Lists wrap logical nodes without consuming another logical depth level."""
    stack = [(value, 0)]
    leaves: list[dict[str, Any]] = []
    remaining = MAX_NODES
    while stack:
        node, depth = stack.pop()
        if isinstance(node, list):
            if len(node) > MAX_NODES:
                raise EvaluationLimit("expression_limit")
            stack.extend((child, depth) for child in node)
            continue
        remaining -= 1
        if depth > MAX_DEPTH or remaining < 0:
            raise EvaluationLimit("expression_limit")
        if not isinstance(node, dict):
            continue
        matches = node.get("cpeMatch", [])
        if not isinstance(matches, list) or len(matches) > remaining:
            raise EvaluationLimit("expression_limit")
        remaining -= len(matches)
        leaves.extend(leaf for leaf in matches if isinstance(leaf, dict))
        stack.append((node.get("nodes", node.get("children", [])), depth + 1))
    return leaves
