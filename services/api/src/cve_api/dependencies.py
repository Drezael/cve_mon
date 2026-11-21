"""Explicit technical context, never selected from untrusted request identity headers."""

from cve_common.lifecycle.resources import Resources
from fastapi import Request


def resources_for(request: Request) -> Resources:
    value: Resources = request.app.state.resources
    return value
