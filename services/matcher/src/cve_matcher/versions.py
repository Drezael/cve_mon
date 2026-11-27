"""Bounded deterministic Debian, RPM EVR and strict SemVer 2 adapters.

No coercion, remote calls, subprocesses or universal fallback. Cache is scoped to
this immutable adapter implementation; all operands remain in decision evidence.
"""

import re
from functools import lru_cache

from packaging.version import InvalidVersion, Version

ADAPTERS = {"debian": "dpkg-1", "rpm": "rpm-1", "semver": "semver-2", "pep440": "packaging-26.3"}
ECOSYSTEMS = {
    "Debian": "debian",
    "Ubuntu": "debian",
    "npm": "semver",
    "crates.io": "semver",
    "PyPI": "pep440",
}


def ecosystem_adapter(ecosystem: str) -> str | None:
    if ecosystem.startswith("Ubuntu:") or ecosystem.startswith("Debian:"):
        return "debian"
    return ECOSYSTEMS.get(ecosystem)


class VersionError(ValueError):
    """A fixed error code, never an untrusted input string."""


def sign(a: object, b: object) -> int:
    # Internal callers supply homogeneous int/str/tuple values.
    return int(a > b) - int(a < b)  # type: ignore[operator]


def checked(value: str) -> str:
    if not isinstance(value, str) or not 1 <= len(value) <= 512 or not value.isascii():
        raise VersionError("invalid_version")
    return value


def deb_parts(value: str) -> tuple[int, str, str]:
    checked(value)
    epoch, sep, rest = value.partition(":")
    if sep:
        if not epoch.isdigit():
            raise VersionError("invalid_version")
        e, v = int(epoch), rest
    else:
        e, v = 0, value
    upstream, dash, revision = v.rpartition("-")
    if not dash:
        upstream, revision = v, "0"
    if not re.fullmatch(r"[0-9][A-Za-z0-9.+:~\-]*", upstream) or not re.fullmatch(
        r"[A-Za-z0-9+.~]+", revision
    ):
        raise VersionError("invalid_version")
    if ":" in upstream and not sep:
        raise VersionError("invalid_version")
    return e, upstream, revision


def deb_order(c: str) -> int:
    if c == "~":
        return -1
    if not c or c.isdigit():
        return 0
    return ord(c) if c.isalpha() else ord(c) + 256


def deb_segment(a: str, b: str) -> int:
    i = j = 0
    while i < len(a) or j < len(b):
        while (i < len(a) and not a[i].isdigit()) or (j < len(b) and not b[j].isdigit()):
            ac, bc = a[i : i + 1], b[j : j + 1]
            d = sign(deb_order(ac), deb_order(bc))
            if d:
                return d
            i += bool(ac)
            j += bool(bc)
        ai, bj = i, j
        while i < len(a) and a[i].isdigit():
            i += 1
        while j < len(b) and b[j].isdigit():
            j += 1
        x, y = a[ai:i].lstrip("0"), b[bj:j].lstrip("0")
        d = sign(len(x), len(y)) or sign(x, y)
        if d:
            return d
    return 0


def rpm_parts(value: str) -> tuple[int, str, str]:
    checked(value)
    if not re.fullmatch(r"(?:[0-9]+:)?[A-Za-z0-9._+~^]+(?:-[A-Za-z0-9._+~^]+)?", value):
        raise VersionError("invalid_version")
    epoch, sep, rest = value.partition(":")
    e, v = (int(epoch), rest) if sep else (0, value)
    version, dash, release = v.partition("-")
    return e, version, release if dash else ""


def rpm_segment(a: str, b: str) -> int:
    while a or b:
        a = a.lstrip("._+")
        b = b.lstrip("._+")
        if a.startswith("~") or b.startswith("~"):
            if not a.startswith("~") or not b.startswith("~"):
                return -1 if a.startswith("~") else 1
            a, b = a[1:], b[1:]
            continue
        if a.startswith("^") or b.startswith("^"):
            if not a or not b:
                return 1 if a else -1
            if not a.startswith("^") or not b.startswith("^"):
                return -1 if a.startswith("^") else 1
            a, b = a[1:], b[1:]
            continue
        if not a or not b:
            return sign(bool(a), bool(b))
        numeric = a[0].isdigit()
        if numeric != b[0].isdigit():
            return 1 if numeric else -1
        pattern = r"[0-9]+" if numeric else r"[A-Za-z]+"
        x, y = re.match(pattern, a), re.match(pattern, b)
        assert x is not None and y is not None
        av, bv = x[0], y[0]
        a, b = a[len(av) :], b[len(bv) :]
        if numeric:
            av, bv = av.lstrip("0"), bv.lstrip("0")
            d = sign(len(av), len(bv)) or sign(av, bv)
        else:
            d = sign(av, bv)
        if d:
            return d
    return 0


def semver(value: str) -> tuple[tuple[int, int, int], tuple[str, ...]]:
    checked(value)
    m = re.fullmatch(
        r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)"
        r"(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?"
        r"(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?",
        value,
    )
    if not m:
        raise VersionError("invalid_version")
    pre = tuple(m[4].split(".")) if m[4] else ()
    if any(p.isdigit() and len(p) > 1 and p.startswith("0") for p in pre):
        raise VersionError("invalid_version")
    return (int(m[1]), int(m[2]), int(m[3])), pre


@lru_cache(maxsize=8192)
def compare(adapter: str, a: str, b: str) -> int:
    if adapter == "pep440":
        try:
            return sign(Version(checked(a)), Version(checked(b)))
        except InvalidVersion:
            raise VersionError("invalid_version") from None
    if adapter == "debian":
        ae, au, ar = deb_parts(a)
        be, bu, br = deb_parts(b)
        return sign(ae, be) or deb_segment(au, bu) or deb_segment(ar, br)
    if adapter == "rpm":
        ae, av, ar = rpm_parts(a)
        be, bv, br = rpm_parts(b)
        return sign(ae, be) or rpm_segment(av, bv) or rpm_segment(ar, br)
    if adapter == "semver":
        avs, ap = semver(a)
        bvs, bp = semver(b)
        d = sign(avs, bvs)
        if d:
            return d
        if not ap or not bp:
            return sign(not ap, not bp)
        for x, y in zip(ap, bp, strict=False):
            if x == y:
                continue
            if x.isdigit() and y.isdigit():
                return sign(int(x), int(y))
            if x.isdigit() != y.isdigit():
                return -1 if x.isdigit() else 1
            return sign(x, y)
        return sign(len(ap), len(bp))
    raise VersionError("unsupported_comparator")
