"""Independent native dpkg/RPM oracles and strict SemVer precedence fixtures."""

import ctypes
import ctypes.util
import itertools
import subprocess

import pytest
from cve_matcher.ranges import osv
from cve_matcher.versions import VersionError, compare, rpm_parts

pytestmark = [pytest.mark.matching, pytest.mark.domain]
DEBIAN = [
    "0",
    "1.0",
    "1.0-0",
    "1.0~rc1",
    "1.0~~",
    "1.0+git1",
    "1.0-1",
    "1.0-1ubuntu8.4",
    "1.0-1ubuntu8.10",
    "1:0.1-1",
    "2:0.0-1",
    "1.001",
    "1.01",
    "1.1",
    "1.0-a-b",
]
RPM = [
    "0",
    "1.0",
    "1.0-0",
    "1.0~rc1",
    "1.0^git1",
    "1.0.1",
    "1.0-1.el9",
    "1.0-2.el9",
    "1:0.1-1",
    "2:0.0-1",
    "1.001",
    "1.01",
    "1.1",
    "1.0+git",
    "1.0.git",
]


@pytest.mark.parametrize(
    "a,b",
    [
        ("1.0.dev1", "1.0a1"),
        ("1.0a1", "1.0rc1"),
        ("1.0rc1", "1.0"),
        ("1.0", "1.0.post1"),
        ("1!9.0", "2!0.1"),
        ("1.0+local.1", "1.0+local.2"),
    ],
)
def test_pep440_epoch_prerelease_postrelease_and_local_order(a: str, b: str) -> None:
    assert compare("pep440", a, b) == -1
    assert compare("pep440", b, a) == 1


def test_pep440_equivalent_and_invalid_versions_and_osv_range() -> None:
    assert compare("pep440", "1.0", "1.0.0") == 0
    with pytest.raises(VersionError):
        compare("pep440", "unknown-version", "1.0")
    affected = {
        "package": {"ecosystem": "PyPI", "name": "demo"},
        "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "2.0"}]}],
    }
    assert osv("1.9", affected) == (True, "osv_interval", "pep440")
    assert osv("2.0", affected) == (False, "outside_osv_intervals", "pep440")


@pytest.mark.parametrize(("a", "b"), list(itertools.combinations(DEBIAN, 2)))
def test_debian_dpkg_oracle(a: str, b: str) -> None:
    less = subprocess.run(["dpkg", "--compare-versions", a, "lt", b], check=False).returncode
    equal = subprocess.run(["dpkg", "--compare-versions", a, "eq", b], check=False).returncode
    expected = -1 if less == 0 else 0 if equal == 0 else 1
    assert compare("debian", a, b) == expected
    assert compare("debian", b, a) == -expected


@pytest.mark.parametrize(("a", "b"), list(itertools.combinations(RPM, 2)))
def test_rpm_native_oracle(a: str, b: str) -> None:
    path = ctypes.util.find_library("rpm")
    assert path, "Native librpm oracle required (install librpm9/rpm)"
    library = ctypes.CDLL(path)
    library.rpmvercmp.argtypes = [ctypes.c_char_p, ctypes.c_char_p]
    library.rpmvercmp.restype = ctypes.c_int
    ae, av, ar = rpm_parts(a)
    be, bv, br = rpm_parts(b)
    expected = (ae > be) - (ae < be)
    expected = (
        expected
        or library.rpmvercmp(av.encode(), bv.encode())
        or library.rpmvercmp(ar.encode(), br.encode())
    )
    expected = (expected > 0) - (expected < 0)
    assert compare("rpm", a, b) == expected
    assert compare("rpm", b, a) == -expected


@pytest.mark.parametrize(
    ("a", "b"),
    [
        ("1.0.0-alpha", "1.0.0-alpha.1"),
        ("1.0.0-alpha.1", "1.0.0-alpha.beta"),
        ("1.0.0-beta.2", "1.0.0-beta.11"),
        ("1.0.0-rc.1", "1.0.0"),
        ("1.9.0", "1.10.0"),
    ],
)
def test_semver_precedence(a: str, b: str) -> None:
    assert compare("semver", a, b) == -1


def test_semver_build_metadata() -> None:
    assert compare("semver", "1.0.0+foo", "1.0.0+bar") == 0


@pytest.mark.parametrize(
    ("adapter", "value"),
    [
        ("semver", "1.0"),
        ("semver", "v1.0.0"),
        ("semver", "01.0.0"),
        ("semver", "1.0.0-01"),
        ("debian", "1.0-"),
        ("debian", "1;echo bad"),
        ("rpm", "1.0-foo-bar"),
        ("rpm", "ä"),
        ("rpm", "1" * 513),
    ],
)
def test_invalid_versions(adapter: str, value: str) -> None:
    with pytest.raises(VersionError, match="invalid_version"):
        compare(adapter, value, value)


def test_unsupported_comparator() -> None:
    with pytest.raises(VersionError, match="unsupported_comparator"):
        compare("PyPI", "1.0", "2.0")
