"""Regression tests for dependency version floors adopted for security reasons.

Context (2026-07-25). CI's ``pip-audit`` step failed on PR #45 because
``uv.lock`` pinned ``click 8.3.1`` (PYSEC-2026-2132 / CVE-2026-7246), and the
same audit revealed ``mcp 1.27.0`` carrying three further advisories
(PYSEC-2026-3481/3482/3483). Both were *legal* pins: nothing in the repository
recorded that a security floor had been adopted. ``uv.lock`` is a resolution
snapshot, not a constraint, so a future ``uv lock`` regeneration could silently
drop back below either fix.

These tests encode the missing invariant:

  every version floor this project adopted for a security reason must
  (a) hold in the resolved environment, and
  (b) be declared in ``pyproject.toml`` at the layer matching the
      dependency's kind.

The layer distinction is load-bearing:

* **Direct** dependencies belong in ``[project.dependencies]`` — the only
  place that reaches the published wheel's ``METADATA`` and therefore the only
  thing protecting ``pip install ssh-mcp`` consumers.
* **Transitive** dependencies belong in ``[tool.uv] constraint-dependencies``.
  Putting them in ``[project.dependencies]`` would assert a dependency edge
  that does not exist; a uv constraint binds resolution without lying about
  the graph.

These tests deliberately do NOT query an advisory database. That makes them
offline, deterministic, and able to catch a lockfile regression on a laptop
with no network — something ``pip-audit`` structurally cannot do.
"""

from __future__ import annotations

import tomllib
from importlib.metadata import PackageNotFoundError
from importlib.metadata import version as installed_version
from pathlib import Path

import pytest
from packaging.requirements import Requirement
from packaging.version import Version

PYPROJECT_PATH = Path(__file__).resolve().parent.parent / "pyproject.toml"

# package -> (minimum safe version, why the floor exists)
#
# Add an entry here whenever a dependency version is chosen to clear an
# advisory. The tests below then enforce that the choice is both declared and
# actually in effect.
SECURITY_FLOORS: dict[str, tuple[str, str]] = {
    "click": (
        "8.3.3",
        "PYSEC-2026-2132 / CVE-2026-7246 — command injection in click.edit() "
        "via an unescaped filename interpolated into a shell string. "
        "Transitive only (mcp[cli] -> typer -> click, uvicorn -> click); "
        "ssh-mcp never imports click, so it is not exploitable here.",
    ),
    "mcp": (
        "1.28.1",
        "PYSEC-2026-3481 / CVE-2026-52870 (experimental tasks handlers), "
        "PYSEC-2026-3482 / CVE-2026-52869 (StreamableHTTPSessionManager "
        "cross-principal session bypass), PYSEC-2026-3483 / CVE-2026-59950 "
        "(deprecated websocket_server). None reachable from ssh-mcp's SDK "
        "usage; 1.28.1 is the max first-patched version across the three.",
    ),
}

# Packages that ssh-mcp imports directly and must therefore constrain in the
# published wheel metadata, not merely in the lockfile.
DIRECT_DEPENDENCIES: frozenset[str] = frozenset({"mcp"})


def _pyproject() -> dict:
    with open(PYPROJECT_PATH, "rb") as fh:
        return tomllib.load(fh)


def _declared_floor(requirement: str, package: str) -> Version | None:
    """Return the lower-bound version ``requirement`` places on ``package``.

    Returns ``None`` when the requirement is for a different package or
    declares no lower bound at all. Extras and upper bounds are ignored:
    ``"mcp[cli]>=1.28.1,<2.0.0"`` yields ``Version("1.28.1")``.
    """
    req = Requirement(requirement)
    if req.name.lower() != package.lower():
        return None
    for spec in req.specifier:
        if spec.operator in (">=", "==", "~=", ">"):
            return Version(spec.version)
    return None


def _floor_from(requirements: list[str], package: str) -> Version | None:
    """Highest lower bound any entry in ``requirements`` places on ``package``."""
    floors = [f for f in (_declared_floor(r, package) for r in requirements) if f]
    return max(floors) if floors else None


@pytest.mark.parametrize(
    ("package", "floor", "reason"), [(p, f, r) for p, (f, r) in SECURITY_FLOORS.items()]
)
def test_installed_version_meets_security_floor(
    package: str, floor: str, reason: str
) -> None:
    """The resolved environment must satisfy every adopted security floor."""
    try:
        actual = Version(installed_version(package))
    except PackageNotFoundError:  # pragma: no cover - env misconfiguration
        pytest.fail(
            f"{package!r} is not installed, so its security floor cannot be "
            f"verified. Run `uv sync --extra dev`."
        )
    assert actual >= Version(floor), (
        f"{package} {actual} is below the adopted security floor {floor}.\n"
        f"Reason for the floor: {reason}\n"
        f"Fix: uv lock --upgrade-package {package} && uv sync --extra dev"
    )


@pytest.mark.parametrize("package", sorted(SECURITY_FLOORS))
def test_security_floor_is_declared_in_pyproject(package: str) -> None:
    """A floor that lives only in uv.lock is one `uv lock` away from vanishing.

    Every entry in ``SECURITY_FLOORS`` must be declared in pyproject.toml —
    either as a direct dependency or as a uv constraint — with a bound at
    least as high as the table's.
    """
    expected = Version(SECURITY_FLOORS[package][0])
    cfg = _pyproject()

    project_floor = _floor_from(cfg["project"].get("dependencies", []), package)
    constraint_floor = _floor_from(
        cfg.get("tool", {}).get("uv", {}).get("constraint-dependencies", []), package
    )
    declared = [f for f in (project_floor, constraint_floor) if f]

    assert declared, (
        f"No floor for {package!r} is declared in pyproject.toml. It must appear "
        f"in [project.dependencies] (direct deps) or [tool.uv] "
        f"constraint-dependencies (transitive deps), otherwise the next "
        f"`uv lock` regeneration can silently reintroduce a vulnerable version."
    )
    assert max(declared) >= expected, (
        f"Declared floor for {package!r} is {max(declared)}, below the required "
        f"{expected}. Reason: {SECURITY_FLOORS[package][1]}"
    )


@pytest.mark.parametrize("package", sorted(DIRECT_DEPENDENCIES))
def test_direct_dependency_floor_reaches_wheel_metadata(package: str) -> None:
    """Direct deps must be constrained in [project.dependencies], not just uv.

    ``[tool.uv]`` settings are uv-only and absent from the built wheel's
    ``METADATA``. For a project published to PyPI, a floor declared only there
    leaves ``pip install ssh-mcp`` free to resolve a vulnerable version. This
    is the assertion that protects downstream consumers rather than just CI.
    """
    expected = Version(SECURITY_FLOORS[package][0])
    declared = _floor_from(_pyproject()["project"]["dependencies"], package)

    assert declared is not None, (
        f"{package!r} is a direct dependency but declares no lower bound in "
        f"[project.dependencies]; the published wheel would not protect users."
    )
    assert declared >= expected, (
        f"[project.dependencies] pins {package}>={declared}, below the security "
        f"floor {expected}. The wheel's METADATA would permit a vulnerable "
        f"resolution for anyone running `pip install ssh-mcp`."
    )


def test_transitive_floor_uses_uv_constraint_not_project_dependency() -> None:
    """`click` must NOT be promoted to a direct dependency.

    ssh-mcp does not import click (its CLI parses ``sys.argv`` directly).
    Declaring it in ``[project.dependencies]`` would assert a dependency edge
    that does not exist and publish it to every consumer. The floor belongs in
    ``[tool.uv] constraint-dependencies``, which binds resolution only when
    something else already pulls click into the graph.
    """
    cfg = _pyproject()

    assert _floor_from(cfg["project"]["dependencies"], "click") is None, (
        "click appears in [project.dependencies]. It is a transitive "
        "dependency only; use [tool.uv] constraint-dependencies instead so the "
        "published metadata does not misstate the dependency graph."
    )
    assert (
        _floor_from(cfg["tool"]["uv"]["constraint-dependencies"], "click") is not None
    ), "click floor is missing from [tool.uv] constraint-dependencies."


# --- failure-path coverage for the assertion machinery itself ---------------
#
# Without these, a bug in `_declared_floor` could make every test above pass
# vacuously (e.g. by always returning None and never comparing anything).


@pytest.mark.parametrize(
    ("requirement", "package", "expected"),
    [
        ("mcp[cli]>=1.28.1,<2.0.0", "mcp", "1.28.1"),  # extras + upper bound
        ("click>=8.3.3", "click", "8.3.3"),
        ("pytest==9.0.3", "pytest", "9.0.3"),  # == is a floor too
        ("hypothesis~=6.151.0", "hypothesis", "6.151.0"),
    ],
)
def test_declared_floor_extracts_lower_bound(
    requirement: str, package: str, expected: str
) -> None:
    assert _declared_floor(requirement, package) == Version(expected)


@pytest.mark.parametrize(
    ("requirement", "package"),
    [
        ("mcp[cli]>=1.28.1", "click"),  # different package
        ("click<9", "click"),  # upper bound only, no floor
        ("orjson", "orjson"),  # unconstrained
    ],
)
def test_declared_floor_returns_none_when_no_floor_applies(
    requirement: str, package: str
) -> None:
    assert _declared_floor(requirement, package) is None


def test_floor_comparison_rejects_a_vulnerable_version() -> None:
    """Proves the comparison is version-aware, not lexicographic.

    A string compare would rank ``"8.3.1" < "8.3.3"`` correctly by luck but
    ``"8.10.0" < "8.4.2"`` incorrectly. This asserts the real semantics that
    ``test_installed_version_meets_security_floor`` relies on.
    """
    floor = Version(SECURITY_FLOORS["click"][0])  # 8.3.3
    assert Version("8.3.1") < floor, "the vulnerable version must fail the floor"
    assert Version("8.3.3") >= floor
    assert Version("8.4.2") >= floor
    assert Version("8.10.0") > Version("8.4.2"), "comparison must not be lexicographic"
