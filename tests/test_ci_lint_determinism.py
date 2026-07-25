"""Regression tests: CI gates must be reproducible from the repository state.

Context (2026-07-25). The ``Lint`` job invoked ``uvx ruff check`` and
``uvx bandit``. ``uvx`` resolves the *newest* release of a tool at run time, so
the job's verdict depended on the outside world rather than on the commit under
review. On 2026-07-23 ruff 0.16.0 expanded its default rule set from 59 to 413
rules; the same command that printed ``All checks passed!`` on 2026-07-16
started reporting 50 errors with zero code changes in between. The repository
also declared no rule set of its own, so its lint standard was whatever the
installed ruff happened to ship.

Separately, ``pip-audit``'s input is the live advisory database. That cannot
(and should not) be pinned — it is the point of the gate — but it *was* coupled
to PR activity, so a newly published CVE against any transitive dependency
failed every open PR at once. It now has a dedicated job plus a scheduled
counterpart.

The invariants asserted here:

1. no CI step invokes a linter through ``uvx`` (unpinned);
2. every lint tool is exactly pinned in the ``dev`` extra;
3. the ruff rule selection is declared by this repo;
4. ``pip-audit`` has a dedicated job, not a step buried inside ``lint``;
5. **the image-publish job depends on that audit job** — see below;
6. a scheduled audit workflow exists for proactive discovery.

Assertion 5 is the highest-value test in this file. When ``pip-audit`` lived
inside ``lint``, the ``docker`` job depended on it only *implicitly* via
``needs: [test, lint]``. A proposed refactor that moved the audit into a
separate workflow would have silently removed the audit from the GHCR publish
path, because GitHub Actions ``needs:`` cannot express a cross-workflow
dependency. That regression was caught in review; this test makes it
impossible to reintroduce.
"""

from __future__ import annotations

import tomllib
from pathlib import Path
from typing import Any

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
CI_WORKFLOW_PATH = REPO_ROOT / ".github" / "workflows" / "ci.yml"
AUDIT_WORKFLOW_PATH = REPO_ROOT / ".github" / "workflows" / "audit.yml"
PYPROJECT_PATH = REPO_ROOT / "pyproject.toml"

# Tools whose *version* determines whether the gate passes. These must come
# from the locked dev environment, never from `uvx`.
PINNED_LINT_TOOLS: tuple[str, ...] = ("ruff", "bandit")


def _load_workflow(path: Path) -> dict[str, Any]:
    # Fail with an actionable message rather than a bare FileNotFoundError:
    # a deleted workflow is a plausible regression, and the traceback for it
    # should say which gate went missing.
    if not path.exists():
        pytest.fail(
            f"{path.relative_to(REPO_ROOT)} does not exist. A CI workflow that "
            f"enforces a security gate was removed or renamed."
        )
    with open(path, encoding="utf-8") as fh:
        loaded = yaml.safe_load(fh)
    assert isinstance(loaded, dict), f"{path.name} did not parse as a mapping"
    return loaded


def _triggers(workflow: dict[str, Any]) -> dict[str, Any]:
    """Return a workflow's trigger mapping.

    ``on`` is a YAML 1.1 boolean, so ``yaml.safe_load`` yields the key ``True``
    rather than the string ``"on"``. Accept either so the test does not depend
    on the loader's quirk.
    """
    for key in (True, "on"):
        if key in workflow:
            value = workflow[key]
            return value if isinstance(value, dict) else {}
    pytest.fail("workflow declares no `on:` triggers")


def _run_commands(workflow: dict[str, Any]) -> list[str]:
    """Every ``run:`` command across every job in a workflow."""
    commands: list[str] = []
    for job in workflow.get("jobs", {}).values():
        for step in job.get("steps") or []:
            command = step.get("run")
            if command:
                commands.append(command)
    return commands


def _needs(job: dict[str, Any]) -> list[str]:
    """Normalise a job's ``needs:`` into a list (it may be a bare string)."""
    needs = job.get("needs", [])
    return [needs] if isinstance(needs, str) else list(needs)


def _dev_requirements() -> list[str]:
    with open(PYPROJECT_PATH, "rb") as fh:
        cfg = tomllib.load(fh)
    return cfg["project"]["optional-dependencies"]["dev"]


@pytest.mark.parametrize("tool", PINNED_LINT_TOOLS)
def test_no_linter_is_invoked_through_uvx(tool: str) -> None:
    """`uvx <tool>` floats to the newest release and must not gate CI."""
    for path in (CI_WORKFLOW_PATH, AUDIT_WORKFLOW_PATH):
        for command in _run_commands(_load_workflow(path)):
            assert f"uvx {tool}" not in command, (
                f"{path.name} runs `uvx {tool}`, which resolves the newest "
                f"release at run time and makes the gate depend on the outside "
                f"world instead of on the commit. Use `uv run {tool}` and pin "
                f"{tool} in the dev extra."
            )


@pytest.mark.parametrize("tool", PINNED_LINT_TOOLS)
def test_lint_tools_are_exactly_pinned_in_dev_extra(tool: str) -> None:
    """A pinned tool means a lint result that is reproducible over time."""
    matching = [r for r in _dev_requirements() if r.lower().startswith(tool)]
    assert matching, (
        f"{tool!r} is not declared in the dev extra, so `uv run {tool}` cannot "
        f"work in CI."
    )
    assert any("==" in r for r in matching), (
        f"{tool!r} is declared as {matching!r} — not exactly pinned. A floating "
        f"version can change the rule set between runs (ruff 0.16.0 expanded "
        f"its defaults 59 -> 413). Pin with `==`."
    )


@pytest.mark.parametrize("tool", PINNED_LINT_TOOLS)
def test_ci_runs_lint_tools_from_the_locked_environment(tool: str) -> None:
    commands = _run_commands(_load_workflow(CI_WORKFLOW_PATH))
    assert any(f"uv run {tool}" in c for c in commands), (
        f"ci.yml never runs `uv run {tool}`; the pinned {tool} in the dev extra "
        f"would not actually be the one enforcing the gate."
    )


def test_ruff_rule_selection_is_declared_by_this_repo() -> None:
    """Inheriting ruff's built-in default makes the standard drift on upgrade."""
    with open(PYPROJECT_PATH, "rb") as fh:
        cfg = tomllib.load(fh)

    select = cfg.get("tool", {}).get("ruff", {}).get("lint", {}).get("select")
    assert select, (
        "pyproject.toml declares no [tool.ruff.lint] select. Without it the "
        "lint standard is whatever default the installed ruff ships, which "
        "changed from 59 to 413 rules in 0.16.0."
    )
    assert isinstance(select, list) and all(isinstance(r, str) for r in select)


def test_pip_audit_has_a_dedicated_job() -> None:
    """The audit's input is world-state; it should not masquerade as a lint error."""
    workflow = _load_workflow(CI_WORKFLOW_PATH)
    jobs = workflow["jobs"]

    assert "audit" in jobs, (
        "ci.yml declares no `audit` job. pip-audit's result depends on the live "
        "advisory database rather than on the commit, so it belongs in its own "
        "job where a failure is attributable."
    )
    audit_commands = [s.get("run", "") for s in jobs["audit"]["steps"]]
    assert any("pip-audit" in c for c in audit_commands), (
        "the `audit` job does not actually run pip-audit."
    )

    lint_commands = [s.get("run", "") for s in jobs["lint"]["steps"]]
    assert not any("pip-audit" in c for c in lint_commands), (
        "pip-audit is still a step inside `lint`; it should live only in the "
        "dedicated `audit` job."
    )


def test_docker_publish_requires_the_audit_job() -> None:
    """No image may reach GHCR without pip-audit having passed.

    This guards the exact regression caught in cross-model review: relocating
    pip-audit out of `lint` removed it from the publish path, because
    `needs:` cannot span workflows. If this test fails, a known-vulnerable
    image can be pushed to the registry.
    """
    jobs = _load_workflow(CI_WORKFLOW_PATH)["jobs"]
    assert "docker" in jobs, "ci.yml no longer declares a `docker` job"

    needs = _needs(jobs["docker"])
    assert "audit" in needs, (
        f"the `docker` job needs {needs!r}, which omits `audit`. The image "
        f"publish would no longer be gated on pip-audit, so a release could "
        f"ship a known-vulnerable dependency. Add `audit` to its `needs:`."
    )
    # The other two gates must survive as well.
    assert "test" in needs and "lint" in needs, (
        f"the `docker` job needs {needs!r}; it must still depend on both "
        f"`test` and `lint`."
    )


def test_scheduled_audit_workflow_exists() -> None:
    """A scheduled run decouples advisory discovery from PR activity."""
    assert AUDIT_WORKFLOW_PATH.exists(), (
        f"{AUDIT_WORKFLOW_PATH.name} is missing. Without a scheduled audit, a "
        f"newly published CVE is discovered only when somebody happens to open "
        f"a PR — and it fails that unrelated PR."
    )
    workflow = _load_workflow(AUDIT_WORKFLOW_PATH)
    triggers = _triggers(workflow)

    assert "schedule" in triggers, "audit.yml declares no `schedule:` trigger"
    assert "workflow_dispatch" in triggers, (
        "audit.yml declares no `workflow_dispatch:` trigger, so the audit "
        "cannot be run on demand after remediating an advisory."
    )
    assert any("pip-audit" in c for c in _run_commands(workflow)), (
        "audit.yml does not run pip-audit."
    )


def test_scheduled_audit_does_not_duplicate_pull_request_runs() -> None:
    """PR coverage comes from ci.yml's `audit` job; audit.yml is for discovery."""
    triggers = _triggers(_load_workflow(AUDIT_WORKFLOW_PATH))
    assert "pull_request" not in triggers, (
        "audit.yml has a `pull_request` trigger, duplicating ci.yml's `audit` "
        "job on every PR."
    )


def test_workflow_actions_are_pinned_by_commit_sha() -> None:
    """Existing repo convention: third-party actions are pinned by SHA, not tag."""
    for path in (CI_WORKFLOW_PATH, AUDIT_WORKFLOW_PATH):
        workflow = _load_workflow(path)
        for job_name, job in workflow["jobs"].items():
            for step in job.get("steps") or []:
                uses = step.get("uses")
                if not uses or "@" not in uses:
                    continue
                ref = uses.rsplit("@", 1)[1]
                assert len(ref) == 40 and all(
                    c in "0123456789abcdef" for c in ref.lower()
                ), (
                    f"{path.name} job {job_name!r} uses {uses!r}, which is not "
                    f"pinned to a 40-character commit SHA."
                )


# --- failure-path coverage for the helpers ---------------------------------


def test_run_commands_helper_finds_commands_and_tolerates_stepless_jobs() -> None:
    workflow = {
        "jobs": {
            "a": {"steps": [{"run": "uv run ruff check ."}, {"uses": "x@" + "a" * 40}]},
            "b": {"steps": None},
            "c": {},
        }
    }
    assert _run_commands(workflow) == ["uv run ruff check ."]


def test_uvx_detection_would_catch_a_regression() -> None:
    """Proves the `uvx` assertions are not vacuous."""
    regressed = {"jobs": {"lint": {"steps": [{"run": "uvx ruff check src/"}]}}}
    assert any("uvx ruff" in c for c in _run_commands(regressed))


def test_needs_helper_normalises_a_bare_string() -> None:
    assert _needs({"needs": "lint"}) == ["lint"]
    assert _needs({"needs": ["test", "lint"]}) == ["test", "lint"]
    assert _needs({}) == []


def test_triggers_helper_handles_yaml_boolean_on_key() -> None:
    """`on:` parses as the boolean True under YAML 1.1."""
    assert _triggers({True: {"schedule": []}}) == {"schedule": []}
    assert _triggers({"on": {"push": {}}}) == {"push": {}}
