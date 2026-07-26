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
RELEASE_WORKFLOW_PATH = REPO_ROOT / ".github" / "workflows" / "release.yml"
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
    for path in (CI_WORKFLOW_PATH, AUDIT_WORKFLOW_PATH, RELEASE_WORKFLOW_PATH):
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


def test_every_uv_sync_uses_locked_flag() -> None:
    """Security floors in pyproject.toml require --locked to enforce them.

    Without --locked, a synced venv could ignore raised dependency floors and
    install something stale from the lockfile, silently bypassing security
    constraints. --locked enforces lockfile ↔ pyproject.toml consistency.
    """
    for path in (CI_WORKFLOW_PATH, AUDIT_WORKFLOW_PATH, RELEASE_WORKFLOW_PATH):
        for command in _run_commands(_load_workflow(path)):
            if "uv sync" in command:
                assert "--locked" in command, (
                    f"{path.name} runs `uv sync` without `--locked`, which allows "
                    f"the lockfile to drift from pyproject.toml's security floors. "
                    f"Command: {command!r}"
                )


def test_setup_uv_is_version_pinned() -> None:
    """setup-uv without a version: resolves the newest uv at run time.

    This is the identical failure mode that bit the repo when unpinned `uvx ruff`
    jumped to 0.16.0 and reddened CI (see pyproject.toml:56-62). Every gate must
    be a function of the commit, not of what Astral shipped this morning.
    """
    for path in (CI_WORKFLOW_PATH, AUDIT_WORKFLOW_PATH, RELEASE_WORKFLOW_PATH):
        workflow = _load_workflow(path)
        for job_name, job in workflow["jobs"].items():
            for step in job.get("steps") or []:
                uses = step.get("uses", "")
                if "astral-sh/setup-uv@" in uses:
                    with_config = step.get("with", {})
                    assert "version" in with_config, (
                        f"{path.name} job {job_name!r} uses setup-uv without a "
                        f"version: field, so it resolves the newest uv at run time "
                        f"and makes the gate depend on the outside world instead of "
                        f"on the commit."
                    )


def test_docker_job_builds_exactly_once() -> None:
    """S7: the scanned image must be the published image.

    With load: true (docker exporter), BuildKit constructs an image that the
    Docker daemon re-assembles. A second build-push-action with push: true
    (registry exporter) is an independent invocation, so cache misses or
    poisoning produce different bytes. Fix: build once with push-by-digest,
    scan that digest, then promote tags from it.
    """
    workflow = _load_workflow(CI_WORKFLOW_PATH)
    docker_job = workflow["jobs"].get("docker")
    assert docker_job, "docker job does not exist"

    build_push_steps = [
        step
        for step in docker_job.get("steps", [])
        if step.get("uses", "").startswith("docker/build-push-action@")
    ]

    assert len(build_push_steps) <= 2, (
        "docker job has more than 2 build-push-action steps; this defeats "
        "the 'build once' requirement"
    )

    # If there are 2 steps, one must be conditional (PR path) and one (publish path)
    if len(build_push_steps) == 2:
        step_ifs = [step.get("if", "") for step in build_push_steps]
        assert any("PUBLISH" in cond for cond in step_ifs), (
            "docker job has 2 build-push-action steps but neither is gated on "
            "PUBLISH, so both always run"
        )

    # The publish-path step must use push-by-digest
    for step in build_push_steps:
        if "build" in step.get("id", "") and "local" not in step.get("id", ""):
            # This is the main/publish build step
            with_config = step.get("with", {})
            outputs = with_config.get("outputs", "")
            assert "push-by-digest=true" in outputs, (
                "docker job's publish-path build step does not use "
                "push-by-digest=true; the pushed image would not be the "
                "scanned one"
            )


def test_digest_verification_accounts_for_index_wrapping() -> None:
    """Production incident 2026-07-26: the publish-path digest check failed on
    every run to ``main``, and because it sits *before* the attestation step it
    also stopped provenance from ever being attached.

    ``docker buildx imagetools create`` does not reuse the source digest — it
    wraps the scanned manifest in a NEW OCI index. So comparing the tag's own
    digest (or a hash of ``inspect --raw`` stdout) against
    ``steps.build.outputs.digest`` compares an index against one of its
    children and can never match. Verified against the live registry: tag
    ``:latest`` was index ``sha256:8204263e…`` whose sole child was the scanned
    ``sha256:12db37ce…``.

    The invariant worth asserting is that every published tag serves *only* the
    scanned digest, which means inspecting the index's children. This test
    fails if someone reintroduces the digest-to-digest comparison.
    """
    workflow = _load_workflow(CI_WORKFLOW_PATH)
    docker_job = workflow["jobs"]["docker"]

    verify_steps = [
        step
        for step in docker_job.get("steps", [])
        if "serves only the scanned digest" in step.get("name", "")
        or "resolves to the scanned digest" in step.get("name", "")
    ]
    assert verify_steps, (
        "the docker job no longer verifies that published tags serve the "
        "scanned digest; that check is the proof the Trivy gate was not bypassed"
    )

    for step in verify_steps:
        script = step.get("run", "")
        # The broken form hashed the raw manifest bytes and compared that to
        # the build digest. Both halves of that mistake are banned.
        assert "sha256sum" not in script, (
            "the digest-verification step hashes `imagetools inspect --raw` "
            "output again. That yields the INDEX digest, which never equals "
            "the scanned manifest digest, so the step fails on every publish "
            "run and blocks provenance attestation. Inspect the index's "
            "child manifests instead."
        )
        # It must actually look at what the index serves.
        assert ".manifests" in script, (
            "the digest-verification step does not inspect the index's "
            "`.manifests` children, so it cannot tell whether the tag serves "
            "the scanned image after `imagetools create` wrapped it"
        )

    # Ordering matters for the consequence described above: attestation must
    # not be gated behind a check that is prone to this failure mode without
    # someone noticing the images lost their provenance.
    step_names = [step.get("name", "") for step in docker_job.get("steps", [])]
    attest = next(
        (i for i, name in enumerate(step_names) if "Attest build provenance" in name),
        None,
    )
    assert attest is not None, (
        "the docker job no longer attests build provenance for the image"
    )


def test_release_workflow_exists_and_is_tag_triggered() -> None:
    """S6: a release workflow must exist and be triggered by version tags."""
    assert RELEASE_WORKFLOW_PATH.exists(), (
        f"{RELEASE_WORKFLOW_PATH.name} does not exist. Without a release "
        f"workflow, the wheel cannot be published to PyPI with Trusted "
        f"Publishing and PEP 740 attestations."
    )

    workflow = _load_workflow(RELEASE_WORKFLOW_PATH)
    triggers = _triggers(workflow)

    assert "push" in triggers, "release.yml does not have a push trigger"
    push_config = triggers.get("push", {})
    tags = push_config.get("tags", [])
    assert "v*" in tags, (
        "release.yml's push trigger does not list tags: [v*], so release "
        "tags do not trigger the workflow"
    )


def test_release_workflow_gates_on_test_lint_audit() -> None:
    """S6: the release publish job must gate on test, lint, and audit.

    ci.yml runs on branches only; a tag could be cut from a commit that never
    passed CI. The audit job must re-run at tag time — its input is the live
    advisory database, not the commit.
    """
    workflow = _load_workflow(RELEASE_WORKFLOW_PATH)
    jobs = workflow["jobs"]

    for job_name in ("test", "lint", "audit"):
        assert job_name in jobs, (
            f"release.yml does not define a {job_name!r} job, so release "
            f"tags would bypass {job_name}"
        )

    build_job = jobs.get("build")
    assert build_job, "release.yml does not define a build job"

    build_needs = _needs(build_job)
    for gate in ("test", "lint", "audit"):
        assert gate in build_needs, (
            f"release.yml's build job needs {build_needs!r}, which omits {gate!r}. "
            f"A release could ship without passing {gate}."
        )


def test_release_workflow_publishes_via_trusted_publishing() -> None:
    """S6: publish-pypi job must use Trusted Publishing with id-token: write.

    Trusted Publishing (OIDC) replaces API tokens and generates PEP 740
    attestations by default.
    """
    workflow = _load_workflow(RELEASE_WORKFLOW_PATH)
    jobs = workflow["jobs"]

    publish_job = jobs.get("publish-pypi")
    assert publish_job, "release.yml does not define a publish-pypi job"

    permissions = publish_job.get("permissions", {})
    assert permissions.get("id-token") == "write", (
        f"publish-pypi job has permissions {permissions!r}, which does not "
        f"include id-token: write (required for Trusted Publishing)"
    )

    # Verify that attestations: is NOT set (it defaults to true in v1.11.0+)
    for step in publish_job.get("steps", []):
        uses = step.get("uses", "")
        if "pypa/gh-action-pypi-publish@" in uses:
            with_config = step.get("with", {})
            assert "attestations" not in with_config, (
                "publish-pypi step explicitly sets attestations:, which invites "
                "someone to 'simplify' it to false later. Let it default to true "
                "(v1.11.0+ default behavior)."
            )


def test_release_workflow_uses_environment_gate() -> None:
    """S6: publish-pypi should run in a GitHub Environment for human approval.

    This is where the second gate lives (first gate is the test/lint/audit
    dependency), and it should be the `pypi` environment that PyPI's trusted
    publisher config pins to.
    """
    workflow = _load_workflow(RELEASE_WORKFLOW_PATH)
    publish_job = workflow["jobs"].get("publish-pypi")
    assert publish_job, "release.yml does not define a publish-pypi job"

    environment = publish_job.get("environment")
    assert environment, (
        "publish-pypi job does not declare an environment, so there is no "
        "human approval gate before publishing to PyPI"
    )

    env_name = environment.get("name") if isinstance(environment, dict) else environment
    assert env_name == "pypi", (
        f"publish-pypi job uses environment {env_name!r}, not 'pypi'. "
        f"PyPI's trusted publisher config should pin to the 'pypi' environment."
    )


def test_github_release_survives_a_failed_pypi_publish() -> None:
    """Release incident 2026-07-26 (v0.6.0): ``github-release`` had
    ``needs: [publish-pypi]`` and no ``if:``, so a PyPI-side trusted-publisher
    misconfiguration — which fails the token exchange *before* any upload —
    also SKIPPED the GitHub Release. The tag and container image were published
    but the release record and its artifacts were lost, and re-running could not
    recover them, because a tag's workflow is pinned at the tag ref. The release
    had to be recreated by hand.

    A GitHub Release documents the tag; PyPI is an independent distribution
    channel. So the job must still run when ``publish-pypi`` fails, while not
    running when there is no artifact to attach.
    """
    workflow = _load_workflow(RELEASE_WORKFLOW_PATH)
    job = workflow["jobs"].get("github-release")
    assert job, "release.yml does not define a github-release job"

    needs = _needs(job)
    assert "build" in needs, (
        "github-release does not depend on `build`, so it can run with no "
        "distribution artifact to attach"
    )

    condition = str(job.get("if", ""))
    assert condition, (
        "github-release has no `if:`, so it inherits the default "
        "'skip if any dependency failed'. A failed PyPI upload — including a "
        "registry-side config error that uploads nothing — would silently take "
        "the GitHub Release down with it. Use `always()` plus an explicit "
        "`needs.build.result` check."
    )
    assert "always()" in condition, (
        f"github-release `if:` is {condition!r}, which does not use always(); "
        "it will still be skipped when publish-pypi fails"
    )
    # always() alone would also run the job after a FAILED build, when there is
    # no artifact — so the build result must be checked explicitly.
    assert "needs.build.result" in condition, (
        f"github-release `if:` is {condition!r}. With always() but no "
        "needs.build.result check, the job also runs after a failed build and "
        "fails confusingly on a missing artifact instead of being skipped."
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
