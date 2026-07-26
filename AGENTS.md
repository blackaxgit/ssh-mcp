# AGENTS.md

> AI coding assistant context for this repository. Read natively by Codex, Cursor, Copilot,
> Gemini CLI, Windsurf, and 20+ AGENTS.md-aware tools. Claude Code users: load via `@AGENTS.md` in `CLAUDE.md`.

Command sources: `.github/workflows/ci.yml` (the gates), `.github/workflows/release.yml` (build/publish), `CONTRIBUTING.md`, `pyproject.toml`. There is no Makefile — copy commands from CI rather than inventing them.

## Overview

- **Purpose:** SSH MCP server that lets AI assistants execute commands on remote servers.
- **Owner:** TODO: team/maintainer
- **Type:** app — published as a PyPI wheel (`uvx blc-ssh-mcp`) *and* a container image (`ghcr.io/blackaxgit/ssh-mcp`). **The PyPI distribution is `blc-ssh-mcp`, not `ssh-mcp`** — that name belongs to an unrelated project this repo has never owned; see the comment above `name` in `pyproject.toml`. The import package is still `ssh_mcp` and the image is still `.../ssh-mcp`.
- **Stacks:** Python 3.11-3.14, `uv` + hatchling, asyncssh, MCP SDK, Starlette/uvicorn (HTTP transport only)
- **Deploy targets:** N/A — this is a tool operators run themselves, not a hosted service
- **Version:** `src/ssh_mcp/__init__.py` is the single source (hatchling reads it). Currently `0.5.6`; `CHANGELOG.md` `[Unreleased]` targets **0.6.0**.

**What this tool does matters for how you treat it.** Every tool call runs a shell command or transfers a file on a remote host. A bug here is not a crashed request; it is an unintended command on someone's infrastructure, or a write to the operator's own machine.

## Commands

```bash
uv sync --locked --extra dev        # setup. --locked is required; see Gotchas
uv run pytest                       # full suite (~690 tests, seconds)
uv run pytest tests/test_ssh.py::TestRedactSecrets -v          # one class
uv run pytest 'tests/test_ssh.py::TestRedactSecrets::<test_name>' -v   # one test
uv run pytest -k "confinement" -v                              # by keyword
```

Full gate, exactly as CI runs it — run all six before opening a PR:

```bash
uv run python -m pytest tests/ -v --cov=ssh_mcp --cov-report=term-missing
uv run ruff format --check src/ tests/
uv run ruff check src/ tests/
uv run mypy src/                    # src/ only — tests are not type-checked
uv run bandit -r src/ -q
uv run pip-audit                    # separate `audit` job in CI
```

Run it locally (needs a `servers.toml`, see below):

```bash
uv run ssh-mcp                      # stdio transport (default)
SSH_MCP_TRANSPORT=http uv run ssh-mcp    # streamable HTTP on 127.0.0.1:8000
uv run ssh-mcp healthcheck          # the only argv subcommand that exists
```

## Repository Layout

| Path | Purpose |
|---|---|
| `src/ssh_mcp/server.py` | MCP tool definitions, stdio + HTTP transport dispatch, bearer-auth ASGI middleware, `_mcp_tool` decorator (init guard + `ToolError` conversion + an `mcp.tool.{name}` OTel span) |
| `src/ssh_mcp/ssh.py` | `SSHManager`: connection pool, exec, SFTP — **and** the security policy (credential redaction, dangerous-command patterns, sensitive paths) |
| `src/ssh_mcp/paths.py` | Symlink-safe path confinement beneath a pinned root fd. Read its module docstring before touching it |
| `src/ssh_mcp/config.py` | `ServerRegistry`: TOML loading, validation, circular jump-host detection |
| `src/ssh_mcp/models.py` | Frozen Pydantic dataclasses (`extra="forbid"`) + the mutable `ExecResult` |
| `src/ssh_mcp/formatting.py` | Renders results as text tables for an LLM to read |
| `src/ssh_mcp/healthcheck.py` | `ssh-mcp healthcheck` CLI, stdlib only, invoked by the Dockerfile `HEALTHCHECK` |
| `config/servers.example.toml` | Copy to `~/.config/ssh-mcp/servers.toml` and edit. The real file is gitignored |

Config resolution order, as implemented in `server.py::_get_config_path`: `$SSH_MCP_CONFIG` → `$XDG_CONFIG_HOME/ssh-mcp/servers.toml` → `~/.config/ssh-mcp/servers.toml` → a package-relative `config/servers.toml` (development only; not present in a clone, since real config files are gitignored). Any test that exercises this chain must pin **both** `$HOME` and `$XDG_CONFIG_HOME` — see Gotchas.

## Configuration

`[settings]` in `servers.toml`, validated by `models.py` (frozen, `extra="forbid"`, ranges enforced):

| Key | Default | Range | Note |
|---|---|---|---|
| `ssh_config_path` | `~/.ssh/config` | — | `~` expanded at the model boundary |
| `command_timeout` | `30` | 1-3600 | seconds |
| `max_output_bytes` | `51200` | 1024-10485760 | **per stream** — see Gotchas |
| `max_command_bytes` | `65536` | 1024-1048576 | enforced at the tool boundary |
| `transfer_root` | `$XDG_DATA_HOME/ssh-mcp/transfers`, else `~/.local/share/ssh-mcp/transfers` | — | SFTP confinement root; computed in `paths.py::default_transfer_root`, but the settings loader in `config.py` applies `SSH_MCP_TRANSFER_ROOT` on top — precedence is **env > TOML > computed default** |
| `connection_idle_timeout` | `300` | ≥10 | eviction scan runs every 60s |
| `known_hosts` | `true` | — | `false` removes MITM protection |
| `max_parallel_hosts` | `10` | 1-100 | process-wide, not per call |

Environment variables (names only — `README.md` has the full table): `SSH_MCP_CONFIG`, `SSH_MCP_TRANSFER_ROOT`, `SSH_MCP_LOG_FORMAT`, `SSH_MCP_TRANSPORT`, the HTTP-transport set `SSH_MCP_HTTP_{HOST,PORT,TOKEN,TOKEN_FILE,AUTH,NETWORK_NO_AUTH,STATELESS,ALLOWED_HOSTS,KEEPALIVE_TIMEOUT,LIMIT_CONCURRENCY,BACKLOG}`, plus three read outside the `SSH_MCP_` prefix: `XDG_CONFIG_HOME` (`server.py::_get_config_path`) and `XDG_DATA_HOME` (`paths.py::default_transfer_root`) — the two the config-resolution Gotcha calls load-bearing — and `HYPOTHESIS_PROFILE` (`tests/conftest.py`, `dev` = 50 examples / `ci` = 200). The conftest comment claims the CI workflow sets `HYPOTHESIS_PROFILE`; **it does not** — no workflow sets it, so CI runs the `dev` profile.

Four module-level tunables in `ssh.py` are *deliberately* not `Settings` fields — lifted out of inline literals to be greppable and testable without widening the operator-facing config surface. Do not promote them without a reason: `_EVICTION_LOOP_INTERVAL_S` (60s), `_MAX_JUMP_HOST_DEPTH` (5 chained jump hosts), `_STREAM_READ_CHUNK_BYTES`, and `_MAX_SFTP_BYTES` — a **100 MiB hard cap per SFTP transfer**, which `_upload_impl` refuses to exceed while `_download_impl` only warns, the bytes being already on disk by then.

**HTTP transport fails closed by design, and the gates are load-bearing.** Binding to anything other than loopback without `SSH_MCP_HTTP_TOKEN` raises at startup; a token shorter than 16 characters is rejected; DNS-rebinding protection is forced on, and a bare-wildcard `allowed_hosts` entry (`*`, `*:*`) is refused — though a *suffix* wildcard such as `*.internal.example.com` is deliberately permitted (the `allowed_hosts` gate in `server.py::_run_http`). Read that refusal set carefully before editing it: `"*.*"` is listed in it, but the `entry.startswith("*.")` `continue` on the next line fires first, so `*.*` currently lands on the **permitted** side. Disabling auth on a non-loopback bind additionally requires `SSH_MCP_HTTP_NETWORK_NO_AUTH=I_ACCEPT_RCE_RISK` — a deliberately verbose opt-in, because the endpoint executes shell commands. Do not add a code path that relaxes any of these, and note the server speaks plain HTTP: TLS is the reverse proxy's job.

## Testing

Tests mirror modules (`test_ssh.py` ↔ `ssh.py`). `pytest-asyncio` runs in `asyncio_mode = "auto"`, so `async def test_*` needs no decorator. Hypothesis drives the redaction and dangerous-command property tests.

Not every test file mirrors a module. `tests/test_input_limits.py` (18 tests) guards `max_command_bytes` at the tool boundary; `tests/test_logging.py` (7) and `tests/test_otel.py` (7) cover the observability wiring in `server.py`.

Three test files assert *invariants* rather than behaviour, and are load-bearing — read them before changing what they guard:

- `tests/test_ci_lint_determinism.py` — CI must not invoke a linter via `uvx`, lint tools must be `==`-pinned, and the `docker` job must depend on `audit`. It guards considerably more than that: every action pinned to a 40-char commit SHA, every `uv sync` carrying `--locked`, `setup-uv` version-pinned, the `docker` job building exactly once, and `release.yml`'s `build` gating on test/lint/audit plus Trusted Publishing and the `pypi` environment. Assume any workflow edit is machine-checked.
- `tests/test_dependency_floors.py` — every security-motivated version floor must hold *and* be declared in `pyproject.toml`.
- `tests/test_sftp_confinement.py` — asserts `sftp.get`/`sftp.put` are **never called**, which is the whole point of the confinement design.

When adding a test for a fix, make it fail on the unfixed code first. Several tests in this repo exist specifically because a plausible-looking fix silently did nothing.

## Conventions

**`ExecResult` has two opposite error contracts. This is the single easiest way to write a bug here.**

```python
# execute() / execute_on_group() NEVER raise — failures ride inside the result:
result = await ssh.execute("host", "cmd")
if result.error:            # SSH failure, timeout, blocked command, unknown server
    ...                     # result.exit_code is None
# upload() / download() DO raise — ValueError / RuntimeError, converted to
# ToolError by the _mcp_tool decorator in server.py.
```

The full state matrix is documented on `ExecResult` in `models.py`. Do not "normalise" one side to match the other without changing both the docstring and `formatting.py`.

**`execute`, `upload` and `download` in `ssh.py` are thin tracing wrappers — the behaviour lives in `_execute_impl` / `_upload_impl` / `_download_impl`.** If you are told to change what `execute()` does, edit `_execute_impl`; the public method only opens an OTel span and delegates. Editing the wrapper is the obvious wrong turn here. OpenTelemetry is optional throughout: the `otel` extra in `pyproject.toml` installs the API only (operators bring their own SDK/exporter; the SDK is a dev dep for the in-memory exporter in `tests/test_otel.py`), and both `server.py::_span` and `ssh.py::_ssh_tracer` soft-import it and no-op when absent. **Spans are a leak surface — treat them like logs.** They record `ssh.command_length`, never the command itself, and error text is `_redact_secrets`'d and truncated to 200 characters. Do not add an attribute carrying a command, a path, or raw error output.

**Comments explain *why*, and cite the incident.** The codebase carries its own history inline — `# Production incident 2026-04-11`, `# R5 finding #3`, `# panel iteration 2`. Match that register. A comment restating what the code does is noise; a comment naming the failure that motivated the code is why this repo is auditable.

**Settings are frozen and reject unknown keys.** `models.py` uses `extra="forbid"` with `Field(ge=…, le=…)` ranges, so a typo in `servers.toml` fails loudly at load. Add validation there, not at call sites — and note that Pydantic does **not** validate defaults unless the field sets `validate_default=True`.

## CI/CD

| Workflow | Trigger | Jobs |
|---|---|---|
| `ci.yml` | push/PR to `main`, tags `v*` | `test` (3.11-3.14), `lint`, `audit`, `docker` (`needs: [test, lint, audit]`) |
| `audit.yml` | daily cron + manual | `pip-audit` against `main`, so a new advisory surfaces on its own schedule instead of reddening an unrelated PR |
| `release.yml` | tag `v*` | re-runs test/lint/audit → `build` (asserts tag == packaged version, emits CycloneDX SBOM) → `publish-pypi` → `github-release` |

**Every push to `main` publishes a container image.** The `docker` job's `PUBLISH` is `github.event_name == 'push' && (github.ref == 'refs/heads/main' || startsWith(github.ref, 'refs/tags/v'))` (`ci.yml:160`), so a merged PR pushes `latest` + `type=sha` tags to GHCR with **no environment gate and no human approval** — a tag is not the only path to a publish. PRs build and scan only. Two Trivy steps (CRITICAL severity) gate the promote, both reading `.trivyignore`.

All third-party actions are pinned to a full commit SHA with a `# vX` comment, and `astral-sh/setup-uv` additionally pins a `version:` so `uv` itself cannot float. Keep both — an unpinned tool is how this repo previously had CI go red on commits that had passed days earlier. Never replace a SHA with a tag reference. None of this is prose-only convention: `tests/test_ci_lint_determinism.py` asserts it, so a workflow edit that drops a pin fails the suite.

Publishing to PyPI uses **Trusted Publishing** (OIDC) behind a reviewer-gated `pypi` environment. PEP 740 attestations are on by default in the publish action — do not add an `attestations:` input.

## Git & Workflow

- Branch from `main`; never commit directly to it.
- **Conventional Commits**, subject-only where possible: `type(scope): subject`. Types in use: `feat`, `fix`, `chore`, `docs`, `test`, `ci`.
- **No AI signatures, no "Generated by", no `Co-Authored-By` trailers** in commit messages.
- Keep PRs focused. Security-sensitive changes (credential handling, command execution) get closer review and may need explicit testing evidence — see `CONTRIBUTING.md`.
- PR approval requirements: TODO — no `CODEOWNERS` file exists.

## Gotchas

Most of these will break a build, a release, or production if ignored. The last two are different in kind — known debt and one unconfirmed suspicion — and are labelled as such so they are not mistaken for work to pick up.

- **SFTP local paths are relative to `transfer_root`, not absolute (0.6.0, breaking).** `upload_file`/`download_file` reject absolute paths and `..`. Local files are opened one component at a time beneath a pinned root fd, refusing symlinks at *every* component, and `sftp.get`/`sftp.put` are deliberately never used — they re-resolve the path inside asyncssh, which is what made arbitrary writes to the operator's machine possible. Do not "simplify" this back to a path string. Four behaviour contracts ride along and are easy to break by accident: download is **no-clobber** (`O_CREAT|O_EXCL`) and *raises* rather than overwriting an existing local file; a failed download unlinks its own partial file via `_unlink_beneath`, which proves inode identity so a concurrent rename cannot redirect the unlink; intermediate directories under `transfer_root` must already exist — neither tool creates them (documented in the `upload_file`/`download_file` docstrings); and both directions refuse non-regular remote files via `sftp.stat(follow_symlinks=False)`. `transfer_root` itself is created `0700`, must be owned by the running user and must not be a symlink, and the whole subsystem is **POSIX-only** — `paths.py::ensure_root` fails closed without `dir_fd`/`O_NOFOLLOW`, so SFTP does not work on Windows at all.

- **Do not optimise `_redact_secrets` without running the adversarial tests.** It has had four implementations; the first was a denial of service and the next two leaked credentials. A quadratic regex was a DoS; bounding the quantifiers made it stop matching past the bound; a positional scanner skipped a credential flag that followed a boolean flag (`docker run --rm --password=X`). It is now a token-wise scan where every token is classified independently, which is what makes skipping impossible. Redaction covers the **command string only, never command output**, and multi-word quoted values are only partially redacted — it is a tripwire, and the documented mitigation is to pass credentials via env files or stdin rather than argv.

- **Never lower the `asyncssh` log levels — that suppression *is* a credential control.** `server.py::_configure_logging` raises the `asyncssh`, `asyncssh.sftp` and `asyncssh.connection` loggers to WARNING because asyncssh logs the full raw command, credentials included, at INFO via its own channel logger. That is "Production incident 2026-04-11 (round 2)", and `_redact_secrets` did **not** fix it: redaction only sanitizes the ssh-mcp logger, so the password leaked anyway. Turning those loggers back down to INFO to debug an SSH problem reopens the leak. Note also that `_configure_logging()` is called at *import* time and clears root handlers, so anything configuring logging around it will be overwritten.

- **The dangerous-command list is a tripwire, not a security boundary.** `README.md` and `SECURITY.md` say so explicitly, and base64 / hex-escape / homoglyph / `$(...)` bypasses are acknowledged. Do not describe it as a security control, and do not widen it into a claim it cannot keep.

- **`ssh-mcp --version` and `--help` do not exist.** `main()` in `server.py` inspects only `sys.argv[1] == "healthcheck"`; anything else falls through and starts the MCP server on stdin. `CONTRIBUTING.md` no longer tells bug reporters to run it (it now points at `import ssh_mcp; ssh_mcp.__version__` or `pip show blc-ssh-mcp`), but `release.yml` still smoke-tests artifacts with `ssh-mcp --help` — that test exits 0 only because CI closes stdin, so it verifies the entry point imports and nothing more. Fix the flags or fix both callers; do not assume the smoke test is meaningful.

- **`uv sync` must use `--locked` in CI, and lint tools must run via `uv run`, never `uvx`.** `uvx` resolves the newest release at run time: ruff 0.16.0 widened its default rule set from 59 to 413 rules and turned CI red on commits that had passed days earlier. `[tool.ruff.lint] select` therefore pins the rule set explicitly — widening it is a deliberate decision, not a cleanup. `tests/test_ci_lint_determinism.py` enforces all of this.

- **The `docker` job must keep `needs: [test, lint, audit]`.** Dropping `audit` lets an image with a known-vulnerable dependency reach GHCR. A regression test asserts it. Note the asymmetry: that `needs:` gates the **entire `docker` job** — PR build-and-scan included, and therefore any image publish —, but whether a red `audit` blocks a **PR merge** depends on it being listed in branch-protection required checks — which is repository configuration, not something in this repo. Do not assume a failing audit prevents a merge.

- **`max_output_bytes` is enforced per stream**, so stdout + stderr together can reach 2× the configured value. It bounds allocation (output is consumed incrementally and the process terminated), not just the returned string.

- **`known_hosts = false` in `servers.toml` disables host-key verification** and therefore MITM protection. The loader logs a warning; do not add a code path that sets it implicitly.

- **`.gitleaksignore` fingerprints are commit-scoped.** They cover synthetic credential fixtures in `tests/test_ssh.py::TestRedactSecrets`. Regenerate from a real `gitleaks` run rather than hand-editing, and never add an entry outside `tests/`.

- **A test that touches config resolution must pin `$HOME` *and* `$XDG_CONFIG_HOME`.** `_get_config_path` consults `$XDG_CONFIG_HOME` first; GitHub runners set it and macOS usually does not, so pinning only `$HOME` produces a test that passes locally and fails in CI while resolving the developer's real config. The same class applies to inode-identity assertions: create a replacement file *before* unlinking the original, because ext4 reuses the freed inode number and APFS does not.

- **`docs/` is gitignored** — along with `wiki/`, `claude/`, `codex/`, `.codex/`, `.claude/`, `logs/` and `.mcp.json`, all local-only working directories. Do not add a *new* reference to any of them from committed documentation or code. Two comments in `ssh.py` already cite one (`grep -n "01-approach" src/ssh_mcp/ssh.py`); they are pre-existing dangling references, not a pattern to follow. Note that gitignoring a directory does not untrack files already committed under it.

- **`server.py` chains the MCP session-manager lifespan via the SDK's public `FastMCP.session_manager`.** An earlier version reached into Starlette's private `router.lifespan_context`; do not go back to it.

- **Known architectural debt** (verified by reading the code, not defects): `ssh.py` mixes security *policy* (redaction rules, dangerous-command patterns, sensitive paths) into the module that owns SSH transport and connection pooling; and the two `ExecResult` error contracts described under Conventions remain deliberately inconsistent. Both are known and intentional-for-now, not bugs to opportunistically "fix" mid-task.

- **One suspected defect, NOT confirmed — do not act on it without reproducing it first.** `TODO:` a bastion's `_last_used` appears to refresh only when a *child* connection is created, so a reused jump-host tunnel may look idle and be evicted while still carrying traffic. This was never reproduced against a live tunnel and has no test or issue id. Verify before changing eviction logic.

## Permission Boundaries for AI Agents

The dev loop is safe; **operating the tool is not**. Running the test suite touches nothing outside the repo. Invoking the MCP tools reaches real machines.

**Always allowed**
- Read any file; run `pytest`, `ruff`, `mypy`, `bandit`, `pip-audit`
- `git status` / `diff` / `log` / `branch`
- Edit code and tests, and build (`uv build`)

**Ask first**
- Changing anything under `.github/workflows/`, the `Dockerfile`, or `compose.yaml`
- Bumping dependencies, or editing `uv.lock` / `pyproject.toml` version floors
- Widening `[tool.ruff.lint] select`, or adding a `.gitleaksignore` or `.trivyignore` entry — a `.trivyignore` line suppresses the CRITICAL-severity Trivy gate standing between a build and GHCR
- Editing `SECURITY.md`, or the security-policy tables in `ssh.py` (`_DANGEROUS_PATTERNS`, `_SENSITIVE_PATHS`, the redaction rules)

**Never without explicit approval**
- **Calling the MCP tools against a real server** — `execute`, `execute_on_group`, `upload_file`, `download_file` run commands on live hosts. Use tests and fakes.
- Reading, writing, or copying `~/.ssh/config`, `~/.ssh/*`, or `~/.config/ssh-mcp/servers.toml` — these hold real infrastructure details and key paths
- `git push`, force-push, branch deletion, or committing to `main`
- **Anything that lands a commit on `main` — merging a PR publishes a container image.** `ci.yml`'s `docker` job sets `PUBLISH=true` for pushes to `refs/heads/main` *as well as* `refs/tags/v*`, with **no environment gate**, so `latest` reaches GHCR with no human approval. Publishing is not gated on tagging.
- **Creating a `v*` tag — it publishes twice.** A tag starts *both* workflows: `release.yml` (PyPI, behind the reviewer-gated `pypi` environment) **and** `ci.yml`'s ungated `docker` job. Do not treat a tag as safe merely because PyPI asks for a reviewer.
- Rotating or printing any credential, or adding a real hostname to a tracked file
- `docker push`, or anything that publishes an artifact
