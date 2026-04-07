# ssh-mcp Improvement Plan

> Generated from Red Team Round 1 analysis (2026-04-06).
> 3 agents analyzed the full codebase: mock fidelity, path tracing, architecture review.
> 21 unique findings: 3 CRITICAL, 9 HIGH, 7 MEDIUM, 10 LOW.

---

## Phase 1: Security Fixes (Priority: Immediate)

### 1.1 Validate local paths in SFTP operations

**Finding:** `upload()` and `download()` validate `remote_path` but NOT `local_path`. An LLM caller can read `/etc/shadow` or `~/.ssh/id_rsa` from the MCP host via upload, or overwrite arbitrary local files via download.

**Files to modify:**
- `src/ssh_mcp/ssh.py` — add `_validate_local_path(path: str)` function

**Implementation:**
- Create `_validate_local_path()` with the same sensitive-path blocking as `_validate_remote_path()`
- Add path-traversal detection (`..` in path)
- Block read/write to known sensitive local paths (SSH keys, `/etc/shadow`, `/etc/passwd`)
- Call it in `upload()` before `sftp.put()` and in `download()` before `sftp.get()`
- Add corresponding unit tests in `tests/test_ssh.py`

**Tests:**
- Verify sensitive local paths are blocked for upload source
- Verify sensitive local paths are blocked for download destination
- Verify path traversal in local paths is blocked
- Verify normal local paths are allowed

---

### 1.2 Fix `_cleanup_connections()` — replace `asyncio.run()` in atexit

**Finding:** `asyncio.run()` inside an `atexit` handler crashes when FastMCP's event loop is still running or already torn down. SSH connections are never cleaned up on exit.

**Files to modify:**
- `src/ssh_mcp/server.py` — rewrite `_cleanup_connections()`

**Implementation:**
- Detect if an event loop is currently running via `asyncio.get_event_loop()`
- If running: schedule `_ssh.close_all()` on the existing loop
- If not running: use `asyncio.run()` as a last resort
- Wrap the entire cleanup in a try/except to guarantee silent failure at worst
- Consider replacing atexit with a signal handler or FastMCP lifecycle hook if available

```python
def _cleanup_connections() -> None:
    global _ssh
    if _ssh is None:
        return
    try:
        loop = asyncio.get_running_loop()
        loop.create_task(_ssh.close_all())
    except RuntimeError:
        try:
            asyncio.run(_ssh.close_all())
        except Exception as e:
            logger.warning(f"Error during connection cleanup: {e}")
```

---

### 1.3 Fix `_init()` race condition — add lock on lazy globals

**Finding:** No lock protects the `if _registry is None` check. Concurrent MCP tool calls can create duplicate registries/managers, duplicate eviction loops, and duplicate atexit handlers.

**Files to modify:**
- `src/ssh_mcp/server.py` — add `asyncio.Lock` around `_init()`

**Implementation:**
- Add a module-level `_init_lock = asyncio.Lock()` (or use `asyncio.Lock` created lazily)
- Wrap the entire `_init()` body in `async with _init_lock:`
- Change `_init()` to `async def _init()`
- Update all 6 MCP tool callers to `await _init()`

---

## Phase 2: Bug Fixes (Priority: High)

### 2.1 Fix `execute_on_group` fail_fast task leakage

**Finding:** Cancelled tasks are never awaited after `fail_fast` triggers. Partial results are returned with no indication of skipped servers.

**Files to modify:**
- `src/ssh_mcp/ssh.py` — `execute_on_group()` fail_fast branch

**Implementation:**
- After cancelling remaining tasks, await them with `return_exceptions=True` to drain
- Append cancelled-server entries to results (with a clear error message like "Cancelled: fail_fast triggered")
- Ensure the formatted output shows which servers were skipped

```python
if fail_fast:
    actual_tasks = [asyncio.create_task(coro) for coro in tasks]
    results = []
    for future in asyncio.as_completed(actual_tasks):
        result = await future
        results.append(result)
        if result.error or (result.exit_code is not None and result.exit_code != 0):
            for task in actual_tasks:
                if not task.done():
                    task.cancel()
            # Drain cancelled tasks
            for task in actual_tasks:
                if task.cancelled() or not task.done():
                    try:
                        await task
                    except asyncio.CancelledError:
                        pass
            break
    return results
```

---

### 2.2 Fix connection eviction TOCTOU race

**Finding:** Eviction loop reads `_last_used` outside the lock, then acquires the lock to evict. A connection refreshed between snapshot and lock acquisition gets killed mid-use.

**Files to modify:**
- `src/ssh_mcp/ssh.py` — `_eviction_loop()`

**Implementation:**
- Move the idle-time freshness check INSIDE the per-server lock
- Re-read `_last_used[server_name]` after acquiring the lock
- Only proceed with eviction if the connection is STILL idle after lock acquisition

```python
async with lock:
    # Re-check freshness inside lock
    current_last_used = self._last_used.get(server_name)
    if current_last_used is None:
        continue
    current_idle = now - current_last_used
    if current_idle <= idle_threshold:
        continue  # Connection was refreshed while we waited for lock
    # Proceed with eviction...
```

---

### 2.3 Fix `_start_eviction_loop` inconsistent state

**Finding:** Sets `_running = True` before `create_task()`. If `create_task` fails, `_running` stays `True` but no task runs. Connections accumulate forever.

**Files to modify:**
- `src/ssh_mcp/ssh.py` — `_start_eviction_loop()`

**Implementation:**
- Set `_running = True` AFTER `create_task()` succeeds
- On failure, ensure `_running` stays `False`

```python
def _start_eviction_loop(self) -> None:
    if self._running:
        return
    self._eviction_task = asyncio.create_task(self._eviction_loop())
    self._running = True
```

---

### 2.4 Fix `format_group_results` count gap

**Finding:** `exit_code=None, error=None` case increments neither `succeeded` nor `failed`, causing silent mismatch in summary totals.

**Files to modify:**
- `src/ssh_mcp/formatting.py` — `format_group_results()`

**Implementation:**
- Treat `exit_code=None` with no error as "unknown" and count it as failed (conservative)
- Or add an "unknown" counter to the summary

```python
if result.error:
    failed += 1
else:
    if result.exit_code == 0:
        succeeded += 1
    else:
        failed += 1  # includes exit_code=None (unknown)
```

---

### 2.5 Add `force` parameter to `execute_on_group` MCP tool

**Finding:** `SSHManager.execute_on_group` accepts `force` but the MCP tool never passes it. Group execution can never bypass dangerous command detection.

**Files to modify:**
- `src/ssh_mcp/server.py` — `execute_on_group()` tool function

**Implementation:**
- Add `force: bool = False` parameter to the MCP tool signature
- Pass it through to `_ssh.execute_on_group()`
- Match the same docstring pattern as `execute()` tool

---

## Phase 3: Test Coverage (Priority: High)

### 3.1 Add `tests/test_server.py` — MCP tool integration tests

**Finding:** All 6 MCP tools have zero test coverage. The entire public API is untested.

**Files to create:**
- `tests/test_server.py`

**Tests to write:**
- `_get_config_path()` — all 3 fallback branches + FileNotFoundError
- `_init()` — successful initialization, double-init idempotency
- `list_servers()` — with/without group filter, empty results, invalid group
- `list_groups()` — normal case, empty groups
- `execute()` — mock SSHManager, verify delegation, error handling
- `execute_on_group()` — mock SSHManager, verify delegation, error handling
- `upload_file()` / `download_file()` — mock SSHManager, verify delegation, error handling
- All error paths returning `f"Error ...:"` strings

**Approach:**
- Mock `ServerRegistry` and `SSHManager` at the module level
- Use `monkeypatch` to inject test globals into `server.py`
- Test each tool as an async function call

---

### 3.2 Add async tests for SSHManager methods

**Finding:** `execute()`, `execute_on_group()`, `upload()`, `download()`, `_get_connection()`, `_eviction_loop()` are all untested.

**Files to modify:**
- `tests/test_ssh.py` — add async test classes

**Tests to write:**
- `execute()` — successful command, timeout, dangerous command blocked, `force=True` bypass, working_dir handling, output truncation
- `execute_on_group()` — parallel execution, fail_fast behavior, empty group, force parameter
- `upload()` / `download()` — successful transfer, path validation integration, error handling
- `_get_connection()` — new connection, cached connection, stale connection reconnect, jump host recursion, max depth limit
- `_eviction_loop()` — idle eviction, freshness re-check, graceful cancellation
- `close_all()` — closes all connections, stops eviction task

**Approach:**
- Mock `asyncssh.connect()` and `asyncssh.SSHClientConnection`
- Use `pytest-asyncio` for async test execution
- Create fixtures for mock connections

---

### 3.3 Add missing unit tests

**Files to modify:**
- `tests/test_ssh.py` — force=True bypass test, path validation integration
- `tests/test_config.py` — circular jump host detection, unknown settings keys
- `tests/test_formatting.py` — `exit_code=None, error=None` case

---

## Phase 4: Dockerfile & Docker Compose

### 4.1 Create multi-stage Dockerfile

**Files to create:**
- `Dockerfile`

**Implementation:**
```dockerfile
# syntax=docker/dockerfile:1
FROM ghcr.io/astral-sh/uv:python3.13-bookworm-slim AS builder

WORKDIR /app
COPY pyproject.toml uv.lock ./
RUN uv sync --no-dev --frozen

COPY src/ src/

FROM python:3.13-slim-bookworm AS runtime

RUN groupadd --gid 1000 sshmcp && \
    useradd --uid 1000 --gid sshmcp --create-home sshmcp

WORKDIR /app
COPY --from=builder /app/.venv /app/.venv
COPY --from=builder /app/src /app/src

ENV PATH="/app/.venv/bin:$PATH"
ENV SSH_MCP_CONFIG="/config/servers.toml"

USER sshmcp

ENTRYPOINT ["ssh-mcp"]
```

**Key decisions:**
- Multi-stage build: uv for dependency resolution, slim runtime image
- Non-root user `sshmcp` for security
- SSH keys and config mounted at runtime (never baked in)
- `SSH_MCP_CONFIG` env var points to mounted config
- stdio transport works with `docker run -i`

---

### 4.2 Create docker-compose.yml

**Files to create:**
- `docker-compose.yml`

**Implementation:**
```yaml
services:
  ssh-mcp:
    build: .
    stdin_open: true
    volumes:
      - ./config/servers.toml:/config/servers.toml:ro
      - ~/.ssh:/home/sshmcp/.ssh:ro
    environment:
      - SSH_MCP_CONFIG=/config/servers.toml
```

**Key decisions:**
- `stdin_open: true` for MCP stdio transport
- SSH keys mounted read-only from host
- Config file mounted read-only
- No port exposure needed (stdio transport)

---

### 4.3 Create .dockerignore

**Files to create:**
- `.dockerignore`

**Contents:**
```
.git
.venv
__pycache__
*.pyc
.pytest_cache
.ruff_cache
dist
logs
tests
.github
.claude
*.md
!README.md
```

---

## Phase 5: CI/CD Enhancements

### 5.1 Add Docker build job to CI

**Files to modify:**
- `.github/workflows/ci.yml`

**Implementation:**
- Add `docker` job that builds the image on every push/PR
- Use `docker/build-push-action@v6` with cache
- Build-only on PRs, build+push on main (to GHCR)
- Add Trivy container scanning

```yaml
docker:
  name: Docker Build
  runs-on: ubuntu-latest
  steps:
    - uses: actions/checkout@v4
    - uses: docker/setup-buildx-action@v3
    - uses: docker/build-push-action@v6
      with:
        context: .
        push: false
        load: true
        tags: ssh-mcp:test
        cache-from: type=gha
        cache-to: type=gha,mode=max
    - uses: aquasecurity/trivy-action@master
      with:
        image-ref: ssh-mcp:test
        severity: CRITICAL,HIGH
```

---

### 5.2 Add security scanning to CI

**Files to modify:**
- `.github/workflows/ci.yml`

**Implementation:**
- Add `pip-audit` step after dependency install (scans for known CVEs in dependencies)
- Add `bandit` step for Python source code security analysis

```yaml
- name: Audit dependencies
  run: uvx pip-audit --requirement <(uv export --no-hashes)

- name: Security scan
  run: uvx bandit -r src/ -c pyproject.toml
```

---

### 5.3 Add type checking to CI

**Files to modify:**
- `.github/workflows/ci.yml`
- `pyproject.toml` — add mypy config

**Implementation:**
- Add `mypy` step to lint job
- Configure mypy in `pyproject.toml` with strict mode for `src/`

---

### 5.4 Add test coverage reporting

**Files to modify:**
- `.github/workflows/ci.yml`
- `pyproject.toml` — add pytest-cov to dev deps

**Implementation:**
- Add `--cov=ssh_mcp --cov-report=term-missing --cov-fail-under=80` to pytest
- Enforce minimum coverage threshold

---

## Phase 6: Lower-Priority Improvements

### 6.1 Use structured MCP error responses

**Files to modify:**
- `src/ssh_mcp/server.py` — all 6 tool functions

**Change:** Replace `return f"Error ...: {e}"` with proper MCP error raising so callers can distinguish errors from output programmatically.

### 6.2 Improve dangerous command detection

**Files to modify:**
- `src/ssh_mcp/ssh.py` — `_DANGEROUS_PATTERNS`

**Change:** Add patterns for common bypass vectors: split flags (`rm -r -f`), `bash -c`, `eval`, backtick substitution. Document that this is defense-in-depth, not a security boundary.

### 6.3 Add `asyncssh` upper bound

**Files to modify:**
- `pyproject.toml`

**Change:** `asyncssh>=2.14.0,<3.0.0` to prevent breaking changes.

### 6.4 Fix SFTP partial upload (atomic rename)

**Files to modify:**
- `src/ssh_mcp/ssh.py` — `upload()`

**Change:** Upload to a temp file (e.g., `remote_path + ".tmp"`), then rename on success. On failure, clean up the temp file.

### 6.5 Add Python 3.14 to CI matrix (when stable)

**Files to modify:**
- `.github/workflows/ci.yml`
- `pyproject.toml` — add classifier

---

## Implementation Order

```
Phase 1 (Security)     ← Do first, smallest blast radius
  1.1 Local path validation
  1.2 Atexit cleanup fix
  1.3 _init() race condition fix

Phase 2 (Bug Fixes)    ← Fix broken behavior
  2.1 fail_fast task leakage
  2.2 Eviction TOCTOU
  2.3 Eviction start state
  2.4 Group results count gap
  2.5 Missing force parameter

Phase 3 (Tests)         ← Verify all fixes + cover gaps
  3.1 test_server.py (MCP tools)
  3.2 Async SSH tests
  3.3 Missing unit tests

Phase 4 (Docker)        ← Containerize
  4.1 Dockerfile
  4.2 docker-compose.yml
  4.3 .dockerignore

Phase 5 (CI/CD)         ← Harden pipeline
  5.1 Docker build job
  5.2 Security scanning
  5.3 Type checking
  5.4 Coverage reporting

Phase 6 (Polish)        ← Nice-to-have
  6.1–6.5 as time permits
```

---

## Estimated Scope

| Phase | Files Created | Files Modified | Commits |
|-------|--------------|----------------|---------|
| 1     | 0            | 2              | 3       |
| 2     | 0            | 2              | 5       |
| 3     | 1            | 3              | 3       |
| 4     | 3            | 0              | 1       |
| 5     | 0            | 2              | 4       |
| 6     | 0            | 3              | 3–5     |
| **Total** | **4**    | **12**         | **19–21** |
