# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.5.1] - 2026-04-12

### Changed

- **Pure ASGI bearer middleware.** R5 finding #1: replaced Starlette's `BaseHTTPMiddleware` (known body-copying issues, SSE streaming breakage, memory leaks) with a zero-dependency pure ASGI middleware that implements the `__call__(scope, receive, send)` protocol directly. Non-HTTP scopes (lifespan, websocket) pass through unchanged.
- **Deleted `_wrap_with_bearer_auth` dead code.** R5 finding #2: removed ~50 lines of unused code that duplicated the bearer middleware logic. Tests refactored to use `_build_http_app` and `_make_bearer_auth_middleware` directly.
- **`execute_on_group` fail_fast now reports cancelled servers.** R5 finding #9: previously, `fail_fast=True` silently dropped cancelled server results — operators saw a partial result set with no indication that other servers were skipped. Now appends `ExecResult(error="Cancelled: fail_fast triggered by an earlier failure")` for every server whose task was cancelled, so the full server list always appears in the output.
- **mypy strict mode expanded.** R5 finding #14: added `no_implicit_reexport`, `warn_redundant_casts`, `warn_unused_ignores`, `strict_equality` to `[tool.mypy]` config.
- **CI matrix adds Python 3.14.** R5 finding #15: test matrix now covers `["3.11", "3.12", "3.13", "3.14"]`, matching the `pyproject.toml` classifier.
- **ExecResult error contract documented.** R5 finding #16: comprehensive docstring explaining the error/exit_code state matrix and the distinct SFTP contract.

### Added

- 17 new tests: 4 exception-taxonomy tests (asyncssh.DisconnectError, PermissionDenied, OSError, TimeoutError), 6 tool-signature-stability tests, 3 fail_fast-cancelled-results tests, reworked bearer middleware tests for pure ASGI.

## [0.5.0] - 2026-04-12

### Security

- **dry_run preview now redacts credentials.** R5 finding #4: `execute(..., dry_run=True, command="mysql -pSecret ...")` previously returned the raw command in the preview stdout. Now applies `_redact_secrets()` to the preview string.
- **All f-string log calls converted to %-style with `_safe_log_value`.** R5 finding #5: 7 `logger.error(f"...")` calls in `_create_connection`, eviction loop, and group execution bypassed `_safe_log_value` — attacker-controlled SSH banners could inject forged log lines. All 7 now use `%s` + `_safe_log_value(str(e))`.

### Fixed

- **Eviction loop auto-restarts after crash.** R5 finding #6: if the eviction loop raised an unexpected exception, `_running` stayed `True` and the loop was permanently dead — connections accumulated without eviction until fd exhaustion. Now resets `_running = False` in the except block so the next `_get_connection()` call restarts the loop.
- **`close_all()` prunes `_locks` dict.** R5 finding #11: `self._locks` was never cleared by `close_all()` or eviction, causing monotonic memory growth. Now both paths call `.pop()` / `.clear()` on `_locks`.
- **`atexit` handler simplified.** R5 finding #3: removed dead `loop.create_task()` branch (event loop is always torn down before `atexit` fires). Guarded registration with `_atexit_registered` flag to prevent stacking.
- **FastMCP lifespan coupling assertion.** R5 finding #8: `_build_http_app` now validates that `inner_app.router.lifespan_context` is callable at startup. If the MCP SDK restructures its internals, the server crashes immediately with a clear error instead of silently returning 500 on every request.
- **`max_output_bytes` docstring corrected.** R5 finding #10: the enforcement is character-based (`len(str)`), not byte-based. Docstring updated to reflect the actual behavior honestly.

## [0.4.3] - 2026-04-12

### Security

- **Broaden credential redaction coverage.** v0.4.1 covered an enumerated list of env var names; v0.4.3 adds generic **suffix-pattern matching** for env vars ending in `_PASSWORD`, `_SECRET`, `_TOKEN`, `_KEY`, `_CREDENTIAL`, `_PWD` — so `VAULT_TOKEN=`, `STRIPE_SECRET_KEY=`, `MY_CUSTOM_PASSWORD=`, `DOCKER_PASSWORD=`, etc. are all caught without needing to maintain a static list.
- **Variant long-flag redaction.** `--db-password=`, `--admin-password=`, `--user-password=`, `--access-key=`, `--secret-key=`, `--auth-token=`, `--http-password=` (wget), and ANY other `--<prefix>-password/secret/token/key/credential=` pattern is now redacted. Previously only exact `--password` / `--token` / `--secret` / `--api-key` were matched.
- **New tool-specific patterns.** `curl -u user:password`, `sshpass -p PASSWORD` (space-separated), and `wget --http-password` are now redacted.
- **OTel `ssh.error` span attribute** now runs through `_redact_secrets()` before being set on the span, closing the trace-backend leak path identified in green-team round 1 (G5).
- **README security section** now explicitly documents that command OUTPUT (stdout/stderr) is NOT redacted — operators should never run commands that print secrets via ssh-mcp.

## [0.4.2] - 2026-04-11

### Security

- **CRITICAL: Silence asyncssh INFO-level command logging.** Production verification of v0.4.1 revealed a SECOND credential leak: `asyncssh` itself logs every dispatched command at INFO level via its internal channel logger as `[conn=N, chan=N] Command: <raw>`. The v0.4.1 redaction only covered the ssh-mcp audit log, not asyncssh's logger hierarchy, so passwords like `mysql -p<pass>` continued to leak into the structured stderr stream and centralized log aggregators despite the v0.4.1 fix.
- `_configure_logging` now raises the `asyncssh`, `asyncssh.sftp`, and `asyncssh.connection` logger levels to `WARNING` so per-command INFO records never reach the root handler. Real failures (connection errors, channel errors, etc.) still propagate as warnings/errors.
- 2 new regression tests verify (a) the asyncssh logger level is `>= WARNING` after `_configure_logging` runs and (b) a simulated asyncssh INFO record does not propagate to root.

## [0.4.1] - 2026-04-11

### Security

- **CRITICAL: Redact credentials from audit logs and error messages.** Production incident 2026-04-11: the `audit.info` call site in `SSHManager.execute` interpolated the raw `command` value, so `mysql -h host -u admin -pSecretPwd` shipped the plaintext password to stderr, which was then forwarded to centralized log aggregators (Loki/Datadog/Splunk) and visible to every operator with log access. New `_redact_secrets()` helper applies an ordered regex pipeline that replaces known credential patterns with `{REDACTED}` before reaching any logger. Covers:
  - MySQL/MariaDB short flag `-pValue` (quoted and unquoted forms)
  - Long flags `--password=`, `--pass=`, `--token=`, `--secret=`, `--api-key=`, both `=` and whitespace separator, all case-insensitive
  - Known credential env vars: `PGPASSWORD`, `MYSQL_PWD`, `REDIS_PASSWORD`, `MONGODB_PASSWORD`, `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN`, `GH_TOKEN`, `GITHUB_TOKEN`, `GITLAB_TOKEN`, `NPM_TOKEN`, `GCP_API_KEY`, `AZURE_CLIENT_SECRET`, `TOKEN`, `API_KEY`, `API_TOKEN`, `SECRET`, `SECRET_KEY`, `BEARER_TOKEN`, `ACCESS_TOKEN`, `REFRESH_TOKEN`, `CLIENT_SECRET`, `PRIVATE_KEY`, plus variants
  - HTTP `Authorization: Bearer/Basic/Digest/Token <value>` headers
  - Basic auth URLs `scheme://user:password@host` (user preserved, password redacted)
- Applied to the audit log on success, the audit log on timeout, and both the dangerous-command block and timeout `logger.error` lines. Redaction is idempotent (the placeholder doesn't match any rule) so repeated passes produce identical output.
- 28 regression tests including 2 Hypothesis property tests to fuzz the redaction pipeline on arbitrary input.

### Fixed

- **CRITICAL: Prevent file descriptor exhaustion under bursty HTTP traffic.** Production incident 2026-04-11: the container crashed with `OSError(24, 'Too many open files')` on `socket.accept()` because uvicorn's default `timeout_keep_alive=5s` combined with bursty n8n HTTP/1.1 traffic accumulated ~110 ESTABLISHED connections, eventually exceeding the Docker default 1024 fd limit. New tuning knobs with safer defaults:
  - `SSH_MCP_HTTP_KEEPALIVE_TIMEOUT` — default **2s** (down from uvicorn's 5s). Closes idle HTTP/1.1 connections fast enough that ephemeral n8n-style clients don't pile up sockets.
  - `SSH_MCP_HTTP_LIMIT_CONCURRENCY` — default **256**. Rejects new requests with HTTP 503 once 256 are in flight, preventing unbounded growth under burst load.
  - `SSH_MCP_HTTP_BACKLOG` — default **128**. Smaller listen backlog caps SYN-flood exposure.
- Validation at startup: non-numeric, negative, or zero-concurrency values raise `RuntimeError` with the offending env var name.
- README deployment section now documents `ulimits.nofile: 65536` as the Docker compose mitigation for the 1024 fd default.
- Compose `ssh-mcp-http` example template updated with `ulimits` block and tuning env var comments.

### Changed

- `SSHManager._execute_impl` now calls `_redact_secrets(command)` in every log interpolation path. OTel `ssh.command_length` attribute is unchanged (length-only, already privacy-safe).

## [0.4.0] - 2026-04-09

### Added

- **Optional HTTP authentication mode (`SSH_MCP_HTTP_AUTH`)** — set to `none` to disable the built-in bearer middleware entirely. Intended for deployments where a trusted reverse proxy (Caddy, nginx, Traefik, Envoy, Cloudflare Access, etc.) handles authentication at the edge.
- **`SSH_MCP_HTTP_NETWORK_NO_AUTH=I_ACCEPT_RCE_RISK` escape hatch** — required when combining `SSH_MCP_HTTP_AUTH=none` with a non-localhost bind. Deliberately verbose magic-string value so no operator sets it by accident. Without the exact match, `_run_http` raises with a detailed explanation of the risk.
- Startup now logs a loud warning banner whenever ssh-mcp is running without authentication on a non-localhost bind.
- README has a new "Reverse proxy deployment" subsection with a concrete Docker command and a three-point checklist before opting into no-auth mode.

### Changed

- `SSH_MCP_HTTP_TOKEN` is no longer always required for non-localhost binds — it's only required when `SSH_MCP_HTTP_AUTH` is `bearer` (the default). Existing deployments are unaffected because `bearer` is the default mode.
- When `SSH_MCP_HTTP_AUTH=none` is set, any stray `SSH_MCP_HTTP_TOKEN` value is ignored so operators can't accidentally mix modes.

### Security

- The no-auth mode is safe by default: localhost binds work with a plain warning, but non-localhost binds refuse to start unless the operator explicitly sets `SSH_MCP_HTTP_NETWORK_NO_AUTH=I_ACCEPT_RCE_RISK`. This is a deliberate design: the escape hatch requires the operator to physically type the words "I ACCEPT RCE RISK" before ssh-mcp serves unauthenticated traffic to a network.

## [0.3.1] - 2026-04-09

### Fixed

- **CRITICAL: HTTP transport returned 500 on every authenticated request** — the graceful-shutdown lifespan wrapper introduced in v0.3.0 mounted the FastMCP streamable HTTP app as a sub-app and added its own Starlette lifespan. Starlette only runs top-level lifespans, so the FastMCP session manager's task group was never initialized and every request to `/mcp` failed with `RuntimeError('Task group is not initialized. Make sure to use run().')`. Fixed by collapsing the bearer middleware + shutdown-lifespan + FastMCP mount into a **single outer Starlette app** whose lifespan explicitly chains the FastMCP session-manager lifespan via `inner_app.router.lifespan_context(inner_app)`.
- Regression test `test_authenticated_request_reaches_initialized_session_manager` drives an authenticated request through the real FastMCP app and asserts the task-group error does not appear in the response body.
- Test-isolation fixture resets `mcp._session_manager` between tests so `StreamableHTTPSessionManager.run()` (which can only be called once per instance) works across multiple `TestClient` invocations.

## [0.3.0] - 2026-04-09

### Added

- **MCP streamable HTTP transport** — set `SSH_MCP_TRANSPORT=http` (or `streamable-http`) to run ssh-mcp as a network service over the official MCP streamable HTTP transport instead of the default stdio subprocess transport. Includes bearer-token authentication, DNS-rebinding protection via the SDK's `TransportSecuritySettings`, and a Starlette lifespan handler that drains pooled SSH connections on graceful shutdown (SIGTERM).
- **Bearer-token authentication middleware** — `SSH_MCP_HTTP_TOKEN` configures a shared secret. Uses `hmac.compare_digest` for constant-time comparison. Scheme is case-insensitive per RFC 7235. Minimum token length 16 chars enforced at startup. Trailing whitespace stripped so `.env` files with newlines work as expected.
- **Safety gate** — non-localhost binds (`0.0.0.0`, LAN IPs, public IPs, `::`, link-local) raise `RuntimeError` at startup unless `SSH_MCP_HTTP_TOKEN` is set. Loopback detection uses `ipaddress.ip_address().is_loopback` so all IPv4/IPv6 loopback forms (including `::ffff:127.0.0.1`, `0:0:0:0:0:0:0:1`, and the entire `127.0.0.0/8` block) are correctly classified.
- **Wildcard rejection** — `SSH_MCP_HTTP_ALLOWED_HOSTS=*` or entries like `*:*` are rejected at startup so operators can't silently disable DNS-rebinding protection by accident.
- **OpenTelemetry tracing** — `ssh-mcp[otel]` extra installs the API; spans created for `mcp.tool.*`, `ssh.execute`, `ssh.upload`, and `ssh.download`. Attributes carry host, command/path lengths (never raw content), exit code, duration, and error type. Soft import via `try/except ImportError` means operators without the extra installed pay zero cost.
- **`dry_run` parameter** on `execute` and `execute_on_group` — returns a preview of what would run (server, command, working_dir, timeout, force) without connecting. Dangerous-command detection still runs so rejection can be previewed. When `force=True` bypasses a dangerous match, the preview includes an explicit warning banner.
- **Extended dangerous-command regex** — `rm -rf ~`, `rm -rf $HOME`, `rm -rf ${HOME}`, `rm -rf $USER`, `find / -delete`, `find / -exec rm`, `shred /dev/*`, `wipefs /dev/*`, `blkdiscard /dev/*`, `sgdisk -Z /dev/*`, `parted /dev/* mklabel`, `fdisk /dev/sd*`, `> /etc/passwd`, `> /etc/shadow`, `> /etc/sudoers`, spaced fork-bomb variants. All patterns compiled with `re.IGNORECASE` so `rm -RF /` and `RM -rf /` don't bypass. Flag matchers use lookaheads to tolerate arbitrary orders (`-rfv`, `-vfr`, `-rfvi`).
- **Expanded SFTP sensitive-path allowlist** — blocks AWS/Azure/GCP credential files, Kubernetes configs (`~/.kube/config`, `/etc/kubernetes/`, `/var/lib/kubelet/pki/`), shell credential caches (`.netrc`, `.pgpass`, `.git-credentials`, `.docker/config.json`), `/proc/<pid>/{environ,mem,cmdline,maps,stack,status}`, database data directories, Windows registry files (OpenSSH Windows server). Path normalization via `posixpath.normpath` catches obfuscations like `/etc//shadow` and `/etc/./shadow`.
- **Public key exemption** — `.pub` files are allowed through SFTP validation so public-key distribution works.
- **Connection IDs** — every pooled SSH connection gets a stable `{server}-{pid}-{hex}` identifier bound via structlog contextvars so all log lines from a single session are grep-correlatable.
- **SFTP audit lifecycle logs** — three-stage events (`sftp.{upload,download}.{start,complete,failed}`) per transfer with bytes + duration.
- **Hypothesis property tests** — fuzz `_is_dangerous_command` regex (6 properties, 50 examples dev / 200 CI) and OTel span privacy (verifies arbitrary 16-100 char secrets never appear in span attributes).
- Runtime dependencies: `structlog>=25.5,<26.0`, `orjson>=3.10,<4.0`, `pydantic>=2.10,<3.0`. Optional extra: `ssh-mcp[otel]` → `opentelemetry-api>=1.30,<2.0`.

### Changed

- **`max_parallel_hosts` setting** — `execute_on_group` concurrency cap is configurable (default 10, range 1–100). Previously hardcoded to 10.
- **Structured logging** — `SSH_MCP_LOG_FORMAT=json` emits single-line JSON events via structlog; default is colorized console output. stdlib logger records (including `uvicorn.access`) propagate to root and are formatted by `structlog.stdlib.ProcessorFormatter`.
- **Pydantic v2 config validation** — `Settings`/`ServerConfig`/`GroupConfig` migrated to `pydantic.dataclasses.dataclass` with `extra='forbid'`. Unknown TOML keys surface actionable `ConfigError` messages naming the offending key and the valid keys for the section.
- **MCP tool error handling** consolidated into a single `@_mcp_tool` decorator. Eliminates ~90 lines of duplicated try/except across the 6 tools.
- **Log interpolation sanitization** — all user-controlled values (server names, commands, paths, error messages) are wrapped with `repr()` before interpolation so embedded newlines and control characters can't forge additional log records.
- **Dangerous-command detection documented as a TRIPWIRE, not a security boundary** — README security section explicitly lists known bypass classes (base64, hex escapes, Unicode homoglyphs, subshell indirection) and recommends sandboxing at a lower layer for real isolation.
- `mcp[cli]` lower bound bumped from `>=1.2.0` to `>=1.27.0` — aligns with the April 2026 MCP Dev Summit release.

### Fixed

- **SFTP path validation bypass via `/etc//shadow` and `/etc/./shadow`** — `posixpath.normpath` is now applied before substring matching.
- **Safety gate edge cases** — `::ffff:127.0.0.1`, `0:0:0:0:0:0:0:1`, `127.0.0.2` now correctly classified as loopback via `ipaddress.is_loopback`.
- **Log injection via `server_name` / `command` parameters** with embedded `\n` / `\r\n` — all log interpolations of user-controlled values now go through a sanitizer.
- **Graceful shutdown of HTTP transport** — Starlette lifespan closes the SSH connection pool on shutdown so in-flight tool calls aren't abandoned.
- **Public SSH key files blocked from SFTP** — `.pub` files now exempted from the sensitive-path allowlist.
- **Empty / short bearer tokens silently accepted** — `_wrap_with_bearer_auth` now raises `ValueError` for tokens under 16 chars, closing the latent `hmac.compare_digest("","")` → `True` bypass.

### Security

- **Red Team R3 + R4 + Green Team Round 1** — multiple rounds of adversarial review found and fixed: path normalization bypasses, narrow sensitive-path allowlist, dangerous-command regex case-sensitivity and flag-combination bypasses, `$HOME` / `${HOME}` expansion bypasses, log injection via user values, dry_run+force missing warning, empty/short token bypass, wildcard `ALLOWED_HOSTS` silent disable, safety gate narrow loopback coverage.

## [0.2.0] - 2026-04-08

### Added

- **Pydantic v2 config validation.** `Settings`, `GroupConfig`, and `ServerConfig` are now `pydantic.dataclasses` with `extra='forbid'`. Unknown TOML keys, out-of-range numeric values, and missing required fields all raise a `ConfigError` (ValueError subclass) naming the offending field, its section/host context, and the list of valid keys.
- **SFTP audit lifecycle logs.** `upload_file` and `download_file` now emit three structured events per transfer: `sftp.{upload,download}.start` → `sftp.{upload,download}.complete` (or `.failed`), each tagged with a stable `connection_id` contextvar so a single transfer is grep-correlatable. Failure events include the exception type and elapsed `duration_ms`.
- **`connection_id` contextvar.** Every pooled SSH connection is assigned a stable `{server}-{pid}-{hex}` identifier at first connect and reused until eviction. Bound via structlog contextvars for all operations on that connection.
- **Hypothesis property tests.** `_is_dangerous_command` is fuzz-tested on every CI run with 6 new properties: never-crashes-on-arbitrary-input, rm-rf-always-caught, mkfs-always-caught, dd-always-caught, safe-text-not-flagged, control-char-injection-never-bypasses. `HYPOTHESIS_PROFILE=ci` runs 200 examples per property.
- Hypothesis `>=6.151,<7.0` as a dev dependency.
- Pydantic `>=2.10,<3.0` as a runtime dependency.
- `_EVICTION_LOOP_INTERVAL_S` and `_MAX_JUMP_HOST_DEPTH` module-level constants for discoverability and testability.

### Changed

- `mcp[cli]` lower bound bumped from `>=1.2.0` to `>=1.27.0` — aligns with the April 2026 MCP Dev Summit release that introduced OAuth resource validation (RFC 8707), StreamableHTTP idle timeouts, and the TasksCallCapability backport.
- `Settings` field validation is now enforced by Pydantic `Field(ge=..., le=...)` instead of a manual `__post_init__` guard. Error messages still name the offending field.
- README security section expanded with explicit documentation of: the `force=true` audit trail, the full list of blocked sensitive paths, Hypothesis fuzzing coverage, and a JSON log example including `connection_id`.
- `servers.example.toml` settings fields now have inline comments explaining units, ranges, and tuning guidance for every field.
- `execute` and `execute_on_group` docstrings explicitly call out that `timeout` is in **seconds** and document the 1..3600 / 1..100 ranges.

## [0.1.1] - 2026-04-08

### Added

- `max_parallel_hosts` setting in `[settings]` — configurable concurrency cap for `execute_on_group` (default 10, range 1–100). Previously hardcoded to 10.
- `SSH_MCP_LOG_FORMAT` environment variable — set to `json` for single-line JSON logs (timestamp, level, event, contextvars) suitable for log aggregators. Defaults to colorized human-readable console output.
- `structlog 25.5+` and `orjson 3.10+` as runtime dependencies for structured logging.
- `ConfigError` exception class (subclass of `ValueError`) raised on TOML parse errors, unknown keys, and missing required fields — surfaces the offending key, the section, and the list of valid keys in a single actionable message.
- Docker support: multi-stage `Dockerfile` (python:3.13-slim-trixie + uv) and `compose.yaml` for stdio transport
- Prebuilt Docker image published to `ghcr.io/blackaxgit/ssh-mcp:latest` on main branch merges
- `force` parameter on `execute_on_group` MCP tool (already existed on `execute`) — bypass dangerous-command detection for trusted bulk operations
- Local path validation in `upload_file` and `download_file` — blocks reading/writing sensitive files on the MCP host (`/etc/shadow`, SSH keys, path traversal)
- CI/CD: mypy strict type checking, `pip-audit` dependency scanning, `bandit` security analysis, `pytest-cov` coverage reporting, Trivy container scanning
- Tests for MCP tool functions (`tests/test_server.py`) covering all 6 tools, lazy init race, and error passthrough
- Tests for circular jump-host detection
- Tests for `_is_dangerous_command` bypass attempts (null bytes, control characters, Unicode)
- Range validation in `Settings.__post_init__` — rejects negative `command_timeout`, `max_output_bytes < 1024`, `connection_idle_timeout < 10`, and `max_parallel_hosts` outside `1..100`.

### Changed

- MCP tool error handling consolidated into a single `@_mcp_tool` decorator, eliminating ~90 lines of duplicated `try / except ToolError / except Exception` boilerplate across the 6 tools. Tracebacks are now logged with `exc_info=True`.
- MCP tools now raise `ToolError` on failure instead of returning error strings — proper MCP protocol error signalling with `isError=true`
- `_init()` is now async with `asyncio.Lock` double-checked locking to prevent duplicate initialization under concurrent tool calls
- `_cleanup_connections()` no longer crashes when called while an event loop is running
- Connection eviction loop re-checks idle time inside the per-server lock to prevent TOCTOU races
- `execute_on_group` fail_fast path now drains cancelled tasks with `asyncio.gather(..., return_exceptions=True)` to prevent coroutine leaks
- `format_group_results` explicitly counts `exit_code=None` as failed with a clear `is_success` variable
- `_is_dangerous_command` normalizes ASCII control characters before regex matching to prevent null-byte bypass
- `asyncssh` upper bound added to dependencies: `>=2.14.0,<3.0.0`
- CI pipeline updated to 2026 best practices: `actions/checkout@v6`, `astral-sh/setup-uv@v8.0.0`, `docker/build-push-action@v7`, Trivy pinned by commit SHA

### Fixed

- Unknown TOML keys in `[settings]`, `[groups.*]`, or `[servers.*]` now surface the offending key name AND the list of valid keys, instead of crashing with an opaque `TypeError: unexpected keyword argument`.
- TOML parse errors now include the configuration file path in the error message for faster diagnosis.
- Missing `description` field on a server or group now raises `ConfigError` instead of `KeyError`.
- Dockerfile: use `--no-editable` in `uv sync` so the `ssh_mcp` package is copied into site-packages (previously editable install left a dangling `.pth` file pointing to `/app/src` which doesn't exist in the runtime stage)
- Dockerfile: use same `/app` WORKDIR in builder and runtime stages so console script shebangs resolve correctly
- Dockerfile: HEALTHCHECK uses `python -c "import ssh_mcp"` instead of `ps aux | grep` (the slim image has no `ps` binary)
- Server logs startup banner and config path so operators know the stdio server is ready even before the first tool call
- Eviction loop inconsistent state: `_running = True` now set AFTER `create_task` succeeds

### Security

- Fixed missing local path validation on SFTP upload/download — previously an LLM caller could exfiltrate `/etc/shadow` or SSH keys from the MCP host
- Fixed `asyncio.run()` in atexit handler that could crash or silently fail, leaving SSH connections open after shutdown
- Eliminated race condition in lazy server initialization that could create duplicate `SSHManager` instances and leak connections
- Fixed null-byte and control-character bypass in dangerous command detection (`rm\x00-rf /` was not caught by the regex)

## [0.1.0] - 2026-03-01

### Added

- SSH command execution via `execute` tool — run shell commands on a single configured server
- Parallel execution via `execute_on_group` tool — run a command across all servers in a named group
- SFTP file upload via `upload_file` tool
- SFTP file download via `download_file` tool
- Server inventory via `list_servers` and `list_groups` tools
- TOML-based server configuration at `~/.config/ssh-mcp/servers.toml`
- Server groups for organizing hosts (e.g., production, staging, development)
- Connection pooling — reuses SSH connections across tool calls for performance
- Dangerous command detection — warns before executing destructive commands such as `rm -rf`, disk wipes, and shutdown operations
- SSH config integration — reads host, port, user, and key from `~/.ssh/config`; no credentials stored in the MCP config
- Tilde expansion for config file paths
- Packaged for distribution via PyPI; installable with `uvx ssh-mcp`

[Unreleased]: https://github.com/blackaxgit/ssh-mcp/compare/v0.5.1...HEAD
[0.5.1]: https://github.com/blackaxgit/ssh-mcp/compare/v0.5.0...v0.5.1
[0.5.0]: https://github.com/blackaxgit/ssh-mcp/compare/v0.4.3...v0.5.0
[0.4.3]: https://github.com/blackaxgit/ssh-mcp/compare/v0.4.2...v0.4.3
[0.4.2]: https://github.com/blackaxgit/ssh-mcp/compare/v0.4.1...v0.4.2
[0.4.1]: https://github.com/blackaxgit/ssh-mcp/compare/v0.4.0...v0.4.1
[0.4.0]: https://github.com/blackaxgit/ssh-mcp/compare/v0.3.1...v0.4.0
[0.3.1]: https://github.com/blackaxgit/ssh-mcp/compare/v0.3.0...v0.3.1
[0.3.0]: https://github.com/blackaxgit/ssh-mcp/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/blackaxgit/ssh-mcp/compare/v0.1.1...v0.2.0
[0.1.1]: https://github.com/blackaxgit/ssh-mcp/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/blackaxgit/ssh-mcp/releases/tag/v0.1.0
