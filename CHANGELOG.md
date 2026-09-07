# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.8.1] - 2026-09-07

> **Why 0.8.1 and not 0.9.0:** nothing here changes a configuration that started successfully on 0.8.0 into one that refuses to start, which is the test 0.8.0 itself recorded for taking the minor. The one behaviour an operator could notice is that four more command shapes are now blocked by the dangerous-command tripwire — and that list has always been documented as advisory and subject to widening, `force=true` still bypasses it, and no *configuration* becomes invalid. Everything else is a hang becoming an error, a log line becoming honest, an image gaining an architecture, and prose corrections.

### Security

**The audit log can no longer silently omit an executed command.** Redaction replaces from the credential marker to the end of the whitespace-delimited token, which is what makes leaking a partially quoted secret impossible — but shell separators are not whitespace. So `echo --password=X;reboot` was logged as `echo --password={REDACTED}`: the `reboot` was **absent from the audit record while the command still ran on the host**. Reproduced end-to-end against a live SSH host on 2026-09-07, where the elided `touch /tmp/f` created its file.

Narrowing the replacement to the separator was rejected — a secret containing `;` would then have its tail printed. The value stays fully hidden and the record stops being *silent* instead: text that could chain a second command is now replaced with `{REDACTED+ELIDED}`, so a reader knows the token carried something beyond the secret and the log is not a faithful transcript. The marker cannot say *what* was elided, only that something was, and it deliberately errs toward flagging — a secret that merely *contains* a `;` is flagged too, because telling those apart needs shell parsing this module refuses to do. A noisy marker is recoverable; a silently truncated audit record is not.

**The dangerous-command tripwire now covers host availability, not just filesystem destruction.** End-to-end testing found the priorities inverted: `reboot`, `poweroff`, `init 0`, `systemctl poweroff`, `iptables -F`, `nft flush ruleset`, `userdel` and `passwd -l` all reached the host, while a routine `rm -rf /tmp/build-cache` was blocked. For a tool whose `execute_on_group` fans one command across a fleet, a single `reboot` takes the whole group down, and `iptables -F` on a host reached through those rules is unrecoverable without console access.

These are anchored on **command position** rather than the bare word, so `last reboot`, `grep reboot /var/log/messages` and `journalctl | grep -i poweroff` still run — blocking read-only diagnostics is how a tripwire teaches operators to route around it. Cost of the anchor, accepted and documented: `sudo -n reboot` is not matched. Still a tripwire and not a security boundary; `$(printf 'reboo\164')` defeats every entry, exactly as documented for the rest of the table.

Matching now runs over two renderings of the command, because collapsing a newline to a space is right for one class of pattern and wrong for the other: `rm -rf\n/` only matches while the line break reads as whitespace, and a second line `reboot` only matches while it reads as a command position. With the space rendering alone, `echo hi\nreboot` was measurably not caught.

**Both architectures of the published image are now scanned.** A multi-arch push produces an index, and Trivy resolves an index to the runner's own platform, so the single CRITICAL gate would have covered amd64 and published arm64 uninspected — with the gate still green. `ci.yml` now runs one scan step per platform, and a regression test asserts the set of platforms built equals the set scanned.

### Added

**The container image is now `linux/amd64` *and* `linux/arm64`.** Until 0.8.1 it was amd64-only, so `docker run` on Apple Silicon or AWS Graviton failed outright with "no matching manifest" — verified against the published `0.8.0` manifest, whose only entry was `linux/amd64`. Reaching remote infrastructure is this tool's whole job and Graviton is a plausible host for it. arm64 is built under QEMU emulation; the alternative, a second native `ubuntu-24.04-arm` runner plus a manifest-merge job, is faster but splits one digest across two jobs, which the promote/scan/verify chain is built around. The image installs prebuilt manylinux aarch64 wheels rather than compiling, so emulation only pays for `UV_COMPILE_BYTECODE` and `useradd`.

### Fixed

**`upload_file` on a non-regular local file no longer hangs.** The local open beneath `transfer_root` now passes `O_NONBLOCK`. `_upload_impl` has always `fstat`-ed the descriptor and refused anything that is not a regular file, but for a **fifo** that refusal was unreachable: a plain `O_RDONLY` open blocks until a writer appears, so the check never ran for exactly the file type it exists to reject. Found by end-to-end testing against a live SSH host on 2026-09-07, not by the unit suite — the existing non-regular test uses a *directory*, which opens fine and therefore does reach the guard.

The open runs in a worker thread, so the event loop survived; the thread did not. Sixteen concurrent fifo uploads exhausted the default executor (`min(32, cpu+4)`) and every later `asyncio.to_thread` call — all SFTP in the process — stalled until restart, while `execute` kept working. Reaching it requires a non-regular file beneath `transfer_root`, which is `0700` and owner-only, so this is a local availability bug rather than a remote one. This is the same defect class 0.8.0 fixed for `SSH_MCP_HTTP_TOKEN_FILE`; the SFTP path was missed. The flag is referenced bare rather than through `getattr` because SFTP is POSIX-only by design — `paths.py::ensure_root` fails closed without `O_NOFOLLOW`/`O_DIRECTORY` before the open is reached.

**An unknown group is no longer reported as a group with one server.** Asking for a group that does not exist printed `Executing on group 'no-such-group' (1 servers)...`, which asserts two false things at once: that the group exists, and that it has a member. `execute_on_group` cannot raise (see `ExecResult` in `models.py`), so a registry failure arrives as a single result whose `server` *is* the group name; that shape now renders as the error alone. Single-member group headers are also pluralised correctly.

**Two real Pyright errors from `_build_http_app`'s lifespan are gone.** `_lifespan` was annotated `-> Any`, which made both `asynccontextmanager` and Starlette's `lifespan` parameter unverifiable; it is now `-> AsyncGenerator[None]`. The three `-> Iterator[…]`/`-> AsyncIterator[…]` annotations under `@contextmanager`/`@asynccontextmanager` are deprecated forms and became `Generator`/`AsyncGenerator`. Fixing the last of them surfaced a genuine narrowing hole: `_transfer_root` yielded the `int | None` attribute rather than a checked local, so a checker could not tell the descriptor was set. It now reads a local, and `server.py`/`ssh.py` capture the OTel status helpers at import time instead of reaching through a name bound only inside the `try`. `ssh.py` reports zero Pyright errors; `server.py` is down from seven to the two unresolved-import artefacts of Pyright not using the project venv, which `mypy` resolves.

**A symlink at a download destination now says so.** `open_beneath` adds `O_NOFOLLOW`, so `O_CREAT|O_EXCL` reports `EEXIST` for a symlink rather than following it — correct, but the message read as "a regular file is in the way", leaving an operator to wonder why `ls` shows a link pointing somewhere writable.

### Documentation

**Corrected the 0.7.0 claim that all four security floors protect `pip install` consumers.** Only two do: `mcp>=2.1.1` and `asyncssh>=2.24.0` are in `[project.dependencies]` and reach the published wheel's `METADATA` (verified against the 0.7.0 wheel's `requires_dist`). `cryptography>=50.0.1` and `click>=8.3.3` are `[tool.uv] constraint-dependencies` — uv-only, absent from `METADATA` by design, and binding this repo's lock rather than a downstream resolve. The placement was right; the sentence describing it was not.

## [0.8.0] - 2026-09-06

> **Why 0.8.0 and not 0.7.1:** two of the changes below make a configuration that started successfully on 0.7.0 **refuse to start**, which is a breaking change to operator-visible behaviour rather than a bug fix. An empty or whitespace-only `SSH_MCP_HTTP_TOKEN_FILE`, a whitespace-only `SSH_MCP_HTTP_TOKEN`, and a token containing non-ASCII, a control character or an interior space all used to boot; all now abort. A token file with mode `0666` does too. Shipping that as a patch would let `~=0.7.0` pull it in silently and take a working deployment down on its next restart, so it takes the minor — the same reasoning recorded above for 0.6.0 over 0.5.7. The 0.6.1 precedent of a "BREAKING" patch does not apply: that one renamed the PyPI distribution while keeping an `ssh-mcp` alias, the import package and the image, so only the install command changed, never the behaviour of a running server.

### Security

**`SSH_MCP_HTTP_TOKEN_FILE` now validates the file it reads.** It was a bare `Path(p).read_text()` — no checks at all — for a secret that authenticates an endpoint which executes shell commands on remote hosts. Now:

- The descriptor is `fstat`-ed and read, so every check applies to the **same object** that supplies the token. The previous stat-then-open shape would have been a TOCTOU window on exactly the file an attacker would want to swap.
- A **non-regular file aborts startup** — a directory, socket or device is unambiguous misconfiguration. `O_NONBLOCK` means a fifo is refused instead of blocking startup forever waiting for a writer.
- A file over **64 KiB aborts startup** (`_MAX_TOKEN_FILE_BYTES`); a mistyped path pointing at a log file is no longer slurped into memory and used as a secret. Checked twice: on the `st_size` snapshot, and again on the bytes actually read — the same descriptor removes *pathname* TOCTOU but not *content-mutation* TOCTOU, so a file that grows between `fstat` and `read` would otherwise sail past the cap the error message promises.
- A mode **writable** by group or other **aborts startup**. This is an integrity hole, strictly worse than disclosure: whoever can write the file chooses the token that authorises remote command execution, then waits for a restart. Refusing costs nothing in the deployments below — neither `0444` nor `0644` carries a group/other write bit.
- A mode **readable** beyond its owner logs a warning naming the octal mode, and so does an **owner that is neither this process nor root** (which is also what catches a hardlink to another user's file). Both deliberately do **not** refuse: Docker Swarm mounts secrets `0444`, Kubernetes defaults to `0644`, and both are commonly root-owned while the process runs unprivileged — refusing either would break the two most common secret mounts outright. World-readable inside an isolated image is a different risk from world-readable on a shared host, and the process cannot reliably tell which it is in, so it reports and lets the operator judge. An execute bit alone is silent; it discloses nothing about a regular file.
- **Content that is not valid UTF-8 aborts startup with an actionable message.** `UnicodeDecodeError` is a `ValueError`, not an `OSError`, so it escaped the handler and killed startup with a raw codec traceback that never named the env var or the path. The old `Path.read_text()` had the identical hole, so this is not a regression — but a binary file is exactly the wrong-path case this validation exists to report in words.
- **BREAKING: a token source that is configured but yields nothing now aborts startup.** An empty or whitespace-only `SSH_MCP_HTTP_TOKEN_FILE` used to flow through `token = raw_token or None`, so the bearer middleware was never attached — on a loopback bind the RCE-capable endpoint served with **no authentication at all**, while the operator who had mounted a secret file believed it was protected. "Configured but empty" is not "not configured". The same rule now applies to `SSH_MCP_HTTP_TOKEN` set to a whitespace-only value, which is the signature of a broken substitution such as `SSH_MCP_HTTP_TOKEN="${SECRET}"` with `SECRET` unset. A literal empty string is still treated as unset, and configuring no token source at all still permits unauthenticated loopback, so the documented single-user workstation mode is untouched. This mirrors the treatment `SSH_MCP_HTTP_ALLOWED_HOSTS` has always had.
- **BREAKING: a token that cannot be sent in an HTTP header now aborts startup.** `_assert_valid_bearer_token` additionally requires printable ASCII with no interior whitespace, for BOTH the env var and the file. Previously a ≥16-character token containing NUL, a newline, an interior space or non-ASCII text started the server happily and then returned 401 to every client forever: NUL and newline raise `LocalProtocolError: Illegal header value` client-side, and a non-ASCII token is Latin-1 encoded by common clients while the middleware compares UTF-8 bytes. The rule is deliberately looser than RFC 6750's `b64token` grammar, which would reject `:` and `!` — characters that work today.
- **A UTF-8 BOM is now stripped from a token file.** `str.isspace()` is False for U+FEFF, so `.strip()` left it attached: Windows Notepad and PowerShell's `Out-File` write one by default, the BOM counted toward the 16-character minimum, and the operator saw a correct-looking token that authenticated nobody. Decoding as `utf-8-sig` removes it and is a superset for BOM-less input.
- **The 64 KiB cap is now measured in bytes, as documented.** The first implementation read through a `TextIOWrapper`, whose `read(n)` counts decoded *characters*, so a file of 65,536 multi-byte characters (131,072+ bytes) was accepted while three documents promised a byte limit. The read is now binary, length-checked, then decoded.
- **Windows is no longer broken by the new validation.** `os.O_NONBLOCK` and `os.geteuid` are POSIX-only and `AttributeError` is neither `OSError` nor `UnicodeDecodeError`, so either would have escaped both handlers as a raw traceback on every Windows startup; and CPython synthesises `st_mode` as `0o666` there, so the group/other-writable refusal would have rejected **every** Windows token file while advising `chmod go-w`. 0.7.0 read this file with `Path.read_text()`, which worked on Windows, so all three were regressions introduced by the fix itself. Permission and ownership checks are now POSIX-gated, the two constants are reached defensively, and a test simulates all three conditions since CI is ubuntu-only.

`O_NONBLOCK` is deliberately **not** claimed as a liveness guarantee: it stops a fifo hanging startup, but a regular file on a slow or hostile FUSE mount can still block the read. That is accepted as a local denial of service by whoever already controls both the mount and the configuration pointing at it; bounding it would need a reader thread and a timeout, which is not worth the complexity on a startup-only path whose input is operator configuration rather than request data.

Symlinks are **followed on purpose**, which is the one place this diverges from `paths.py::ensure_root`'s `O_NOFOLLOW`. Kubernetes projects each secret key as `key` -> `..data/key` -> `..<timestamp>/key` so updates are atomic; refusing symlinks would reject every Kubernetes secret mount. A regression test pins this, because "add `O_NOFOLLOW` for consistency" is the obvious wrong hardening.

`healthcheck.py` is deliberately left lenient — it returns `None` on an unreadable token file so a missing token still yields a 401 that counts as alive. The server is the enforcement point; a container `HEALTHCHECK` re-warning every 30s would be noise.

### Changed

**Lint standard: adopted `I` (import sorting) and `BLE` (blind-except); rejected the rest of ruff 0.16's 413-rule default.** The default set was measured, not guessed (`ruff check --isolated`, ruff 0.16.6): 70 findings, dominated by `SIM117` (17) and `SIM115` (15) — both tests-only cosmetics — so adopting it wholesale would buy 30-odd suppressions for no safety.

The two adopted groups earn their place. `I` is deterministic and fully autofixable (9 files reordered). `BLE` is the valuable one: the 9 broad `except Exception` blocks are load-bearing — 6 in `ssh.py` back `ExecResult`'s documented never-raises contract, 2 in `healthcheck.py` are deliberately fail-safe, 1 is `server.py`'s atexit cleanup — and each now carries a `# noqa: BLE001` naming *why*. That converts them from accidents-that-look-deliberate into reviewed decisions, and makes a **new** accidental blind except fail CI. `RUF100` is deliberately not enabled: under this select it fires only on the two `# noqa: S310` directives documenting a deliberate `urllib` choice, so it would force deleting intent for no gain.

**Every CI job now declares `timeout-minutes`.** All eleven jobs across `ci.yml`, `release.yml` and `audit.yml` previously inherited GitHub's **360-minute** default. That is not hypothetical: while writing this release a test that removed `O_NONBLOCK` did not fail, it **hung** on opening a writer-less fifo, and the only reason it surfaced in seconds was a `SIGALRM` deadline added inside that one test. Limits are `test: 10`, `lint: 5`, `audit: 5`, `build: 15`, `publish-pypi: 10`, `github-release: 10`, `docker: 20` — each at least 10x the measured duration (14-69 s), so a hang fails fast while a slow-but-healthy run cannot trip it. `tests/test_ci_lint_determinism.py::test_every_job_declares_a_timeout` asserts every job has one and that the value is a positive integer, since `timeout-minutes: 0` parses fine and would fail every job instantly. Verified against the v0.7.0 release run that `publish-pypi`'s limit does **not** consume the reviewer-approval wait: the job's `startedAt` follows approval, so its own runtime was 16 seconds against a 7-minute wait.

## [0.7.0] - 2026-09-06

### Security

Cleared all four Dependabot alerts open against `uv.lock`, moving to the *latest stable* of each affected package rather than the minimum patched version Dependabot proposed, so one lock refresh supersedes three separate open PRs (#53, #54, #55) instead of leaving them to land piecemeal. **None of the four is exploitable in ssh-mcp today** — the floors exist because `uv.lock` carries no guarantee for anyone installing from PyPI. How far a floor actually reaches depends on where it is declared, and only two of these four reach a `pip install` consumer: `mcp>=2.1.1` and `asyncssh>=2.24.0` sit in `[project.dependencies]` and so appear in the published wheel's `METADATA` (verified against the 0.7.0 wheel's `requires_dist`). `cryptography>=50.0.1` and `click>=8.3.3` are `[tool.uv] constraint-dependencies`, which are uv-only and absent from `METADATA` by design — declaring them as project dependencies would assert import edges ssh-mcp does not have. They bind this repo's own lock, not a downstream resolve.

- **CVE-2026-54591** (`GHSA-2wxc-x7rj-hg8f`, asyncssh, SCP-client path traversal to arbitrary file write via a server-supplied filename) — **not reachable**: ssh-mcp uses SFTP exclusively and never calls `asyncssh.scp`, and it is an SSH client, never a server.
- **CVE-2026-54590** (`GHSA-qr67-gv47-xwwh`, asyncssh, `AuthorizedKeysFile %u` escape) — **not reachable**: this is server-side behavior and ssh-mcp is a client only.
- **CVE-2026-69247** (`GHSA-g6cj-pr64-35w5`, cryptography, Bleichenbacher oracle in PKCS#7 `EnvelopedData` decryption) — **not reachable**: ssh-mcp never calls `pkcs7_decrypt_*`.
- **CVE-2026-13346** (`GHSA-qwm4-qh6w-59xr`, pip, doubly-encoded index URLs enabling an arbitrary write under `pip download --only-binary`) — dev/CI extra only, not a runtime dependency.
- `asyncssh` bumped to **2.24.0**, `cryptography` constrained to **>=50.0.1**, `pip` (dev extra) to **>=26.2.1**.

**Credential redaction was missing at a fourth `str(e)` site, and inconsistent at three others.** `ssh.py`'s SSH-error and unexpected-error handlers (single-host and group paths) passed the raw exception text through `_safe_log_value` — control-character escaping only, not `_redact_secrets` — into both the log line and `ExecResult.error`, which `formatting.py` renders verbatim to the LLM. The group-level task-failure path already redacted; the other three did not. All three now redact before logging or returning. A fourth, separate site had the same gap on the *raising* tools: `server.py::_mcp_tool` logged and re-raised `str(e)` un-redacted in `ToolError`, so an unredacted string reached both the ssh-mcp log and the MCP client's error content. It is now redacted before either happens.

**Suppressed a new INFO-level tool-failure log added by the MCP SDK v2.** `mcp/server/mcpserver/server.py` logs `Tool %r failed: %r` at INFO on its own logger before converting a `ToolError` into `CallToolResult(is_error=True)`. `upload_file` and `download_file` are the tools that raise, and their messages carry local and remote paths. This is the same class of leak as "Production incident 2026-04-11 (round 2)" (asyncssh's own INFO logging of raw commands), on a logger the existing mitigation did not cover. `_configure_logging` now raises `mcp.server.mcpserver.server` to WARNING alongside the `asyncssh` loggers it already silences.

**Every remaining raw-exception log site now redacts, via one helper.** A review panel found the redaction work above was only half applied: the three `ExecResult.error` strings were clean, but ten `_safe_log_value(str(e))` call sites still logged the *raw* exception, so a credential embedded in an exception message reached the log aggregator while the client-visible result read `{REDACTED}`. Reproduced against `asyncssh.DisconnectError(2, "auth failed for https://deploy:hunter2@bastion.example.com")`: `ExecResult.error` was redacted and the log line printed `hunter2`. `ssh.py` now has a single `_safe_exc(e)` helper — redact, then control-escape — and all ten sites call it, including the four `_create_connection` error handlers and the two SFTP failure paths. The invariant is now greppable: no exception text reaches a logger except through `_safe_exc`.

**`exc_info=True` was defeating the redaction it sat next to.** `server.py::_mcp_tool` redacted the message and then passed `exc_info=True`, so `logging` rendered the original exception — and every `__cause__` in the chain — verbatim underneath it. A `RuntimeError` carrying `mysql --password=hunter2` logged as `--password={REDACTED}` and then printed `hunter2` twice more in the traceback. The decorator now formats the traceback itself and redacts the whole rendered string, which keeps it useful for operators without reopening the leak. Only the log path was affected; the client-visible `ToolError` was already redacted.

### Changed

**MCP Python SDK 1.x → 2.x** (`mcp>=2.1.1,<3.0.0`). v1.x entered maintenance mode (security fixes only) at the v2.0.0 release. Operator-visible consequences:

- **Streamable HTTP requests are now capped at 4 MiB** (SDK default) — an oversized request gets HTTP 413 before its JSON is parsed or a session is created. Comfortably above `max_command_bytes`' 1 MiB ceiling; no operator action needed.
- **`serverInfo` in the MCP `initialize` response now reports ssh-mcp's own version.** v1 reported the SDK's version instead.
- **The SDK's own OpenTelemetry tracing is on by default.** It records `mcp.method.name`, `mcp.protocol.version`, `jsonrpc.request.id`, `gen_ai.operation.name` and `gen_ai.tool.name` — no tool arguments and no command text. Left enabled: audited against the wheel source, the error path is attribute-only for a converted `ToolError` (`error.type="tool_error"`, a bare error status with no description), so it does not reopen the leak the SDK's INFO log above does.
- **The `[cli]` extra is no longer requested** (`mcp[cli]` → `mcp`). ssh-mcp parses `sys.argv` directly and never imports `typer`, `click`, `python-dotenv` or `mcp.cli`; dropping the extra removes those three packages from the published wheel's dependency closure. `click` still arrives transitively via `uvicorn`, so the existing `click>=8.3.3` security floor stays load-bearing.
- **The `otel` extra is removed.** `opentelemetry-api` is now a hard dependency of `mcp>=2`, so the extra had become dead weight — installing a nonexistent extra warns rather than errors, which would have been silently misleading. The tracing API is always importable now; spans are always created and are no-ops until an operator installs an OpenTelemetry SDK and exporter, same operator experience the extra used to describe.
- **`pydantic>=2.12.0` is now a declared floor**, matching what `mcp>=2` already requires, so the wheel metadata carries the constraint instead of relying on a transitive dependency to enforce it.

All dev tooling and every GitHub Action bumped to latest stable (`pytest` 9.1.1, `pytest-asyncio` 1.4.0, `pytest-cov` 7.1.0, `mypy` 2.3.1, `ruff` 0.16.6, `hypothesis` 6.167.1, `opentelemetry-sdk` 1.44.0, plus action SHA/version bumps across `ci.yml` and `release.yml`). Container base image moved to `python:3.14-slim-trixie`; `uv` pinned to **0.12.10** everywhere it appears (CI, `release.yml`, `Dockerfile`), closing the previous split-brain between a 0.11.3 image and a 0.11.32 CI pin.

**BREAKING: a `*.subdomain` wildcard in `SSH_MCP_HTTP_ALLOWED_HOSTS` now aborts startup.** It was accepted until 0.7.0, and the docstring, `AGENTS.md` and a test all called it "deliberately permitted" — all three were wrong. The MCP SDK never implemented suffix matching: `TransportSecurityMiddleware._validate_host` (`mcp/server/transport_security.py:50-69`) does an exact-set lookup and then one trailing `:*` port-wildcard pass, and there is no `*.` handling anywhere in the SDK. A `*.internal.example.com` entry was therefore compared **literally**, so a real request from `api.internal.example.com` was rejected with a 421 and nothing in the log explained why. Refusing it at startup converts a silent reject-everything into a loud, actionable error. Only a trailing `:*` port wildcard is supported; list concrete hostnames otherwise. If you set such a value today, your remote clients were already being rejected — replace it with the explicit hostnames.

**`SSH_MCP_HTTP_STATELESS` is now whitespace-tolerant.** The value was compared without stripping, so `" true "` from a `.env` file or a Compose heredoc silently selected *stateful* mode — the opposite of the operator's intent, and invisible in a load-balanced deployment until sessions started pinning. It is stripped before comparison now.

### Added

- **`.github/dependabot.yml`**, grouping security and version updates into one PR per ecosystem instead of ungrouped single-package PRs — the reason #54 and #55 were both red: each cleared one advisory while `pip-audit` still saw the rest.
- **`HYPOTHESIS_PROFILE: ci` in both `ci.yml` and `release.yml`**, raising the security-relevant Hypothesis fuzzers (credential redaction, dangerous-command detection) from 50 examples to 200 in CI. This had never actually run: no workflow set the variable before this PR.
- **`packaging` declared as a `dev` dependency.** `tests/test_dependency_floors.py` has always imported `packaging.version`; it worked only because a transitive dependency happened to supply it.

### Fixed

- **The `pip` and `asyncssh` security floors are now actually enforced**, not merely documented. `tests/test_dependency_floors.py` asserts both hold in the resolved environment and are declared in `pyproject.toml` at the layer matching each dependency's kind.
- **`release.yml`'s release-environment URL pointed at the wrong PyPI project** (`https://pypi.org/p/ssh-mcp`, a name this repo has never owned — see 0.6.1) instead of `https://pypi.org/p/blc-ssh-mcp`. Missed when the distribution was renamed in #51.

## [0.6.2] - 2026-07-26

### Fixed

**The PyPI project page had no description at all.** `pyproject.toml` declared no `readme`, so the built wheel carried a zero-length long description and https://pypi.org/project/blc-ssh-mcp/ rendered an empty body — just the name and a one-line summary. `readme = "README.md"` fixes it. Package metadata cannot be edited on PyPI and published files are immutable, so correcting this requires a release; that is the only reason 0.6.2 exists.

**Seven README links would have 404'd once rendered on PyPI.** PyPI resolves relative Markdown links against `pypi.org`, not the repository, so `[LICENSE](LICENSE)`, `[CHANGELOG.md](CHANGELOG.md)`, `[SECURITY.md](SECURITY.md)`, `[CONTRIBUTING.md](CONTRIBUTING.md)`, `[compose.yaml](compose.yaml)` and `config/servers.example.toml` are now absolute. Keep any new README link absolute for the same reason.

### Changed

- **Summary rewritten** from "SSH MCP server for managing infrastructure via Claude Code" to "MCP server giving AI assistants SSH access to run commands, transfer files, and manage server fleets" — the old one named a single MCP client and omitted what the server actually does.
- **`license` migrated to the PEP 639 SPDX form** (`license = "MPL-2.0"` plus `license-files`) from the deprecated `{text = "..."}` table, and the correspondingly deprecated `License :: OSI Approved ::` classifier was dropped. The published `License-File: LICENSE` metadata is unchanged.
- **More project links on PyPI**: Changelog, Documentation, Security Policy and Container Image, alongside the existing Homepage/Repository/Issues.
- Added the `System Administrators` audience classifier and the `sftp`, `devops`, `automation` keywords.

## [0.6.1] - 2026-07-26

### Changed — BREAKING (install command)

**The PyPI distribution is now `blc-ssh-mcp`. It was never published as `ssh-mcp`, and could not be.** That name on PyPI belongs to an unrelated project by a different author (`czyhandsome`, MIT-licensed, last release 0.1.4 in June 2025); this repository has never owned it, and PyPI names are globally unique and first-come. No trusted publisher or credential can change that — an upload under `ssh-mcp` is simply rejected.

The consequence was a documentation defect with a security dimension: `README.md` instructed users to run `uvx ssh-mcp`, `pip install ssh-mcp`, and `claude mcp add ssh-mcp -- uvx ssh-mcp`, all of which install **that stranger's package**. Because it is also an SSH tool, the substitution was not obvious. Every install instruction now names `blc-ssh-mcp`, including the two Claude Desktop JSON examples whose `"args": ["ssh-mcp"]` form was easy to miss.

**Migration:** if you installed by following an earlier README, you have the wrong package. `pip uninstall ssh-mcp` and `pip install blc-ssh-mcp`. Nothing else changes: the import package is still `ssh_mcp`, the container image is still `ghcr.io/blackaxgit/ssh-mcp`, config paths are still `~/.config/ssh-mcp/`, and the environment prefix is still `SSH_MCP_`.

A `blc-ssh-mcp` console script is added so `uvx blc-ssh-mcp` resolves; `ssh-mcp` is retained as an alias, because the Dockerfile `HEALTHCHECK` and `release.yml`'s artifact smoke test both invoke it and existing installs have it on `PATH`.

### Fixed

- **A failed PyPI upload no longer takes the GitHub Release with it.** `github-release` had `needs: [publish-pypi]` and no `if:`, so when 0.6.0's trusted-publisher exchange failed — before uploading anything — the release record and its artifacts were skipped too, and could not be recovered by re-running, because a tag's workflow is pinned at the tag ref. It now gates on `build` with `if: always() && needs.build.result == 'success'`.

### Note on 0.6.0

0.6.0 was tagged and published as a container image (`ghcr.io/blackaxgit/ssh-mcp:0.6.0`) with a GitHub Release, but **never reached PyPI** for the reason above. All of its security fixes are included here.

## [0.6.0] - 2026-07-26

> **Why 0.6.0 and not 0.5.7:** two independent reasons — the `mcp` floor in `[project.dependencies]` is narrowed from `>=1.27.0` to `>=1.28.1`, and the SFTP path contract is a **breaking change** (see everything under *Changed — BREAKING* below).

### Security — please read if you run ssh-mcp

**Versions ≤ 0.5.6 are affected by a local-path confinement flaw in the SFTP tools. Upgrade.** An MCP client — including one steered by prompt injection — could use `download_file` to write to effectively any path on the machine running ssh-mcp, and from there to code execution on that machine. This is the operator's own workstation or container, not the managed fleet, and it was reachable in the default `uvx ssh-mcp` stdio deployment. There is no configuration that mitigates it on an affected version.

The cause was that `upload_file`/`download_file` validated the caller's path *string* against a denylist of sensitive paths and then handed that string to asyncssh, which resolved it independently. Three consequences, all verified against a live SFTP server:

1. Anything not enumerated in the denylist was permitted — shell startup files, `~/Library/LaunchAgents/*.plist`, ssh-mcp's own `servers.toml`, and the installed package itself were all writable.
2. asyncssh rewrites an existing-*directory* destination to `<dir>/<basename>`, a path validation never saw. So `~/.ssh` passed while `~/.ssh/config` was blocked, and the file landed at `~/.ssh/config` anyway — from which a planted `ProxyCommand` executes on the next connection.
3. A downloaded symlink was recreated locally, and asyncssh's local writer follows symlinks, so a later write went *through* it.

**Fixed by confining the operation rather than validating the name.** ssh-mcp now opens the local file itself, one path component at a time beneath a configured transfer root, refusing a symlink at any component, and drives the remote side through the public `sftp.open()` API with its own copy loop. asyncssh never resolves a local path, so consequences (2) and (3) are unreachable code rather than defended-against behaviour. **This changes the `upload_file`/`download_file` contract — see *Local path confinement* under Changed.**

Two further hardening fixes in the same area: the audit record now reports the file actually written (it previously reported the destination *directory* on a directory destination, concealing exactly this exploitation), and a failed download removes its own partial file instead of leaving attacker-supplied bytes behind.

**Denial of service in credential redaction.** `_redact_secrets` ran in quadratic time, so a ~10 KB command stalled the single-threaded server for over six seconds, reachable without an SSH connection or SSH authentication via `dry_run=true`. There was no length limit on a command anywhere. The two rules responsible — URL basic-auth and long-flag matching — are now hand-written token-wise scanners that visit each token once (~0.007 s for 100 KB); the remaining rules stay on Python's `re` engine, which their lookbehinds need. `max_command_bytes` (default 64 KiB) caps command length at the tool boundary. Multi-word *quoted* credential values remain only partially redacted — unchanged from previous behaviour; redaction is a tripwire, and credentials should be passed via env files or stdin rather than argv.

**Credential redaction missed values beginning with a dash.** In the space-separated form (`--password <value>`, not `--password=<value>`), a value starting with `-` was left unredacted, so it reached logs and OTel spans in plaintext. The scanner treated any following token that began with `-` as "this flag was boolean, leave the next token alone" — a guard that exists to fix an earlier leak where a credential flag following a boolean flag was silently skipped — and a password beginning with `-` is indistinguishable from a flag under that rule. Generated passwords routinely start with `-`, so this was not a corner case. The guard is now narrowed to `--`: a single-dash token is redacted, while a `--`-prefixed token is still left for its own classification turn, keeping the earlier fix intact. **Residual, unchanged and deliberate:** a value beginning with `--` is still treated as a flag and not redacted. Redaction remains a tripwire — pass credentials via env files or stdin rather than argv.

**`SSH_MCP_HTTP_ALLOWED_HOSTS=*.*` silently disabled DNS-rebinding protection.** The startup gate refuses bare wildcards, and `*.*` was listed in its refusal set, but the allowance for legitimate suffix wildcards (`*.internal.example.com`) was evaluated first, so `*.*` — which matches effectively any dotted hostname — was accepted. On the HTTP transport that is remote command execution behind a rebinding attack. Validation now strips only the two deliberately-permitted wildcard forms (a leading `*.` subdomain wildcard and a trailing `:*` port wildcard) and refuses anything with a wildcard left over; the same change also starts refusing infix wildcards such as `a*b.example.com`, which the previous check never caught, and a whitespace-only value, which previously fell back silently to loopback-only. Suffix wildcards remain permitted as documented.

**Audit records could be forged.** The success and timeout audit paths interpolated the command without escaping control characters, so an embedded newline produced a convincing fake log line. All audit paths now escape.

Also cleared every advisory reported by `pip-audit`. **None of the four is exploitable in ssh-mcp** — this is defence-in-depth and a CI unblock, not an incident response. Being precise, because the two are not the same thing: three of the four are *unreachable* (the vulnerable code is never imported or never called), while CVE-2026-52869's session manager **is** in the HTTP request path — it is reachable but its exploit precondition cannot be satisfied by ssh-mcp's authentication model. Details per advisory below. Reachability was verified by grep over `src/` and the non-exploitability argument for CVE-2026-52869 was independently stress-tested by two external models.

- **PYSEC-2026-2132 / CVE-2026-7246** (click, CVSS 7.2 HIGH, CWE-78) — command injection in `click.edit()`: the `filename` argument was interpolated into a shell string with its quotes unescaped. Bumped 8.3.1 → **8.4.2** (advisory fix floor is 8.3.3). `click` reaches ssh-mcp only via `mcp[cli]` → `typer` → `click` and `uvicorn` → `click`; ssh-mcp never imports it (its CLI parses `sys.argv` directly), so `click.edit()` is unreachable.
- **PYSEC-2026-3481 / CVE-2026-52870** (mcp, High 7.6, CWE-862) — missing authorization in the experimental tasks handlers. Unreachable: requires opt-in `enable_tasks()`, never called.
- **PYSEC-2026-3482 / CVE-2026-52869** (mcp, High 7.1, CWE-639) — cross-principal session bypass in `StreamableHTTPSessionManager`. The component is in the request path in HTTP mode, but the exploit precondition is unsatisfiable here: ssh-mcp authenticates *outside* the SDK with a single shared bearer token, so the SDK sees every request as anonymous — the advisory's documented "not affected without authentication configured" case.
- **PYSEC-2026-3483 / CVE-2026-59950** (mcp, High 7.6 CVSS v4, CWE-346/1385) — origin validation in the deprecated `websocket_server()` transport. Unreachable: that transport is never imported.
- **`mcp` bumped 1.27.0 → 1.28.1** in both `uv.lock` and `[project.dependencies]`. The `pyproject.toml` floor is the load-bearing half: `[project.dependencies]` is the only declaration that reaches the published wheel's `METADATA`, so a lockfile-only bump would have left `pip install ssh-mcp` free to resolve a vulnerable 1.27.0. stdio mode was unaffected by all three `mcp` advisories.
- Added **`[tool.uv] constraint-dependencies = ["click>=8.3.3"]`** to record the transitive floor. Deliberately *not* added to `[project.dependencies]`, which would assert a dependency edge ssh-mcp does not have. Without this, a future `uv lock` regeneration could silently drop back below the fix.

### Changed — BREAKING

**Local path confinement.** `upload_file` and `download_file` no longer accept arbitrary absolute local paths. Local paths are now **relative to a `transfer_root`** (new `[settings]` key; defaults under `$XDG_DATA_HOME` or `~/.local/share`; override with `SSH_MCP_TRANSFER_ROOT`). The directory is created `0700`, must be owned by the running user, and must not itself be a symlink.

- Absolute local paths and `..` are rejected. Sub-directories are allowed but must already exist.
- **Downloads no longer overwrite** — an existing destination fails rather than being silently replaced.
- Remote non-regular files (symlinks, devices, FIFOs) are refused on a best-effort basis. SFTP v3 has no atomic no-follow open, so a remote server can still win the check-to-open race; the local destination stays confined regardless.
- **Migrating:** replace absolute local paths with names relative to `transfer_root`, or point `transfer_root` at the directory you were already using. There is no flag to restore the previous behaviour.

**The `*.pub` exemption from SFTP path validation is gone.** A path ending in `.pub` used to skip the sensitive-path check entirely (added in 0.3.0 so public-key distribution would work). The suffix said nothing about what the path actually identified — nothing stopped a caller naming a symlink or a sensitive file `foo.pub` — so it was dropped rather than hardened. Remote paths are now matched against the denylist whatever their extension, and local paths no longer go through a denylist at all (see *Local path confinement* above). **Migrating:** a transfer of e.g. `~/.ssh/id_ed25519.pub`, which the exemption used to let through, is now refused; copy public keys to a path outside the denylist, or use `execute` to place them.

**`max_output_bytes` now bounds memory, not just the response.** Output is consumed incrementally and the remote process is terminated once the budget is spent, where previously the entire output was buffered before truncation — so a large `cat` could exhaust memory regardless of the setting. The limit is now counted in real bytes; it was previously character-based, which overran the stated limit roughly 4x on multibyte output. Note the budget is per-stream, so the combined ceiling is 2x the setting.

**`max_parallel_hosts` now bounds the process, not one call.** The concurrency semaphore was created per `execute_on_group` invocation, so N concurrent calls allowed N x the limit — up to 2560 in HTTP mode against a container with a 1024 file-descriptor limit, which is the exhaustion this setting exists to prevent. It is now shared. Independent group calls therefore queue behind one another, which is the documented intent but a behaviour change.

### Fixed

**`execute_on_group(fail_fast=true)` reported hosts that had run the command as "Cancelled".** After the first failure, results from hosts that had already completed successfully were discarded and those hosts were labelled cancelled — in 60 of 60 trials with uniform timing. For a destructive fleet command this told the operator a host was skipped when it had executed. Completed results are now reported, and the wording for the remainder admits the command may already have been dispatched: cancelling a local task does not stop a command already on the wire.

**`~` was not expanded unless `[settings]` was present.** A minimal `servers.toml` left the default `ssh_config_path` as the literal `~/.ssh/config`, so every connection failed with `FileNotFoundError`. `identity_file` was never expanded at all, so a `~`-prefixed key silently failed to authenticate. Expansion now happens at the model boundary, for every path field.

**Connection-pool defects.** A lock was created for a server name *before* the name was validated, so unknown names — reachable straight from tool arguments — accumulated locks permanently. The idle-eviction loop also removed a lock while holding it, orphaning any waiter and letting two callers enter the same critical section, which could leak an unclosed connection.

**The dangerous-command tripwire missed plain variants.** `rm -r -f /`, `rm --recursive --force /`, `chmod 777 -R /` and `dd of=… if=…` all passed, contradicting the `execute` docstring's explicit claim to catch them. Obfuscated bypasses remain out of scope by design and are documented as such.

**The stdio healthcheck reported healthy without a usable config.** It only parsed a config when `SSH_MCP_CONFIG` was set and pointed at an existing file, so a container with no configuration passed its Docker liveness gate. It now resolves the config the same way the server does.

**Command results no longer discard output.** `format_exec_result` dropped stdout, stderr and the exit code whenever an error was set — a state the `ExecResult` contract documents as reachable and meaning "ran but had issues", i.e. exactly when the output matters for diagnosis.

**SFTP no longer raises a bare `KeyError`** for an unknown server, which fell outside its documented `ValueError`/`RuntimeError` contract. A non-ASCII bearer token now returns 401 rather than 500 (it always failed closed). `$XDG_CONFIG_HOME` is honoured for the config search path, matching the new `$XDG_DATA_HOME` handling.

- **The `docker` job scanned an image it did not publish.** It ran BuildKit twice — a `load: true` image for Trivy and a separately built pushed image — which by construction cannot share a digest, so the scanned bytes were never provably the shipped bytes. There is now one build, pushed to GHCR *by digest with no tag attached* (`push-by-digest=true,name-canonical=true`); Trivy scans `${IMAGE}@${digest}`; tags are created from that same digest only after the scan passes, and a verification step fails the job if any tag serves anything other than the scanned digest. Build provenance is recorded as a GitHub Artifact Attestation against the digest.
- **That tag-verification step was itself broken, and it suppressed provenance attestation.** `docker buildx imagetools create` does not reuse the source digest — it wraps the scanned manifest in a *new* OCI index — so comparing the tag's own digest against the build digest compared an index against one of its children and failed on every push to `main`. Because the check runs before the attestation step, images published to GHCR between 2026-07-26 and this release carry **no provenance attestation**. The scan gate itself was never bypassed: Trivy runs against the digest before any tag is promoted, so published content was always the scanned content. Verification now asserts the invariant that matters — the set of image manifests a tag serves is exactly the scanned digest — by inspecting the index's children and ignoring attestation manifests.
- **`SECURITY.md` described dangerous-command detection as "intentionally non-blocking".** The shipped code blocks: a match returns an error instead of executing, and `force=true` is the documented bypass. The policy now says so, and lists the acknowledged obfuscation bypasses rather than implying the check is advisory.
- **CI `Lint` job was non-deterministic and had begun failing on unmodified code.** It invoked `uvx ruff` and `uvx bandit`; `uvx` resolves the newest release at run time. ruff **0.16.0** (2026-07-23) expanded its default rule set from **59 to 413 rules**, so the same command that printed `All checks passed!` on 2026-07-16 reported 50 errors days later with zero code changes. Lint tooling is now pinned (`ruff==0.16.0`, `bandit==1.9.4`) in the `dev` extra and invoked via `uv run`, so the gate is a function of the commit rather than of the outside world.
- **The repo now declares its own lint standard.** There was no `[tool.ruff]` config at all, so the standard was whatever default the installed ruff happened to ship. `[tool.ruff.lint] select = ["E4", "E7", "E9", "F"]` codifies the pre-0.16 default the codebase has always been held to and is 100% clean against — no rule is dropped. Adopting ruff 0.16's wider default is tracked as a separate deliberate change.

### Changed

- **`pip-audit` moved out of the `lint` job into a dedicated `audit` job**, and `docker` now declares `needs: [test, lint, audit]`. The audit's input is the live advisory database, not the commit, so a newly published CVE against any transitive dependency fails every open PR at once; a dedicated job makes that failure attributable instead of masquerading as a lint error. The gate is **not** weakened. Two parts, with different guarantees: the GHCR publish is gated **unconditionally and in-workflow** — the previously *implicit* dependency of `docker` on the audit is now an explicit `needs:` entry. PR blocking, however, is enforced by branch protection, so it holds **only once `Dependency audit` is added to the required-checks list** (see *Operator action required* below). Until then the audit runs on every PR but does not block merges.
- **New `.github/workflows/audit.yml`** runs `pip-audit` daily at 06:00 UTC plus on demand via `workflow_dispatch`, so new advisories are discovered on a schedule and remediated in their own PR rather than first appearing as noise on an unrelated one. Note: `main` will now show a red scheduled run whenever a new advisory lands and remains unremediated.
- **`ci.yml` now also triggers on `v*` tags** (previously `main` pushes and PRs only), so the container image for a release tag is built, scanned and published by the same gated job as every other commit.
- Replaced the private Starlette `router.lifespan_context` dependency with the SDK's public `FastMCP.session_manager`.
- Added `pyyaml>=6.0` to the `dev` extra (used by the new CI-invariant tests; previously present only transitively via bandit).
- **Dockerfile now sets `HOME=/home/sshmcp`.** Without it `expanduser()` in the container had no home to resolve, so the `transfer_root` default (under `$XDG_DATA_HOME` or `~/.local/share`) could not be built — a prerequisite of the breaking change above, not a cosmetic tidy-up.
- `.gitignore` now covers `.coverage` / `.coverage.*`, and the narrower `docs/research-prep/` + `docs/internal/` entries are replaced by a blanket `docs/`, plus `wiki/`, `claude/`, `codex/` and `.codex/`. Everything under `docs/` is therefore local-only from here on; note that ignoring a directory does not untrack files already committed under it.
- **README security section rewritten** for the new SFTP contract: the tool table entries for `upload_file`/`download_file`, a `transfer_root` settings example, and the migration note replace the old list of denylisted local paths.
- **`SECURITY.md` supported-versions table** now reads `0.6.x` supported / `≤ 0.5.6` not supported, with a paragraph naming the confinement flaw and pointing at this entry.
- **`.trivyignore`: two new `perl-base` entries** — `CVE-2026-13221` (regex trie >65535 branches → silently incorrect matches) and `CVE-2026-57433` (Storable `SX_HOOK` signed-integer overflow → deserialization panic). Both surfaced as CRITICAL on the **first Trivy run the `docker` job ever completed**: while `Lint` was red, `docker` was skipped and the image scan never executed, so these were latent rather than new. Verified against the Debian security tracker — trixie is `vulnerable` at perl 5.40.1-6 with **no fixed version published for trixie** — so they meet the existing ignore policy (unfixable OS CVEs only, with a stated reason and review date). perl is not used at runtime by this pure-Python app. The `severity: CRITICAL` threshold was **not** changed and no fixable CVE is ignored. Note for the next base-image bump: `CVE-2026-57433` *is* fixed in Debian sid (5.42.2-3) and forky (5.40.1-8), so it becomes fixable and must be deleted from the ignore list once the image moves off trixie.

### Added

- **`transfer_root`** setting and `SSH_MCP_TRANSFER_ROOT` environment override (see Changed).
- **`max_command_bytes`** setting (default 64 KiB), enforced at the MCP tool boundary.
- `src/ssh_mcp/paths.py` — symlink-safe path confinement primitive. Documents its own residual risk: a same-filesystem rename of an intermediate directory between two `openat` calls is closed only by Linux `openat2(RESOLVE_BENEATH)`, which CPython does not expose and macOS has no equivalent for. Mitigated by requiring the root to be owner-only.
- `.gitleaksignore` recording the synthetic credential fixtures in the redaction test corpus, so a genuinely new finding is not lost in known noise.
- **`.github/workflows/release.yml`** — there was no release workflow: the wheel was published by hand and `ci.yml` did not trigger on tags, so a release tag ran no CI at all. A `v*` tag now re-runs test, lint and audit against the tag, asserts the tag matches the version hatchling reads from `src/ssh_mcp/__init__.py`, smoke-imports both the wheel and the sdist, emits a CycloneDX SBOM of the locked runtime set, and publishes to PyPI via **Trusted Publishing** (OIDC in a `pypi` environment — no long-lived API token in the repo) with PEP 740 attestations. The build job holds `contents: read` only; `id-token: write` exists solely in the publish and release jobs.
- **`AGENTS.md`** — repository context for AI coding assistants (layout, commands copied from CI, invariants that must not be broken), plus a one-line `CLAUDE.md` that includes it so no content is duplicated.
- `tests/test_paths.py`, `tests/test_sftp_confinement.py` and `tests/test_input_limits.py` — regression coverage for the confinement primitive, the SFTP contract (absolute paths, `..`, symlink components, no-clobber download, partial-file cleanup) and the `max_command_bytes` / `max_output_bytes` limits.
- `tests/test_dependency_floors.py` — asserts every security-motivated version floor both holds in the resolved environment and is declared in `pyproject.toml` at the layer matching the dependency's kind. Runs offline with no advisory-DB access, so it catches a lockfile regression that `pip-audit` structurally cannot detect without network.
- `tests/test_ci_lint_determinism.py` — asserts no linter is invoked through `uvx`, lint tools are exactly pinned, the ruff rule set is declared, `pip-audit` has its own job, the scheduled audit workflow exists, and **the `docker` publish job depends on `audit`**. That last assertion guards a regression caught during cross-model review: relocating `pip-audit` to a separate workflow would have silently removed it from the image-publish path, because GitHub Actions `needs:` cannot span workflows.

### Operator action required

If `main` has branch protection with required status checks, add **`Dependency audit`** to the required list. Without it the audit becomes advisory-only on pull requests, which *would* weaken the gate. This is a repository-settings change that cannot be made from the repo files.

## [0.5.6] - 2026-07-02

### Security

Cleared every CVE reported by `pip-audit` against the dependency tree. All are transitive deps (pulled in via `mcp[cli]`); ssh-mcp does not call them directly, but the deployed Docker image and dev/CI environment are now clean.

- **GHSA-537c-gmf6-5ccf** (cryptography) — bumped 46.0.7 → 49.0.0.
- **CVE-2026-48817 / -48818 / -54282 / -54283** (starlette) — bumped 0.52.1 → 1.3.1 (major version; full test suite passes unchanged).
- **PYSEC-2026-175 … -179** (PyJWT) — bumped 2.12.0 → 2.13.0.
- **CVE-2026-53538 / -53539 / -53540** (python-multipart) — bumped 0.0.27 → 0.0.32.
- **GHSA-4xgf-cpjx-pc3j** (pydantic-settings) — bumped 2.12.0 → 2.14.2.
- **GHSA-6v7p-g79w-8964** (msgpack, `Unpacker` segfault after a decode failure) — bumped 1.1.2 → 1.2.1.
- **PYSEC-2026-196** (pip in the dev/CI venv) — pinned `pip>=26.1.2` in the `dev` extra. pip is not a runtime dependency of the shipped package.

### Changed

- **asyncssh** bumped 2.22.0 → 2.23.0 (routine; direct dependency, no advisory).
- CI Trivy image scan now reads a documented `.trivyignore` for two **upstream-unfixable** `perl-base` CVEs from the `python:3.13-slim-trixie` base image (`CVE-2026-42496` `fix_deferred`, `CVE-2026-8376` `affected`). perl is not used at runtime. Only OS CVEs with no published fix are ignored; fixable CVEs remain gated. Re-review on the next base-image bump.

## [0.5.5] - 2026-05-02

### Security

- **CVE-2026-28684** (python-dotenv ≤ 1.2.1, symlink-following in `set_key`/`unset_key`) — closed by bumping the transitive dep to 1.2.2 in `uv.lock`. ssh-mcp doesn't call dotenv directly, but the package was pulled in via `mcp[cli]`; the deployed Docker image is now clean.
- **CVE-2026-40347** (python-multipart < 0.0.26, multipart preamble DoS) — closed by bumping the transitive dep to 0.0.27 in `uv.lock`. Same transitive path via `mcp[cli]` → `starlette`.

### Changed

- CI `pip-audit` step now passes `--ignore-vuln CVE-2026-3219` for the runner-bundled pip 26.0.1 vulnerability (no upstream fix yet at release time). Tracked for removal once upstream pip ships a patched release; an automated agent will revisit on 2026-05-16.

## [0.5.4] - 2026-04-12

### Added

- **`ssh-mcp healthcheck` CLI subcommand** — built-in liveness probe that auto-detects transport (stdio vs streamable-http), respects auth env vars (`SSH_MCP_HTTP_TOKEN`, `SSH_MCP_HTTP_TOKEN_FILE`, `SSH_MCP_HTTP_AUTH=none`), and performs a real MCP `initialize` handshake in HTTP mode. Uses Python stdlib only, 3-second timeout, exits 0 healthy / 1 unhealthy.
- New module `src/ssh_mcp/healthcheck.py` with unit tests in `tests/test_healthcheck.py`.

### Changed

- **Dockerfile `HEALTHCHECK`** now uses the built-in `ssh-mcp healthcheck` subcommand instead of the old `python -c "import ssh_mcp"` liveness-only check. The new check performs a real MCP protocol handshake in HTTP mode, so a container marked "healthy" actually means the MCP tools respond correctly — not just that the Python package is importable.
- **`compose.yaml`** — removed the ~40-line inline Python healthcheck block from the commented `ssh-mcp-http` service template. Operators no longer need to embed credential-handling Python in their compose files. The Dockerfile's baked-in HEALTHCHECK handles both stdio and HTTP modes automatically.

### Fixed

- Eliminates the pain point where upgrading the healthcheck required editing every operator's compose.yaml.

## [0.5.3] - 2026-04-12

### Security

- Added `.ssh/config` and `.ssh/known_hosts` to SFTP sensitive-path blocklist (purple-team P2).
- DNS rebinding protection now enabled by default even without `SSH_MCP_HTTP_ALLOWED_HOSTS` (P3).
- Dangerous-command tripwire expanded: `base64 -d | bash`, `eval`, `python -c`, `perl -e`, `bash -c` (P10).

### Added

- `SSH_MCP_HTTP_TOKEN_FILE` env var for file-based token delivery, Docker secrets compatible (P5).
- SFTP transfer size limit: 100 MiB default via `_MAX_SFTP_BYTES` constant (P8).
- Dockerfile + CI actions pinned by SHA digest (P7).
- README: TLS requirement warning, Docker secrets documentation.

### Changed

- Dockerfile and CI GitHub Actions pinned by SHA digest for supply-chain hardening (P7).

## [0.5.2] - 2026-04-12

### Security

- Audit log `server_name` now wrapped in `_safe_log_value` at both success and timeout call sites (closes log-injection gap).
- All remaining f-string logger calls in ssh.py and server.py converted to lazy %-style with `_safe_log_value`.
- Gather exception path in `execute_on_group` now redacts credentials via `_redact_secrets`.
- ASGI 401 responses now include `Content-Length` header (proxy interop) and `WWW-Authenticate` on invalid-token path (RFC 7235 compliance).
- `SSH_MCP_HTTP_PORT` validated with try/except and range check (1–65535).
- `max_output_bytes` upper bound added (`le=10_485_760` / 10 MiB) to prevent unbounded memory.
- Explicit `except asyncio.CancelledError: raise` in `_mcp_tool` decorator for defensive cancellation handling.

### Added

- Connection pool size periodic log in eviction loop (`Connection pool: N active, N locks` every 60s).
- 6 new mutation-gap regression tests: audit-log redaction on success/timeout, eviction loop crash→restart, lifespan assertion, max_output_bytes bounds.

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

[Unreleased]: https://github.com/blackaxgit/ssh-mcp/compare/v0.5.6...HEAD
[0.5.6]: https://github.com/blackaxgit/ssh-mcp/compare/v0.5.5...v0.5.6
[0.5.5]: https://github.com/blackaxgit/ssh-mcp/compare/v0.5.4...v0.5.5
[0.5.4]: https://github.com/blackaxgit/ssh-mcp/compare/v0.5.3...v0.5.4
[0.5.3]: https://github.com/blackaxgit/ssh-mcp/compare/v0.5.2...v0.5.3
[0.5.2]: https://github.com/blackaxgit/ssh-mcp/compare/v0.5.1...v0.5.2
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
