# Security Policy

## Supported Versions

| Version            | Supported |
|--------------------|-----------|
| 0.6.x (unreleased) | Yes       |
| ≤ 0.5.6            | No        |

Older versions are not supported. Please upgrade to the latest 0.6.x release before reporting an issue.

**0.6.0 is not released yet.** The latest tag and `__version__` are still 0.5.6,
so there is currently no released version carrying the fix below — build from
`main` or wait for the 0.6.0 release.

**0.6.0 contains security fixes. Versions ≤ 0.5.6 are affected by a local-path
confinement flaw in the SFTP tools that allows an MCP client to write to
arbitrary paths on the machine running ssh-mcp, including files that lead to
code execution there.** See the `[Unreleased]` section of the CHANGELOG, which
ships as 0.6.0. Upgrade rather than patching in place; the fix changes the
`upload_file`/`download_file` path contract.

## Reporting a Vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

Report vulnerabilities through [GitHub Security Advisories](https://github.com/blackaxgit/ssh-mcp/security/advisories/new). Include:

- A clear description of the vulnerability
- Steps to reproduce
- Potential impact assessment
- Any suggested mitigations (optional)

You will receive an acknowledgment within 72 hours and a status update within 7 days. If a fix is warranted, a patched release will be coordinated before public disclosure.

## Response Timeline

| Stage              | Target      |
|--------------------|-------------|
| Acknowledgment     | 72 hours    |
| Status update      | 7 days      |
| Patch release      | 30 days     |
| Public disclosure  | After patch |

## SSH-Specific Security Considerations

### Credential Handling

ssh-mcp does not manage SSH credentials directly. Authentication is delegated to the system SSH agent and to an SSH config file — `~/.ssh/config` by default, overridable via the `ssh_config_path` setting. ssh-mcp never stores, prompts for, or transmits a credential of its own.

Two qualifications worth knowing:

- If a server sets `identity_file`, that path is handed to asyncssh as `client_keys`, so the private key is read and parsed **inside the ssh-mcp process**. Only the agent path keeps key material out of the process entirely.
- There is no passphrase support. A passphrase-protected `identity_file` fails to load rather than prompting; use the SSH agent for passphrase-protected keys.

Ensure your SSH keys follow least-privilege principles.

### Command Execution

The `execute` and `execute_on_group` tools run arbitrary shell commands on remote servers as the configured SSH user. The AI assistant invoking these tools has the same privileges as that user. Apply standard SSH hardening:

- Use dedicated low-privilege accounts where possible
- Restrict sudo access on target servers
- Enable SSH audit logging on remote hosts

### Dangerous Command Detection

ssh-mcp **blocks** commands matching a list of commonly destructive patterns (e.g. `rm -rf /`, `mkfs`, disk wipes) and returns an error instead of executing them. A caller may bypass the block by passing `force=true`. This is a safety feature, not a vulnerability.

**The bypass is not recorded in the audit log.** Audit records carry `server`, `command`, `exit_code` and `duration_ms` only; `force` is emitted solely as an OpenTelemetry span attribute (`ssh.force`), and therefore only when the optional `otel` extra is installed and an exporter is configured. A block is logged as a warning on the operational logger, not the audit logger. If you need a paper trail for bypasses, export traces or withhold `force=true` at the MCP client.

The pattern list is a **tripwire for accidents, not a security boundary**: base64-encoded payloads, shell hex escapes, Unicode homoglyphs and indirection via `$(...)`/`eval` are acknowledged bypasses. See the README for the full statement of what it does and does not defend against. The responsibility for authorizing commands lies with the operator.

### known_hosts Verification

Host key verification is on by default: ssh-mcp uses asyncssh's default verification unless the `known_hosts` setting is set to `false`, in which case verification is disabled for **every** server. That setting is the real kill switch — ssh-mcp only logs a warning and continues. Leave it at `true` in production.

Disabling host key checking in the SSH config via `StrictHostKeyChecking no` weakens man-in-the-middle protection the same way and should also be avoided.

### Configuration File Permissions

`servers.toml` is resolved from `SSH_MCP_CONFIG`, else `$XDG_CONFIG_HOME/ssh-mcp/servers.toml` (defaulting to `~/.config/ssh-mcp/servers.toml`), else a `config/servers.toml` beside the package for development.

Treat it as a security-relevant file, not just inventory. Besides hostnames and group metadata it carries `user`, `identity_file` paths, `jump_host`, `transfer_root`, and the `known_hosts` toggle — so write access to it is enough to disable man-in-the-middle protection or repoint the SFTP transfer root. Restrict its permissions to the owning user:

```bash
chmod 600 ~/.config/ssh-mcp/servers.toml
```

**This is advisory: ssh-mcp does not verify the mode or owner of `servers.toml`.** (`transfer_root` is different — its `0700` mode and ownership *are* enforced at startup, see below.) A file-permission check on `servers.toml` would be a welcome hardening contribution, but its absence is a known gap, not a vulnerability report.

### SFTP File Transfers

The `upload_file` and `download_file` tools transfer files using SFTP over the same authenticated SSH session. Since 0.6.0 the **local** side is confined rather than validated:

- Local paths are **relative to `transfer_root`** (default under `$XDG_DATA_HOME`, override with `SSH_MCP_TRANSFER_ROOT`). Absolute paths and `..` are rejected.
- The root is created `0700` on demand and must be a real directory owned by the running user and inaccessible to group/other — otherwise ssh-mcp refuses the transfer.
- Each path component is opened beneath a pinned directory descriptor with `O_NOFOLLOW`, so a symlink *anywhere* in the path aborts the walk. A caller-supplied local path never reaches the SFTP library.
- Downloads use `O_CREAT|O_EXCL` and **never overwrite**; a failed download unlinks its own partial file, guarded by a `(st_dev, st_ino)` identity check.
- Non-regular local files, and existing non-regular remote destinations, are refused.
- A 100 MiB size limit applies: an oversized upload is refused before any bytes move, while an oversized download is warned about after the fact (the count comes from the descriptor just written).

**POSIX only.** Transfers require `dir_fd` support plus `O_NOFOLLOW`/`O_DIRECTORY`. On a platform without them (including Windows) file transfer **fails closed** rather than running without symlink protection.

Remote paths are still validated by name, not confined — see below.

### Remote Path Validation

Remote paths passed to the SFTP tools are rejected if they contain `..` or match a denylist of sensitive locations (`/etc/shadow`, `~/.ssh/*` key material and `config`, cloud and Kubernetes credentials, `.netrc`, `.pgpass`, `/proc/<pid>/{environ,mem,maps,…}`, and similar).

Like the dangerous-command list, this is a **tripwire, not a security boundary**: matching is substring-based after `normpath` and case-folding, `..` is blocked lexically only, and no symlink resolution happens on the remote side. Anything not enumerated is permitted, and the remote SSH user's own permissions remain the real boundary.

### Credential Redaction in Logs

Known credential patterns in the **command string** (`-p<pass>`, `--password=`, `PGPASSWORD=`, `Authorization: Bearer`, URL basic-auth, `*_PASSWORD`/`_SECRET`/`_TOKEN`/`_KEY` env assignments) are redacted before reaching audit logs, stderr, or OTel span attributes.

This is a tripwire too, with two documented limits: multi-word **quoted** values are only partially redacted, and command **output** is never redacted at all — `env | grep PASSWORD` returns plaintext to the MCP client by design. Pass credentials via env files, secret stores, or stdin rather than argv.

### Resource Limits

Several bounds exist for denial-of-service reasons and should not be raised casually:

- `max_command_bytes` (default 64 KiB) caps command length **at the MCP tool boundary**, because redaction and dangerous-pattern matching are superlinear and reachable without an SSH connection or SSH authentication via `dry_run=true`.
- `max_output_bytes` bounds allocation per stream, so the real process ceiling is 2x the configured value (stdout plus stderr).
- `max_parallel_hosts` bounds concurrent SSH connections **process-wide**, not per call.

### HTTP Transport

The streamable HTTP transport is the highest-risk deployment surface: reaching the port means being able to execute commands on the managed fleet.

- The default bind, `127.0.0.1:8000`, is **unauthenticated by design** — it matches the single-user stdio deployment model. This is intentional and not a vulnerability report.
- Bearer auth is configured via `SSH_MCP_HTTP_TOKEN` or `SSH_MCP_HTTP_TOKEN_FILE`. Tokens must be at least 16 characters and are compared in constant time. Prefer the file form, keep it `0600`, and rotate by restarting with a new value — there is no online rotation.
- Binding a non-localhost address without a token **aborts startup**. Setting `SSH_MCP_HTTP_AUTH=none` on such a bind additionally requires the literal acknowledgement `SSH_MCP_HTTP_NETWORK_NO_AUTH=I_ACCEPT_RCE_RISK`.
- DNS-rebinding protection is always enabled, and wildcard entries in `SSH_MCP_HTTP_ALLOWED_HOSTS` are rejected rather than silently disabling it.

If you expose ssh-mcp beyond loopback, terminate TLS and authenticate at a reverse proxy; the bearer token is a single shared secret, not a user model.

## What Is Not a Vulnerability

The following behaviors are intentional design decisions, not security flaws:

- Dangerous-command blocks bypassed via the documented `force=true` parameter, or via obfuscation (base64, hex escapes, homoglyphs, subshell indirection) — the pattern list is a documented tripwire, not a security boundary
- The tool executing whatever command the invoking AI assistant sends — access control is the operator's responsibility via SSH permissions
- Lack of a built-in allowlist/blocklist for commands — this is a general-purpose infrastructure tool
- Secrets appearing in command **output** returned to the MCP client, and multi-word quoted credential values being only partially redacted in logs — redaction covers the command string and is a tripwire, documented above
- Remote sensitive paths not on the denylist being reachable via SFTP — remote-path checking is a name-based tripwire; the remote user's permissions are the boundary
- The default `127.0.0.1` HTTP bind being unauthenticated — deliberate, and non-localhost binds are gated as described above
- The three accepted residual races, all documented in the source: a same-filesystem `rename()` of an intermediate directory between two `os.open` calls during the confined walk, the stat-then-unlink gap when removing a partial download, and the non-atomic no-follow check on the **remote** side (SFTP protocol v3 offers no atomic no-follow open). None of them let a local write escape `transfer_root`.
