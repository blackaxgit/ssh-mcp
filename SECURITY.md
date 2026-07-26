# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.6.x   | Yes       |
| ≤ 0.5.6 | No        |

Older versions are not supported. Please upgrade to the latest 0.6.x release before reporting an issue.

**0.6.0 contains security fixes. Versions ≤ 0.5.6 are affected by a local-path
confinement flaw in the SFTP tools that allows an MCP client to write to
arbitrary paths on the machine running ssh-mcp, including files that lead to
code execution there.** See the CHANGELOG entry for 0.6.0. Upgrade rather than
patching in place; the fix changes the `upload_file`/`download_file` path
contract.

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

ssh-mcp does not manage SSH credentials directly. All authentication is delegated to the system SSH agent and `~/.ssh/config`. Private keys never pass through this tool. Ensure your SSH keys follow least-privilege principles and are protected with passphrases.

### Command Execution

The `execute` and `execute_on_group` tools run arbitrary shell commands on remote servers as the configured SSH user. The AI assistant invoking these tools has the same privileges as that user. Apply standard SSH hardening:

- Use dedicated low-privilege accounts where possible
- Restrict sudo access on target servers
- Enable SSH audit logging on remote hosts

### Dangerous Command Detection

ssh-mcp **blocks** commands matching a list of commonly destructive patterns (e.g. `rm -rf /`, `mkfs`, disk wipes) and returns an error instead of executing them. A caller may bypass the block by passing `force=true`, which is recorded in the audit log. This is a safety feature, not a vulnerability.

The pattern list is a **tripwire for accidents, not a security boundary**: base64-encoded payloads, shell hex escapes, Unicode homoglyphs and indirection via `$(...)`/`eval` are acknowledged bypasses. See the README for the full statement of what it does and does not defend against. The responsibility for authorizing commands lies with the operator.

### known_hosts Verification

ssh-mcp uses asyncssh's default host key verification. Disabling host key checking in `~/.ssh/config` via `StrictHostKeyChecking no` weakens man-in-the-middle protection and should be avoided in production environments.

### Configuration File Permissions

`~/.config/ssh-mcp/servers.toml` may contain server hostnames and group metadata. Restrict its permissions to the owning user:

```bash
chmod 600 ~/.config/ssh-mcp/servers.toml
```

### SFTP File Transfers

The `upload_file` and `download_file` tools transfer files using SFTP over the same authenticated SSH session. Validate file paths and content before uploading to remote servers, particularly in automated workflows.

## What Is Not a Vulnerability

The following behaviors are intentional design decisions, not security flaws:

- Dangerous-command blocks bypassed via the documented `force=true` parameter, or via obfuscation (base64, hex escapes, homoglyphs, subshell indirection) — the pattern list is a documented tripwire, not a security boundary
- The tool executing whatever command the invoking AI assistant sends — access control is the operator's responsibility via SSH permissions
- Lack of a built-in allowlist/blocklist for commands — this is a general-purpose infrastructure tool
