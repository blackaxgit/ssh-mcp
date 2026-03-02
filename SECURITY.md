# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.1.x   | Yes       |

Older versions are not supported. Please upgrade to the latest 0.1.x release before reporting an issue.

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

ssh-mcp warns before executing commands that are commonly destructive (e.g., `rm -rf`, disk wipes, shutdown). These warnings are a safety feature, not a vulnerability. They are intentionally non-blocking to preserve tool utility; the responsibility for authorizing commands lies with the operator.

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

- Dangerous command warnings that can be bypassed — warnings are informational guardrails, not hard blocks
- The tool executing whatever command the invoking AI assistant sends — access control is the operator's responsibility via SSH permissions
- Lack of a built-in allowlist/blocklist for commands — this is a general-purpose infrastructure tool
