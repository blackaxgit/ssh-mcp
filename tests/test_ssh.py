"""Unit tests for SSH MCP security-critical functions in ssh.py.

Tests cover dangerous command detection, path validation, and SSHManager
initialization. All tests run without real SSH connections.
"""

from __future__ import annotations

import asyncio

import pytest
from hypothesis import given
from hypothesis import strategies as st

from ssh_mcp.config import ServerRegistry
from ssh_mcp.models import ExecResult, Settings
from ssh_mcp.ssh import (
    SSHManager,
    _DANGEROUS_PATTERNS,
    _REDACTION_PLACEHOLDER,
    _SENSITIVE_PATHS,
    _is_dangerous_command,
    _make_connection_id,
    _redact_secrets,
    _validate_local_path,
    _validate_remote_path,
)


# ---------------------------------------------------------------------------
# Dangerous command detection
# ---------------------------------------------------------------------------


class TestIsDangerousCommand:
    """Tests for _is_dangerous_command using _DANGEROUS_PATTERNS."""

    # --- Commands that MUST be blocked ---

    @pytest.mark.parametrize(
        "command",
        [
            # rm -rf /  variants
            "rm -rf /",
            "rm  -rf  /",
            "rm -rf /home",
            "rm -rf /var/log",
            "sudo rm -rf /",
            "rm -rf /tmp/../etc",
            # mkfs variants
            "mkfs.ext4 /dev/sda",
            "mkfs.xfs /dev/sdb1",
            "mkfs /dev/sda",
            "sudo mkfs.vfat /dev/sdc",
            # dd if= variants
            "dd if=/dev/zero of=/dev/sda",
            "dd if=/dev/urandom of=/disk bs=1M",
            "dd if=/dev/sda of=/dev/sdb",
            # redirect to /dev/sd*
            "> /dev/sda",
            "cat /dev/zero > /dev/sdb",
            "echo bad > /dev/sdc",
            # chmod 777 /  variants
            "chmod 777 /",
            "chmod 777 /etc",
            "sudo chmod 777 /var",
            # fork bomb
            ":(){ :|:& };:",
            ":(){ :|:& };: ",
        ],
        ids=lambda c: c[:40].replace(" ", "_"),
    )
    def test_blocks_dangerous_command(self, command: str) -> None:
        """_is_dangerous_command returns True for commands that match patterns."""
        assert _is_dangerous_command(command) is True

    # --- Commands that MUST NOT be blocked ---

    @pytest.mark.parametrize(
        "command",
        [
            "ls -la",
            "cat /var/log/syslog",
            "df -h",
            "ps aux",
            "uptime",
            "whoami",
            "echo hello",
            "pwd",
            "find /tmp -name '*.log'",
            "grep -r error /var/log/app",
            "tail -f /var/log/nginx/access.log",
            "systemctl status nginx",
            # rm -rf targeting a relative path (no leading /) is safe
            "rm -rf mydir",
            "rm -rf ./cache",
            # chmod with numeric mode but no / prefix is safe
            "chmod 777 mydir",
            "chmod 777 ./scripts",
            "cat /etc/hostname",
            "date",
            "env",
        ],
        ids=lambda c: c[:40].replace(" ", "_"),
    )
    def test_allows_safe_command(self, command: str) -> None:
        """_is_dangerous_command returns False for safe commands."""
        assert _is_dangerous_command(command) is False

    def test_empty_string_is_safe(self) -> None:
        """An empty command string is not dangerous."""
        assert _is_dangerous_command("") is False

    def test_rm_rf_without_slash_is_safe(self) -> None:
        """rm -rf without any leading / is not dangerous."""
        assert _is_dangerous_command("rm -rf mydir") is False

    def test_rm_rf_relative_path_is_safe(self) -> None:
        """rm -rf on a relative path (no /) is safe."""
        assert _is_dangerous_command("rm -rf ./builddir") is False

    def test_rm_rf_absolute_path_is_dangerous(self) -> None:
        """rm -rf on any absolute path (with /) is dangerous per the pattern."""
        # Pattern is rm\s+-rf\s+/ — matches any absolute path
        assert _is_dangerous_command("rm -rf /tmp/builddir") is True

    def test_chmod_777_any_absolute_path_is_dangerous(self) -> None:
        """chmod 777 on any absolute path (with /) is dangerous per the pattern."""
        # Pattern is chmod\s+777\s+/ — matches any path beginning with /
        assert _is_dangerous_command("chmod 777 /home/user/public") is True

    def test_chmod_777_relative_path_is_safe(self) -> None:
        """chmod 777 on a relative path (no leading /) is safe."""
        assert _is_dangerous_command("chmod 777 mydir") is False

    def test_mkfs_in_path_name_is_dangerous(self) -> None:
        """mkfs anywhere in the command string triggers the pattern."""
        # The pattern is a simple substring match on 'mkfs'
        assert _is_dangerous_command("sudo mkfs.btrfs /dev/sde") is True

    def test_dd_if_requires_equals(self) -> None:
        """dd without 'if=' is not matched by the dangerous pattern."""
        assert _is_dangerous_command("dd bs=512 count=100") is False

    def test_pipes_do_not_suppress_dangerous_detection(self) -> None:
        """Dangerous command embedded in a pipeline is still detected."""
        assert _is_dangerous_command("echo test | rm -rf /") is True

    def test_semicolon_separated_dangerous_command(self) -> None:
        """Dangerous command after a semicolon is still detected."""
        assert _is_dangerous_command("ls -la; rm -rf /") is True

    # --- Null-byte and control-character injection bypass attempts ---

    def test_null_byte_between_rm_and_flag_is_still_dangerous(self) -> None:
        """Null byte injected between 'rm' and '-rf' must not bypass detection."""
        # Without sanitization "rm\x00-rf /" would not match r"rm\s+-rf\s+/"
        # because \x00 is not \s. Sanitization strips it before matching.
        assert _is_dangerous_command("rm\x00-rf /") is True

    def test_null_byte_before_mkfs_device_is_still_dangerous(self) -> None:
        """Null byte between mkfs and device path must not bypass detection."""
        assert _is_dangerous_command("mkfs\x00/dev/sda") is True

    def test_embedded_newline_in_rm_rf_is_still_dangerous(self) -> None:
        """Embedded newline splitting 'rm -rf /' must not bypass detection."""
        assert _is_dangerous_command("rm -rf\n/") is True

    def test_carriage_return_in_rm_rf_is_still_dangerous(self) -> None:
        """Carriage return splitting token must not bypass detection."""
        assert _is_dangerous_command("rm\r-rf /") is True

    def test_multiple_control_chars_do_not_bypass_detection(self) -> None:
        """Multiple interspersed control chars must not bypass detection."""
        assert _is_dangerous_command("rm\x01\x02-rf\x03 /") is True

    def test_null_byte_only_command_is_safe(self) -> None:
        """A command consisting only of null bytes produces an empty string — safe."""
        assert _is_dangerous_command("\x00\x00\x00") is False

    def test_control_chars_around_safe_command_remain_safe(self) -> None:
        """Control chars around a safe command do not make it dangerous."""
        assert _is_dangerous_command("\x01ls\x02 -la\x03") is False


# ---------------------------------------------------------------------------
# _DANGEROUS_PATTERNS coverage: each pattern tested individually
# ---------------------------------------------------------------------------


class TestDangerousPatternsDirectly:
    """Ensure every compiled pattern in _DANGEROUS_PATTERNS fires correctly.

    These tests use ``_is_dangerous_command`` (the public entry point) rather
    than ``_DANGEROUS_PATTERNS[n]`` with hardcoded indices — Red Team R3
    added several new patterns and the indices would be brittle to future
    extensions.
    """

    def test_pattern_list_is_nonempty(self) -> None:
        """Sanity: at least the original six patterns plus R3 additions."""
        assert len(_DANGEROUS_PATTERNS) >= 6

    def test_rm_rf_slash_pattern(self) -> None:
        assert _is_dangerous_command("rm -rf /") is True
        assert _is_dangerous_command("rm -rf /tmp") is True
        assert _is_dangerous_command("rm -rf mydir") is False

    def test_mkfs_pattern(self) -> None:
        assert _is_dangerous_command("mkfs.ext4 /dev/sda") is True
        assert _is_dangerous_command("mkfs") is True

    def test_dd_if_pattern(self) -> None:
        assert _is_dangerous_command("dd if=/dev/zero of=/dev/sda") is True
        assert _is_dangerous_command("dd if=input.bin of=output.bin") is True
        assert _is_dangerous_command("dd bs=512 count=1") is False

    def test_redirect_dev_sd_pattern(self) -> None:
        assert _is_dangerous_command("> /dev/sda") is True
        assert _is_dangerous_command("echo x > /dev/sdb") is True
        assert _is_dangerous_command("echo x > /dev/null") is False

    def test_chmod_777_slash_pattern(self) -> None:
        assert _is_dangerous_command("chmod 777 /") is True
        assert _is_dangerous_command("chmod 777 /etc") is True
        assert _is_dangerous_command("chmod 777 /home/user") is True
        # Relative paths (no /) are safe
        assert _is_dangerous_command("chmod 777 mydir") is False
        assert _is_dangerous_command("chmod 777 ./scripts") is False

    def test_fork_bomb_pattern(self) -> None:
        assert _is_dangerous_command(":(){ :|:& };:") is True
        assert _is_dangerous_command(":(){ :|:&};:") is True
        # R3 extension: spaced variants also caught
        assert _is_dangerous_command(":() { :|:& };:") is True
        assert _is_dangerous_command(":()  {  :|:&  };:") is True
        # Unrelated strings do not match
        assert _is_dangerous_command("echo hello") is False
        assert _is_dangerous_command("ls -la") is False


# ---------------------------------------------------------------------------
# Path validation
# ---------------------------------------------------------------------------


class TestValidateRemotePath:
    """Tests for _validate_remote_path."""

    # --- Paths that MUST be blocked ---

    @pytest.mark.parametrize(
        "path",
        [
            # Parent directory traversal
            "/var/log/../etc/shadow",
            "../../etc/passwd",
            "/home/user/../../etc/shadow",
            "/tmp/../tmp/../etc/shadow",
            # Sensitive files (exact paths)
            "/etc/shadow",
            "/etc/passwd",
            "/root/.ssh/authorized_keys",
            "/home/user/.ssh/authorized_keys",
            "/home/user/.ssh/id_rsa",
            "/home/user/.ssh/id_ed25519",
            "/home/user/.ssh/id_ecdsa",
            "/home/user/.ssh/id_dsa",
            # Case insensitive variants
            "/etc/SHADOW",
            "/ETC/passwd",
            "/home/user/.SSH/id_rsa",
        ],
        ids=lambda p: p.replace("/", "_").replace(".", "_")[:50],
    )
    def test_blocks_sensitive_path(self, path: str) -> None:
        """_validate_remote_path raises ValueError for sensitive or traversal paths."""
        with pytest.raises(ValueError):
            _validate_remote_path(path)

    # --- Paths that MUST be allowed ---

    @pytest.mark.parametrize(
        "path",
        [
            "/var/log/app.log",
            "/home/user/file.txt",
            "/tmp/data",
            "/opt/app/config.yaml",
            "/srv/www/index.html",
            "/etc/nginx/nginx.conf",
            # NOTE: /var/lib/mysql/ is deliberately NOT in this list — Red Team
            # R3 added it to _SENSITIVE_PATHS because direct filesystem access
            # to database data files can exfiltrate tables/secrets.
            "/usr/local/bin/script.sh",
            "/backups/2026-01-01/dump.sql",
            "/home/user/.ssh/id_ed25519.pub",  # public keys are legitimate
        ],
        ids=lambda p: p.replace("/", "_")[:50],
    )
    def test_allows_normal_path(self, path: str) -> None:
        """_validate_remote_path does not raise for normal paths."""
        _validate_remote_path(path)  # Should not raise

    def test_traversal_raises_value_error_with_message(self) -> None:
        """ValueError message mentions traversal for .. paths."""
        with pytest.raises(ValueError, match="traversal"):
            _validate_remote_path("/var/log/../etc/shadow")

    def test_sensitive_path_raises_value_error_with_message(self) -> None:
        """ValueError message mentions sensitive path when blocked."""
        with pytest.raises(ValueError, match="sensitive"):
            _validate_remote_path("/etc/shadow")

    def test_double_dot_anywhere_in_path_is_blocked(self) -> None:
        """A '..' segment anywhere in the path triggers the traversal guard."""
        with pytest.raises(ValueError):
            _validate_remote_path("/valid/path/with/../traversal/attempt")

    def test_dotdot_in_filename_is_blocked(self) -> None:
        """A filename containing '..' is blocked even if not a traversal."""
        with pytest.raises(ValueError):
            _validate_remote_path("/tmp/my..file")

    def test_sensitive_paths_list_coverage(self) -> None:
        """Every entry in _SENSITIVE_PATHS triggers a ValueError.

        Directory-style entries (ending with ``/``) are tested by appending
        a child filename. File-style absolute entries are tested as-is.
        Relative entries (``.ssh/id_rsa``) are prepended with a home dir.
        Windows ``\\...`` entries are covered separately since substring
        matching on backslashes is awkward inside test strings.
        """
        for sensitive in _SENSITIVE_PATHS:
            if sensitive.startswith("\\"):
                continue  # Windows entries — covered by TestExpandedSensitiveAllowlist
            if sensitive.endswith("/"):
                # Directory — test with a file inside
                path = sensitive + "secret.txt"
            elif sensitive.startswith("/"):
                # Absolute file — test as-is
                path = sensitive
            else:
                # Relative — prepend a home
                path = f"/home/user/{sensitive}"
            with pytest.raises(ValueError, match="sensitive"):
                _validate_remote_path(path)


# ---------------------------------------------------------------------------
# SSHManager initialization (no real SSH connections)
# ---------------------------------------------------------------------------


class TestSSHManagerInit:
    """Tests for SSHManager initialization and configuration storage."""

    def _make_registry(self) -> ServerRegistry:
        """Return a minimal ServerRegistry backed by a real config file."""
        import tempfile

        config_content = """
[settings]
command_timeout = 30

[groups]
test = { description = "Test group" }

[servers.test-host]
description = "Test server"
groups = ["test"]
"""
        tmp = tempfile.NamedTemporaryFile(suffix=".toml", mode="w", delete=False)
        tmp.write(config_content)
        tmp.flush()
        tmp.close()
        return ServerRegistry(tmp.name)

    def test_registry_stored_on_init(self, sample_settings: Settings) -> None:
        """SSHManager stores the registry reference passed at construction."""
        registry = self._make_registry()
        manager = SSHManager(registry, sample_settings)
        assert manager.registry is registry

    def test_settings_stored_on_init(self, sample_settings: Settings) -> None:
        """SSHManager stores the settings reference passed at construction."""
        registry = self._make_registry()
        manager = SSHManager(registry, sample_settings)
        assert manager.settings is sample_settings

    def test_connection_pool_starts_empty(self, sample_settings: Settings) -> None:
        """The internal connection pool dict is empty on init."""
        registry = self._make_registry()
        manager = SSHManager(registry, sample_settings)
        assert manager._connections == {}

    def test_last_used_starts_empty(self, sample_settings: Settings) -> None:
        """The last-used tracking dict is empty on init."""
        registry = self._make_registry()
        manager = SSHManager(registry, sample_settings)
        assert manager._last_used == {}

    def test_locks_start_empty(self, sample_settings: Settings) -> None:
        """The per-server locks dict is empty on init."""
        registry = self._make_registry()
        manager = SSHManager(registry, sample_settings)
        assert manager._locks == {}

    def test_custom_settings_reflected(self) -> None:
        """SSHManager correctly stores non-default Settings values."""
        custom_settings = Settings(
            command_timeout=120,
            max_output_bytes=102400,
            connection_idle_timeout=600,
            known_hosts=True,
        )
        registry = self._make_registry()
        manager = SSHManager(registry, custom_settings)

        assert manager.settings.command_timeout == 120
        assert manager.settings.max_output_bytes == 102400
        assert manager.settings.connection_idle_timeout == 600
        assert manager.settings.known_hosts is True

    def test_audit_logger_configured(self, sample_settings: Settings) -> None:
        """SSHManager sets up the audit logger under ssh_mcp.audit."""
        import logging

        registry = self._make_registry()
        manager = SSHManager(registry, sample_settings)

        assert manager._audit is logging.getLogger("ssh_mcp.audit")

    def test_eviction_not_started_without_event_loop(
        self, sample_settings: Settings
    ) -> None:
        """SSHManager defers eviction start when no event loop is running."""
        registry = self._make_registry()
        manager = SSHManager(registry, sample_settings)
        # Eviction is deferred — _running should be False
        assert manager._running is False
        assert manager._eviction_task is None

    async def test_group_execution_semaphore_uses_max_parallel_hosts(self) -> None:
        """execute_on_group's concurrency semaphore reflects Settings.max_parallel_hosts.

        Guards against regressing the hardcoded ``Semaphore(10)``. We inject a
        custom ``max_parallel_hosts`` and assert the semaphore built inside
        ``execute_on_group`` has the matching bound by patching
        ``asyncio.Semaphore`` and capturing its first positional argument.
        """
        from unittest.mock import patch

        settings = Settings(max_parallel_hosts=7)
        registry = self._make_registry()
        manager = SSHManager(registry, settings)

        captured: list[int] = []
        real_semaphore = asyncio.Semaphore

        def capturing_semaphore(value: int) -> asyncio.Semaphore:
            captured.append(value)
            return real_semaphore(value)

        with patch("ssh_mcp.ssh.asyncio.Semaphore", side_effect=capturing_semaphore):
            # Group has 1 test-host, so only 1 execute will be attempted;
            # the real execute will fail (no SSH), but by then the Semaphore
            # is already constructed.
            try:
                await manager.execute_on_group("test", "true")
            except Exception:
                pass

        assert captured, "Semaphore was never constructed in execute_on_group"
        assert captured[0] == 7


# ---------------------------------------------------------------------------
# _validate_local_path
# ---------------------------------------------------------------------------


class TestValidateLocalPath:
    """Tests for _validate_local_path — blocks sensitive local files."""

    @pytest.mark.parametrize(
        "path",
        [
            "/home/user/../etc/shadow",
            "../../etc/passwd",
            "/etc/shadow",
            "/etc/passwd",
            "/home/user/.ssh/authorized_keys",
            "/home/user/.ssh/id_rsa",
            "/home/user/.ssh/id_ed25519",
        ],
        ids=lambda p: p.replace("/", "_").replace(".", "_")[:50],
    )
    def test_blocks_sensitive_local_path(self, path: str) -> None:
        with pytest.raises(ValueError):
            _validate_local_path(path)

    @pytest.mark.parametrize(
        "path",
        [
            "/var/log/app.log",
            "/home/user/file.txt",
            "/tmp/data",
            "/opt/app/config.yaml",
        ],
        ids=lambda p: p.replace("/", "_")[:50],
    )
    def test_allows_normal_local_path(self, path: str) -> None:
        _validate_local_path(path)  # Should not raise

    def test_sensitive_local_paths_list_coverage(self) -> None:
        for sensitive in _SENSITIVE_PATHS:
            if sensitive.startswith("\\"):
                continue
            if sensitive.endswith("/"):
                path = sensitive + "secret.txt"
            elif sensitive.startswith("/"):
                path = sensitive
            else:
                path = f"/home/user/{sensitive}"
            with pytest.raises(ValueError):
                _validate_local_path(path)


# ---------------------------------------------------------------------------
# Red-team hardening: path normalization + expanded allowlist (RT-Fix 1)
# ---------------------------------------------------------------------------


class TestLogInjectionSanitization:
    """Red Team R3 finding C4: values interpolated into log messages must
    be escaped so embedded newlines cannot forge extra log records.
    """

    def _make_registry_with_server(self, name: str = "victim") -> ServerRegistry:
        import tempfile

        toml = f"""
[groups]
t = {{ description = "t" }}
[servers.{name}]
description = "t"
groups = ["t"]
"""
        f = tempfile.NamedTemporaryFile(suffix=".toml", mode="w", delete=False)
        f.write(toml)
        f.close()
        return ServerRegistry(f.name)

    async def test_blocked_dangerous_command_log_escapes_newlines(
        self,
        caplog: pytest.LogCaptureFixture,
        sample_settings: Settings,
    ) -> None:
        """Command with CRLF does not produce multi-line log output."""
        manager = SSHManager(self._make_registry_with_server(), sample_settings)

        with caplog.at_level("WARNING", logger="ssh_mcp.ssh"):
            await manager.execute(
                "victim",
                "rm -rf /\nFORGED_LINE=attacker",
                dry_run=False,
            )

        # Scan every emitted record for raw newlines inside the rendered
        # message — if any record contains a literal \n in its message
        # body (not the trailing record separator), the interpolation leaked.
        for record in caplog.records:
            rendered = record.getMessage()
            # FORGED_LINE should only appear in escaped form (\\nFORGED...)
            if "FORGED_LINE" in rendered:
                assert "\\n" in rendered, (
                    f"Log injection: raw newline leaked in {rendered!r}"
                )
                assert "\nFORGED" not in rendered, (
                    f"Raw newline before FORGED: {rendered!r}"
                )


class TestPathNormalizationBypasses:
    """Paths that resolve to sensitive files must be blocked after normalization.

    Red Team R3 finding C1: ``/etc//shadow`` and ``/etc/./shadow`` are both
    valid Unix paths that resolve to ``/etc/shadow``, but the naive substring
    check in the original implementation missed them.
    """

    @pytest.mark.parametrize(
        "path",
        [
            "/etc//shadow",
            "/etc/./shadow",
            "/etc/././shadow",
            "/etc//./shadow",
            "//etc/shadow",
            "/etc///shadow",
            "/./etc/shadow",
            "/./etc/./shadow",
        ],
    )
    def test_double_slash_bypass_blocked(self, path: str) -> None:
        """Double-slash and dot-slash obfuscations of /etc/shadow must fail."""
        with pytest.raises(ValueError):
            _validate_remote_path(path)

    @pytest.mark.parametrize(
        "path",
        [
            "/etc//shadow",
            "/etc/./shadow",
        ],
    )
    def test_double_slash_bypass_blocked_local(self, path: str) -> None:
        """Same protection for local SFTP paths."""
        with pytest.raises(ValueError):
            _validate_local_path(path)


class TestExpandedSensitiveAllowlist:
    """Cloud credentials, k8s secrets, proc memory, Windows paths all blocked.

    Red Team R3 finding C2: the original allowlist only covered classic Unix
    system files and SSH keys. Modern infrastructure hosts cloud tokens and
    k8s kubeconfigs that are equally sensitive.
    """

    @pytest.mark.parametrize(
        "path",
        [
            # Cloud credentials
            "/home/user/.aws/credentials",
            "/home/user/.aws/config",
            "/home/user/.azure/accessTokens.json",
            "/home/user/.config/gcloud/credentials.db",
            # Kubernetes
            "/home/user/.kube/config",
            "/var/lib/kubelet/pki/kubelet-client.key",
            "/etc/kubernetes/admin.conf",
            # Shell credential caches
            "/home/user/.netrc",
            "/home/user/.pgpass",
            "/home/user/.git-credentials",
            "/home/user/.docker/config.json",
            # Process memory / kernel
            "/proc/self/mem",
            "/proc/self/environ",
            "/proc/1234/environ",
            "/proc/kcore",
            # Database data files
            "/var/lib/mysql/mysql/user.MYD",
            "/var/lib/postgresql/16/main/base/1/",
            # Additional Unix secrets
            "/etc/sudoers",
            "/etc/gshadow",
        ],
    )
    def test_sensitive_path_blocked(self, path: str) -> None:
        with pytest.raises(ValueError):
            _validate_remote_path(path)

    def test_ssh_pub_key_allowed(self) -> None:
        """.pub keys are NOT secret — allow SFTP upload/download of public keys.

        Red Team R3 finding H5: the previous substring match blocked
        ``id_ed25519.pub`` because it contains the substring ``id_ed25519``.
        This broke legitimate public-key distribution via SFTP.
        """
        _validate_remote_path("/home/user/.ssh/id_ed25519.pub")
        _validate_remote_path("/home/user/.ssh/id_rsa.pub")
        _validate_remote_path("/home/user/.ssh/id_ecdsa.pub")
        _validate_remote_path("/home/user/.ssh/id_dsa.pub")
        _validate_local_path("/tmp/deploy_key.pub")


# ---------------------------------------------------------------------------
# force=True bypass
# ---------------------------------------------------------------------------


class TestDangerousCommandR4Extensions:
    """Red Team R4 bypasses: case-insensitivity, flag combos, $HOME, more verbs."""

    @pytest.mark.parametrize(
        "command",
        [
            # R4-F1: regex was case-sensitive, uppercase bypassed
            "rm -RF /",
            "rm -RF ~",
            "RM -rf /",
            "Rm -rF ~",
            "rm -rF /",
            # R4-F2: flag combinations beyond -rf
            "rm -rfv /",
            "rm -rfv ~",
            "rm -rvf ~",
            "rm -vrf /",
            "rm -rfi /",
            "rm -rfI ~",
            # R4-F3: env-var home expansion
            "rm -rf $HOME",
            "rm -rf ${HOME}",
            "rm -rf $USER",
            "rm -rf ${USER}",
            "find $HOME -delete",
            "find ${HOME} -delete",
            # R4-F5: additional destructive verbs
            "> /etc/passwd",
            "> /etc/shadow",
            "> /etc/sudoers",
            ">/etc/gshadow",  # no space
            "blkdiscard /dev/sda",
            "sgdisk -Z /dev/sda",
            "sgdisk -z /dev/nvme0n1",
            "parted /dev/sda mklabel gpt",
            "fdisk /dev/sda",
            "fdisk /dev/sdb",
        ],
    )
    def test_r4_bypass_attempts_blocked(self, command: str) -> None:
        assert _is_dangerous_command(command) is True, (
            f"R4 regex must block: {command!r}"
        )

    @pytest.mark.parametrize(
        "command",
        [
            # Must remain allowed — common admin commands
            "shred --help",
            "wipefs --help",
            "parted --version",
            "fdisk --help",
            "find /var/log -mtime +30",
            "find . -name '*.py'",
            "> /var/log/app.log",
            "> /tmp/output.txt",
            "rm file.txt",
            "rm -f file.txt",
            "rm -rf ./build",
            "rm -rf ../dist",
        ],
    )
    def test_r4_safe_commands_allowed(self, command: str) -> None:
        assert _is_dangerous_command(command) is False, (
            f"R4 regex over-matched: {command!r}"
        )


class TestDangerousCommandR3Extensions:
    """Red Team R3 regex extensions: home-wipe, find-delete, shred, wipefs, spaced fork bomb."""

    @pytest.mark.parametrize(
        "command",
        [
            # Home directory wipe — `~` is shell-expanded to $HOME and can
            # nuke the user's entire home. Previously bypassed because
            # the regex required a literal `/` after `-rf`.
            "rm -rf ~",
            "rm -rf ~/",
            "rm -rf ~/Documents",
            "sudo rm -rf ~",
            # find / -delete  — same destructive power as rm -rf /
            "find / -delete",
            "find /home -delete",
            "find / -exec rm {} +",
            # shred / wipefs — block-level destruction
            "shred /dev/sda",
            "shred -zvu /dev/sda",
            "wipefs -a /dev/sda",
            "wipefs --all /dev/nvme0n1",
            # Spaced fork bomb — the original regex required adjacent (){
            ":() { :|:& };:",
            ":()  {  :|:&  };:",
        ],
    )
    def test_r3_dangerous_patterns_blocked(self, command: str) -> None:
        assert _is_dangerous_command(command) is True, (
            f"R3 regex must block: {command!r}"
        )

    @pytest.mark.parametrize(
        "command",
        [
            # Don't over-flag — these must stay allowed
            "find /var/log -name '*.log' -mtime +30",
            "find . -type f",
            "shred --help",  # docs lookup, no device arg
            "wipefs --version",
        ],
    )
    def test_r3_false_positives_not_blocked(self, command: str) -> None:
        assert _is_dangerous_command(command) is False, (
            f"R3 regex over-matched: {command!r}"
        )


class TestDangerousCommandForceBypass:
    """Tests for force=True bypassing dangerous command detection."""

    def test_dangerous_command_blocked_without_force(self) -> None:
        assert _is_dangerous_command("rm -rf /") is True

    def test_force_parameter_exists_in_execute_signature(self) -> None:
        """Verify force parameter exists in SSHManager.execute signature."""
        import inspect

        sig = inspect.signature(SSHManager.execute)
        assert "force" in sig.parameters


# ---------------------------------------------------------------------------
# dry_run parameter (C3)
# ---------------------------------------------------------------------------


class TestDryRun:
    """Tests for dry_run=True preview behavior."""

    def _make_registry(self) -> ServerRegistry:
        import tempfile

        config_content = """
[settings]
command_timeout = 30

[groups]
test = { description = "Test group" }

[servers.test-host]
description = "Test server"
groups = ["test"]
default_dir = "/srv/app"
"""
        tmp = tempfile.NamedTemporaryFile(suffix=".toml", mode="w", delete=False)
        tmp.write(config_content)
        tmp.flush()
        tmp.close()
        return ServerRegistry(tmp.name)

    async def test_dry_run_does_not_call_get_connection(self) -> None:
        """dry_run=True must skip connection setup entirely."""
        from unittest.mock import AsyncMock, patch

        manager = SSHManager(self._make_registry(), Settings())

        with patch.object(
            manager,
            "_get_connection",
            AsyncMock(side_effect=AssertionError("must not connect in dry_run")),
        ):
            result = await manager.execute("test-host", "uptime", dry_run=True)

        assert result.exit_code == 0
        assert result.error is None
        assert "[DRY RUN]" in result.stdout
        assert "uptime" in result.stdout
        assert "test-host" in result.stdout

    async def test_dry_run_includes_default_dir_from_config(self) -> None:
        """The preview must show the server's default_dir when no override."""
        from unittest.mock import AsyncMock, patch

        manager = SSHManager(self._make_registry(), Settings())
        with patch.object(
            manager,
            "_get_connection",
            AsyncMock(side_effect=AssertionError("must not connect in dry_run")),
        ):
            result = await manager.execute("test-host", "uptime", dry_run=True)

        assert "/srv/app" in result.stdout

    async def test_dry_run_working_dir_override_wins(self) -> None:
        """An explicit working_dir override must appear in the preview."""
        from unittest.mock import AsyncMock, patch

        manager = SSHManager(self._make_registry(), Settings())
        with patch.object(
            manager,
            "_get_connection",
            AsyncMock(side_effect=AssertionError("must not connect in dry_run")),
        ):
            result = await manager.execute(
                "test-host",
                "ls",
                working_dir="/custom/path",
                dry_run=True,
            )

        assert "/custom/path" in result.stdout
        assert "/srv/app" not in result.stdout

    async def test_dry_run_still_blocks_dangerous_commands(self) -> None:
        """Dangerous commands must be rejected even in dry_run mode.

        This is the whole point of dry_run: preview what would happen,
        including rejection. Skipping the dangerous-command check would
        defeat the use case of previewing a plan before committing.
        """
        manager = SSHManager(self._make_registry(), Settings())
        result = await manager.execute("test-host", "rm -rf /", dry_run=True)

        assert result.error is not None
        assert "Blocked" in result.error
        assert "[DRY RUN]" not in result.stdout

    async def test_dry_run_with_force_bypasses_dangerous_check(self) -> None:
        """dry_run + force should preview a dangerous command without blocking."""
        from unittest.mock import AsyncMock, patch

        manager = SSHManager(self._make_registry(), Settings())
        with patch.object(
            manager,
            "_get_connection",
            AsyncMock(side_effect=AssertionError("must not connect in dry_run")),
        ):
            result = await manager.execute(
                "test-host",
                "rm -rf /",
                force=True,
                dry_run=True,
            )

        assert result.error is None
        assert "[DRY RUN]" in result.stdout
        assert "rm -rf /" in result.stdout

    async def test_dry_run_redacts_credentials_in_preview(self) -> None:
        """Green Team v0.5.0: dry_run preview must redact credentials.

        R5 finding #4 regression test — if _redact_secrets is removed
        from the dry_run path, this test catches the leak.
        """
        from unittest.mock import AsyncMock, patch

        manager = SSHManager(self._make_registry(), Settings())
        with patch.object(
            manager,
            "_get_connection",
            AsyncMock(side_effect=AssertionError("must not connect")),
        ):
            result = await manager.execute(
                "test-host",
                "mysql -u root -pSuperSecret123 mydb",
                dry_run=True,
            )

        assert "SuperSecret123" not in result.stdout, (
            f"Credential leaked in dry_run preview: {result.stdout!r}"
        )
        assert _REDACTION_PLACEHOLDER in result.stdout

    async def test_dry_run_with_force_warns_about_dangerous_bypass(self) -> None:
        """Red Team R3 finding H1: dry_run+force must warn when the dangerous
        check would otherwise have blocked the command. An LLM building a
        force-enabled rollout plan needs a visible signal that the preview
        contains a command that matched a destructive pattern.
        """
        from unittest.mock import AsyncMock, patch

        manager = SSHManager(self._make_registry(), Settings())
        with patch.object(
            manager,
            "_get_connection",
            AsyncMock(side_effect=AssertionError("must not connect in dry_run")),
        ):
            result = await manager.execute(
                "test-host",
                "rm -rf /",
                force=True,
                dry_run=True,
            )

        # Warning banner must be present
        assert "DANGEROUS" in result.stdout.upper() or "⚠" in result.stdout, (
            f"dry_run+force must surface a warning. Got: {result.stdout!r}"
        )

    async def test_dry_run_with_force_no_warning_for_safe_command(self) -> None:
        """dry_run+force on a SAFE command must NOT emit a dangerous warning."""
        from unittest.mock import AsyncMock, patch

        manager = SSHManager(self._make_registry(), Settings())
        with patch.object(
            manager,
            "_get_connection",
            AsyncMock(side_effect=AssertionError("must not connect in dry_run")),
        ):
            result = await manager.execute(
                "test-host",
                "uptime",
                force=True,
                dry_run=True,
            )
        # No warning banner on a safe command
        assert "DANGEROUS" not in result.stdout.upper()
        assert "⚠" not in result.stdout

    async def test_dry_run_group_produces_result_per_server(self) -> None:
        """execute_on_group dry_run must produce a preview for every server."""
        from unittest.mock import AsyncMock, patch

        manager = SSHManager(self._make_registry(), Settings())
        with patch.object(
            manager,
            "_get_connection",
            AsyncMock(side_effect=AssertionError("must not connect in dry_run")),
        ):
            results = await manager.execute_on_group("test", "uptime", dry_run=True)

        assert len(results) == 1  # test group has 1 server
        assert all(r.exit_code == 0 for r in results)
        assert all("[DRY RUN]" in r.stdout for r in results)


# ---------------------------------------------------------------------------
# connection_id generation + SFTP audit lifecycle (B2)
# ---------------------------------------------------------------------------


class TestConnectionIdGeneration:
    """_make_connection_id produces grep-friendly unique identifiers."""

    def test_connection_id_starts_with_server_name(self) -> None:
        cid = _make_connection_id("web1")
        assert cid.startswith("web1-")

    def test_connection_id_contains_pid(self) -> None:
        import os

        cid = _make_connection_id("web1")
        assert f"-{os.getpid()}-" in cid

    def test_connection_ids_are_unique(self) -> None:
        """Two calls must produce distinct ids even for the same server."""
        ids = {_make_connection_id("web1") for _ in range(100)}
        assert len(ids) == 100


class TestSFTPAuditLogging:
    """SFTP upload/download emit start/complete/failed audit logs."""

    def _make_registry(self) -> ServerRegistry:
        import tempfile

        config_content = """
[settings]
command_timeout = 30

[groups]
test = { description = "Test group" }

[servers.test-host]
description = "Test server"
groups = ["test"]
"""
        tmp = tempfile.NamedTemporaryFile(suffix=".toml", mode="w", delete=False)
        tmp.write(config_content)
        tmp.flush()
        tmp.close()
        return ServerRegistry(tmp.name)

    async def test_upload_emits_start_and_complete_audit_logs(
        self,
        tmp_path,
        caplog: pytest.LogCaptureFixture,
        sample_settings: Settings,
    ) -> None:
        """upload() must emit sftp.upload.start AND sftp.upload.complete."""
        from unittest.mock import AsyncMock, MagicMock, patch

        local = tmp_path / "payload.txt"
        local.write_bytes(b"hello sftp")

        manager = SSHManager(self._make_registry(), sample_settings)
        # Seed the pool so _get_connection returns our mock without touching
        # real network or asyncssh.connect().
        mock_sftp = MagicMock()
        mock_sftp.put = AsyncMock(return_value=None)

        sftp_ctx = MagicMock()
        sftp_ctx.__aenter__ = AsyncMock(return_value=mock_sftp)
        sftp_ctx.__aexit__ = AsyncMock(return_value=None)

        mock_conn = MagicMock()
        mock_conn.is_closed = MagicMock(return_value=False)
        mock_conn.start_sftp_client = MagicMock(return_value=sftp_ctx)

        with patch.object(
            manager, "_get_connection", AsyncMock(return_value=mock_conn)
        ):
            # Pre-seed the connection_id so audit log can reference it
            manager._connection_ids["test-host"] = "test-host-1-abcd1234"

            with caplog.at_level("INFO", logger="ssh_mcp.audit"):
                await manager.upload("test-host", str(local), "/tmp/target.txt")

        messages = [r.message for r in caplog.records]
        assert any("sftp.upload.start" in m for m in messages), (
            f"No start log in: {messages}"
        )
        assert any("sftp.upload.complete" in m for m in messages), (
            f"No complete log in: {messages}"
        )

    async def test_upload_failure_emits_failed_audit_log(
        self,
        tmp_path,
        caplog: pytest.LogCaptureFixture,
        sample_settings: Settings,
    ) -> None:
        """Upload failure must emit sftp.upload.failed with error type."""
        from unittest.mock import AsyncMock, MagicMock, patch

        local = tmp_path / "payload.txt"
        local.write_bytes(b"data")

        manager = SSHManager(self._make_registry(), sample_settings)

        # start_sftp_client raises to simulate failure
        mock_conn = MagicMock()
        mock_conn.is_closed = MagicMock(return_value=False)
        mock_conn.start_sftp_client = MagicMock(side_effect=OSError("no route"))

        with patch.object(
            manager, "_get_connection", AsyncMock(return_value=mock_conn)
        ):
            manager._connection_ids["test-host"] = "test-host-1-deadbeef"
            with caplog.at_level("WARNING", logger="ssh_mcp.audit"):
                with pytest.raises(RuntimeError, match="Upload failed"):
                    await manager.upload("test-host", str(local), "/tmp/target.txt")

        messages = [r.message for r in caplog.records]
        assert any("sftp.upload.failed" in m for m in messages), (
            f"No failed log in: {messages}"
        )
        # Error type should be included so operators can triage quickly
        assert any("OSError" in m for m in messages)

    async def test_download_emits_start_and_complete_audit_logs(
        self,
        tmp_path,
        caplog: pytest.LogCaptureFixture,
        sample_settings: Settings,
    ) -> None:
        """download() must emit sftp.download.start AND sftp.download.complete."""
        from unittest.mock import AsyncMock, MagicMock, patch

        local = tmp_path / "downloaded.txt"
        # Pre-create so Path(local_path).stat() works after mocked get()
        local.write_bytes(b"some data")

        manager = SSHManager(self._make_registry(), sample_settings)
        mock_sftp = MagicMock()
        mock_sftp.get = AsyncMock(return_value=None)

        sftp_ctx = MagicMock()
        sftp_ctx.__aenter__ = AsyncMock(return_value=mock_sftp)
        sftp_ctx.__aexit__ = AsyncMock(return_value=None)

        mock_conn = MagicMock()
        mock_conn.is_closed = MagicMock(return_value=False)
        mock_conn.start_sftp_client = MagicMock(return_value=sftp_ctx)

        with patch.object(
            manager, "_get_connection", AsyncMock(return_value=mock_conn)
        ):
            manager._connection_ids["test-host"] = "test-host-1-cafef00d"
            with caplog.at_level("INFO", logger="ssh_mcp.audit"):
                await manager.download("test-host", "/tmp/source.txt", str(local))

        messages = [r.message for r in caplog.records]
        assert any("sftp.download.start" in m for m in messages)
        assert any("sftp.download.complete" in m for m in messages)

    def test_connection_ids_cleared_on_close_all(
        self, sample_settings: Settings
    ) -> None:
        """close_all() must clear the connection_ids dict."""
        manager = SSHManager(self._make_registry(), sample_settings)
        manager._connection_ids["test-host"] = "test-host-1-abcd"

        asyncio.run(manager.close_all())

        assert manager._connection_ids == {}


# ---------------------------------------------------------------------------
# Property-based fuzz tests for _is_dangerous_command (B3)
#
# These tests use Hypothesis to explore the input space beyond the
# hand-curated parametrize cases. They catch regressions where:
#   * a regex change accidentally makes rm -rf / slip past the filter
#   * a regex change starts rejecting benign commands that happen to
#     contain "dd" or "chmod" substrings in non-destructive positions
#   * control-character sanitization leaves exploitable gaps
# ---------------------------------------------------------------------------


class TestDangerousCommandProperties:
    """Property-based tests using Hypothesis to fuzz ``_is_dangerous_command``."""

    @given(
        st.text(
            alphabet=st.characters(min_codepoint=0, max_codepoint=255),
            max_size=200,
        )
    )
    def test_never_crashes_on_arbitrary_byte_input(self, payload: str) -> None:
        """Property: the function returns bool for ANY input, never raises.

        Guards against regex regressions (catastrophic backtracking,
        encoding errors) that would crash the whole tool call instead of
        returning a safe "not dangerous" verdict.
        """
        result = _is_dangerous_command(payload)
        assert isinstance(result, bool)

    @given(st.from_regex(r"rm\s+-rf\s+/.*", fullmatch=False))
    def test_rm_rf_root_always_caught(self, payload: str) -> None:
        """Property: any string containing ``rm -rf /`` is rejected."""
        assert _is_dangerous_command(payload) is True

    @given(st.from_regex(r"mkfs\.\w+", fullmatch=False))
    def test_mkfs_always_caught(self, payload: str) -> None:
        """Property: any string matching ``mkfs.<fstype>`` is rejected."""
        assert _is_dangerous_command(payload) is True

    @given(st.from_regex(r"dd\s+if=/dev/\w+", fullmatch=False))
    def test_dd_with_device_input_always_caught(self, payload: str) -> None:
        """Property: ``dd if=/dev/*`` patterns are rejected."""
        assert _is_dangerous_command(payload) is True

    @given(
        st.text(
            alphabet=st.characters(
                whitelist_categories=("Lu", "Ll", "Nd"),
                whitelist_characters=" -./_",
            ),
            min_size=1,
            max_size=80,
        ).filter(
            lambda s: (
                not any(
                    token in s.lower()
                    for token in (
                        "rm -rf /",
                        "rm  -rf  /",
                        "mkfs",
                        "dd if=",
                        "/dev/sd",
                        "chmod 777 /",
                    )
                )
            )
        )
    )
    def test_safe_looking_text_not_flagged(self, payload: str) -> None:
        """Property: letters+digits+path-safe chars without dangerous tokens pass.

        Narrower than "any text" to avoid false positives from generated
        substrings accidentally matching a dangerous regex — the filter
        excludes any payload containing a known dangerous substring.
        """
        assert _is_dangerous_command(payload) is False

    @given(
        st.sampled_from(
            ["rm -rf /", "mkfs.ext4 /dev/sda", "dd if=/dev/zero of=/dev/sdb"]
        ),
        st.integers(min_value=1, max_value=10),
    )
    def test_control_char_injection_never_bypasses(self, cmd: str, n_ctrl: int) -> None:
        """Property: injecting control chars into a known-bad command must NOT bypass.

        Red Team R2 fix: null bytes and other ASCII control characters are
        normalized to spaces before regex matching. This property verifies
        the normalization across every dangerous token and every possible
        control character insertion point.
        """
        # Insert control chars at a couple of positions in the command.
        # Pick positions deterministically from n_ctrl so Hypothesis
        # shrinking produces meaningful counterexamples on failure.
        for i in range(n_ctrl):
            pos = i % len(cmd)
            cmd = cmd[:pos] + chr(i % 32) + cmd[pos:]
        assert _is_dangerous_command(cmd) is True, f"bypass found: {cmd!r}"


# ---------------------------------------------------------------------------
# Credential redaction (production finding: mysql password leaked to logs)
# ---------------------------------------------------------------------------


class TestRedactSecrets:
    """``_redact_secrets`` strips credentials from strings before logging.

    Production incident on 2026-04-11: the audit log interpolated the raw
    ``command`` value and shipped ``mysql -h ... -u freepbxuser -p<PLAIN>``
    to stderr, which was then forwarded to centralized log aggregators.
    Passwords must be replaced with a fixed placeholder before reaching
    any logger.
    """

    @pytest.mark.parametrize(
        "command,must_not_contain",
        [
            # MySQL client short flag — no space between -p and the value
            (
                'mysql -h 10.0.0.5 -u freepbxuser -pJeo56i4CuLzc asteriskcdrdb -e "SHOW TABLES;"',
                "Jeo56i4CuLzc",
            ),
            # MySQL with quoted password
            (
                "mysql -u root -p'Secret!Pass123' mydb",
                "Secret!Pass123",
            ),
            # psql --password long flag with equals
            (
                "psql --password=HunterTwo42 --host db.internal -U admin",
                "HunterTwo42",
            ),
            # psql --password with space separator
            (
                "psql --password TopSecretValue2026 --user admin",
                "TopSecretValue2026",
            ),
            # POSIX env var pattern (inline env)
            (
                "PGPASSWORD=MyPgPw pg_dump -h db mydb > /tmp/x",
                "MyPgPw",
            ),
            (
                "MYSQL_PWD=AnotherSecret mysqladmin flush-hosts",
                "AnotherSecret",
            ),
            # Generic TOKEN=/API_KEY= env
            (
                "TOKEN=ey.abc.def curl https://api.example.com/v1/data",
                "ey.abc.def",
            ),
            (
                "API_KEY=sk-proj-abcdef123456 python deploy.py",
                "sk-proj-abcdef123456",
            ),
            # HTTP Authorization header inline
            (
                'curl -H "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.abc.def" https://api',
                "eyJhbGciOiJIUzI1NiJ9.abc.def",
            ),
            # Basic auth URL (username:password@host)
            (
                "wget https://admin:P4ssw0rd@internal.example.com/file.tgz",
                "P4ssw0rd",
            ),
            # Long flag uppercase (--PASSWORD via case-insensitive match)
            # NOTE: in MySQL CLI ``-P`` short flag is PORT (not password),
            # so we intentionally do NOT test uppercase short flag.
            (
                "mysql --PASSWORD=UpperCaseName mydb",
                "UpperCaseName",
            ),
            # AWS creds in env
            (
                "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCY/EXAMPLE aws s3 ls",
                "wJalrXUtnFEMI/K7MDENG/bPxRfiCY/EXAMPLE",
            ),
        ],
        ids=lambda x: x[:40] if isinstance(x, str) else "p",
    )
    def test_known_credential_patterns_redacted(
        self, command: str, must_not_contain: str
    ) -> None:
        """Every known credential pattern must be replaced with the placeholder."""
        redacted = _redact_secrets(command)
        assert must_not_contain not in redacted, (
            f"Secret leaked: {must_not_contain!r} still present in {redacted!r}"
        )
        assert _REDACTION_PLACEHOLDER in redacted, (
            f"Expected redaction placeholder in output: {redacted!r}"
        )

    @pytest.mark.parametrize(
        "safe_command",
        [
            # These must NOT be touched
            "ls -la /var/log",
            "uptime",
            "systemctl status nginx",
            "cat /etc/nginx/nginx.conf",
            "ps auxf | grep python",
            "df -h",
            "find /var/log -mtime +30",
            "mysql --help",  # no password present
            "psql --version",
            # Business text that happens to contain 'token' as a word
            "echo 'the auth token was rotated yesterday'",
        ],
    )
    def test_safe_commands_unchanged(self, safe_command: str) -> None:
        """Commands without credentials must pass through untouched."""
        assert _redact_secrets(safe_command) == safe_command

    def test_redaction_is_idempotent(self) -> None:
        """Redacting an already-redacted string yields the same string."""
        once = _redact_secrets("mysql -u root -pSecret123 mydb")
        twice = _redact_secrets(once)
        assert once == twice

    def test_redaction_preserves_structure(self) -> None:
        """Operators should still recognize the command shape after redaction."""
        redacted = _redact_secrets("mysql -h db -u admin -pHuntr2 dbname")
        assert redacted.startswith("mysql -h db -u admin")
        assert "dbname" in redacted
        assert "Huntr2" not in redacted

    def test_redaction_handles_none_and_empty(self) -> None:
        """Edge cases: None and empty string must not crash."""
        assert _redact_secrets("") == ""
        assert _redact_secrets(None) is None  # type: ignore[arg-type]

    def test_multiple_secrets_in_one_command(self) -> None:
        """A command with TWO secrets redacts BOTH."""
        cmd = "MYSQL_PWD=first mysql -u root -pSecond mydb"
        redacted = _redact_secrets(cmd)
        assert "first" not in redacted
        assert "Second" not in redacted

    @given(st.text(min_size=1, max_size=200))
    def test_redaction_never_crashes_on_arbitrary_input(self, text: str) -> None:
        """Property: redaction never raises on any string input."""
        result = _redact_secrets(text)
        assert isinstance(result, str)
        # Result must never be longer than input by more than one placeholder
        # per potential secret match — bound generously
        assert len(result) < len(text) * 10 + 1000

    # --- v0.4.3 gap closures (G2, G3, G4) ---

    @pytest.mark.parametrize(
        "command,must_not_contain",
        [
            # G2: suffix-pattern env vars NOT in the static list
            ("VAULT_TOKEN=hvs.abc123tokenvalue deploy.sh", "hvs.abc123tokenvalue"),
            ("STRIPE_SECRET_KEY=sk_live_abc123 python app.py", "sk_live_abc123"),
            ("SLACK_BOT_TOKEN=xoxb-foobar-secret slackbot", "xoxb-foobar-secret"),
            ("DOCKER_PASSWORD=MyDockPwd123 docker login", "MyDockPwd123"),
            ("JIRA_API_TOKEN=jira_secret_tok jira-cli ls", "jira_secret_tok"),
            ("MY_CUSTOM_PASSWORD=hunter2 ./run.sh", "hunter2"),
            ("DB_SECRET=verysecretvalue app start", "verysecretvalue"),
            ("SSH_KEY=base64keydata ssh-add -", "base64keydata"),
            # G3: long flag variants with prefix
            ("myapp --db-password=DbPass123 start", "DbPass123"),
            ("myapp --admin-password=AdmPass123", "AdmPass123"),
            ("myapp --user-password SecretPwd run", "SecretPwd"),
            ("deploy --access-key=AKIA_EXAMPLE_KEY", "AKIA_EXAMPLE_KEY"),
            ("deploy --secret-key=wJalrXUtnFEMI", "wJalrXUtnFEMI"),
            ("myapp --auth-token=tok_live_1234 serve", "tok_live_1234"),
            # G4: curl -u, sshpass -p, wget --http-password
            ("curl -u admin:CurlPwd123 https://api.internal/v1", "CurlPwd123"),
            ("curl -u admin:CurlPwd123", "CurlPwd123"),
            ("sshpass -p SshPassValue ssh user@host", "SshPassValue"),
            ("wget --http-password=WgetPwd456 https://x/file", "WgetPwd456"),
            ("wget --http-password WgetPwd789 https://x/file", "WgetPwd789"),
        ],
        ids=lambda x: x[:45] if isinstance(x, str) else "p",
    )
    def test_v043_gap_patterns_redacted(
        self, command: str, must_not_contain: str
    ) -> None:
        """v0.4.3 gap closures: suffix env vars, variant long flags, curl/sshpass/wget."""
        redacted = _redact_secrets(command)
        assert must_not_contain not in redacted, (
            f"v0.4.3 gap: {must_not_contain!r} leaked in {redacted!r}"
        )
        assert _REDACTION_PLACEHOLDER in redacted

    @pytest.mark.parametrize(
        "safe_command",
        [
            # Must NOT trigger false positives
            "vault status",
            "docker ps",
            "jira --help",
            "curl https://public.api.com/health",
            "curl -v https://example.com",
            "wget https://releases.example.com/v1.tar.gz",
            "sshpass --help",
            "myapp --db-port=5432 start",
            "deploy --access-log=/var/log/app.log",
        ],
    )
    def test_v043_safe_commands_unchanged(self, safe_command: str) -> None:
        """v0.4.3 patterns must not over-match common admin commands."""
        assert _redact_secrets(safe_command) == safe_command

    @given(
        st.sampled_from(
            # NOTE: MySQL ``-P`` (uppercase) is the PORT flag, not password,
            # so only lowercase ``-p`` is tested as a credential prefix.
            ["-p", "--password=", "--password ", "PGPASSWORD=", "MYSQL_PWD="]
        ),
        st.text(
            alphabet=st.characters(
                whitelist_categories=("Lu", "Ll", "Nd"),
                whitelist_characters="!@#$%^&*_-+",
            ),
            min_size=8,
            max_size=30,
        ),
    )
    def test_fuzzed_credential_patterns_always_redacted(
        self, prefix: str, secret: str
    ) -> None:
        """Property: any <prefix><secret> combo must not leak the secret."""
        cmd = f"mysql {prefix}{secret} somedb"
        redacted = _redact_secrets(cmd)
        assert secret not in redacted, (
            f"Leaked: prefix={prefix!r} secret={secret!r} → {redacted!r}"
        )


# ---------------------------------------------------------------------------
# fail_fast cancelled-result visibility (R5 finding #9)
# ---------------------------------------------------------------------------


class TestFailFastCancelledResults:
    """R5 finding #9: execute_on_group fail_fast=True must include cancelled
    server results so operators see the full server list instead of a
    silently truncated result set.
    """

    def _make_registry(self, server_names: list[str]) -> ServerRegistry:
        """Build a registry with N servers in one group."""
        import tempfile

        servers_toml = "\n".join(
            f'[servers.{name}]\ndescription = "{name}"\ngroups = ["mygroup"]'
            for name in server_names
        )
        config_content = f"""
[settings]
command_timeout = 30

[groups]
mygroup = {{ description = "Test group" }}

{servers_toml}
"""
        tmp = tempfile.NamedTemporaryFile(suffix=".toml", mode="w", delete=False)
        tmp.write(config_content)
        tmp.flush()
        tmp.close()
        return ServerRegistry(tmp.name)

    async def test_cancelled_servers_appear_in_results(self) -> None:
        """All 3 servers must appear: 1 failed + 2 cancelled."""
        from unittest.mock import patch

        registry = self._make_registry(["srv-a", "srv-b", "srv-c"])
        manager = SSHManager(registry, Settings())

        call_count = 0

        async def mock_execute(
            server_name: str,
            command: str,
            timeout: int = 30,
            working_dir: str | None = None,
            force: bool = False,
            dry_run: bool = False,
        ) -> ExecResult:
            nonlocal call_count
            call_count += 1
            if server_name == "srv-a":
                # Return failure immediately to trigger fail_fast
                return ExecResult(
                    server=server_name,
                    command=command,
                    stdout="",
                    stderr="disk full",
                    exit_code=1,
                    error=None,
                )
            # Other servers: slow enough to be cancelled
            await asyncio.sleep(10)
            return ExecResult(
                server=server_name,
                command=command,
                stdout="ok",
                stderr="",
                exit_code=0,
            )

        with patch.object(manager, "execute", side_effect=mock_execute):
            results = await manager.execute_on_group("mygroup", "df -h", fail_fast=True)

        # All 3 servers must be represented
        result_servers = {r.server for r in results}
        assert result_servers == {"srv-a", "srv-b", "srv-c"}, (
            f"Expected all 3 servers, got: {result_servers}"
        )

        # Exactly 1 failed result (srv-a)
        failed = [r for r in results if r.exit_code is not None and r.exit_code != 0]
        assert len(failed) == 1
        assert failed[0].server == "srv-a"

        # Exactly 2 cancelled results
        cancelled = [
            r for r in results if r.error and r.error.startswith("Cancelled: fail_fast")
        ]
        assert len(cancelled) == 2
        cancelled_servers = {r.server for r in cancelled}
        assert cancelled_servers == {"srv-b", "srv-c"}

    async def test_cancelled_results_have_correct_fields(self) -> None:
        """Cancelled ExecResult entries must have expected field values."""
        from unittest.mock import patch

        registry = self._make_registry(["alpha", "beta"])
        manager = SSHManager(registry, Settings())

        async def mock_execute(
            server_name: str,
            command: str,
            timeout: int = 30,
            working_dir: str | None = None,
            force: bool = False,
            dry_run: bool = False,
        ) -> ExecResult:
            if server_name == "alpha":
                return ExecResult(
                    server=server_name,
                    command=command,
                    stdout="",
                    stderr="",
                    exit_code=None,
                    error="SSH error: connection refused",
                )
            await asyncio.sleep(10)
            return ExecResult(
                server=server_name,
                command=command,
                stdout="ok",
                stderr="",
                exit_code=0,
            )

        with patch.object(manager, "execute", side_effect=mock_execute):
            results = await manager.execute_on_group(
                "mygroup", "uptime", fail_fast=True
            )

        cancelled = [
            r for r in results if r.error and "Cancelled: fail_fast" in r.error
        ]
        assert len(cancelled) == 1
        c = cancelled[0]
        assert c.server == "beta"
        assert c.command == "uptime"
        assert c.stdout == ""
        assert c.stderr == ""
        assert c.exit_code is None
        assert c.error == "Cancelled: fail_fast triggered by an earlier failure"

    async def test_no_cancelled_results_when_all_succeed(self) -> None:
        """When no failure occurs, no cancelled entries should be appended."""
        from unittest.mock import patch

        registry = self._make_registry(["s1", "s2", "s3"])
        manager = SSHManager(registry, Settings())

        async def mock_execute(
            server_name: str,
            command: str,
            timeout: int = 30,
            working_dir: str | None = None,
            force: bool = False,
            dry_run: bool = False,
        ) -> ExecResult:
            return ExecResult(
                server=server_name,
                command=command,
                stdout="ok",
                stderr="",
                exit_code=0,
            )

        with patch.object(manager, "execute", side_effect=mock_execute):
            results = await manager.execute_on_group(
                "mygroup", "echo hi", fail_fast=True
            )

        assert len(results) == 3
        assert all(r.exit_code == 0 for r in results)
        assert not any(r.error and "Cancelled" in r.error for r in results)
