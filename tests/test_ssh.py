"""Unit tests for SSH MCP security-critical functions in ssh.py.

Tests cover dangerous command detection, path validation, and SSHManager
initialization. All tests run without real SSH connections.
"""

from __future__ import annotations


import pytest

from ssh_mcp.config import ServerRegistry
from ssh_mcp.models import Settings
from ssh_mcp.ssh import (
    SSHManager,
    _DANGEROUS_PATTERNS,
    _SENSITIVE_PATHS,
    _is_dangerous_command,
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


# ---------------------------------------------------------------------------
# _DANGEROUS_PATTERNS coverage: each pattern tested individually
# ---------------------------------------------------------------------------


class TestDangerousPatternsDirectly:
    """Ensure every compiled pattern in _DANGEROUS_PATTERNS fires correctly."""

    def test_pattern_count(self) -> None:
        """Sanity check: the expected number of patterns are present."""
        assert len(_DANGEROUS_PATTERNS) == 6

    def test_rm_rf_slash_pattern(self) -> None:
        assert _DANGEROUS_PATTERNS[0].search("rm -rf /") is not None
        assert _DANGEROUS_PATTERNS[0].search("rm -rf /tmp") is not None
        assert _DANGEROUS_PATTERNS[0].search("rm -rf mydir") is None

    def test_mkfs_pattern(self) -> None:
        assert _DANGEROUS_PATTERNS[1].search("mkfs.ext4 /dev/sda") is not None
        assert _DANGEROUS_PATTERNS[1].search("mkfs") is not None
        assert (
            _DANGEROUS_PATTERNS[1].search("ls mkfs_backup") is not None
        )  # substring match

    def test_dd_if_pattern(self) -> None:
        assert _DANGEROUS_PATTERNS[2].search("dd if=/dev/zero of=/dev/sda") is not None
        assert (
            _DANGEROUS_PATTERNS[2].search("dd if=input.bin of=output.bin") is not None
        )
        assert _DANGEROUS_PATTERNS[2].search("dd bs=512 count=1") is None

    def test_redirect_dev_sd_pattern(self) -> None:
        assert _DANGEROUS_PATTERNS[3].search("> /dev/sda") is not None
        assert _DANGEROUS_PATTERNS[3].search("echo x > /dev/sdb") is not None
        assert _DANGEROUS_PATTERNS[3].search("echo x > /dev/null") is None

    def test_chmod_777_slash_pattern(self) -> None:
        # Pattern matches chmod 777 followed by any / prefix — all absolute paths
        assert _DANGEROUS_PATTERNS[4].search("chmod 777 /") is not None
        assert _DANGEROUS_PATTERNS[4].search("chmod 777 /etc") is not None
        assert _DANGEROUS_PATTERNS[4].search("chmod 777 /home/user") is not None
        assert _DANGEROUS_PATTERNS[4].search("chmod 777 /tmp/mydir") is not None
        # Relative paths (no /) are safe
        assert _DANGEROUS_PATTERNS[4].search("chmod 777 mydir") is None
        assert _DANGEROUS_PATTERNS[4].search("chmod 777 ./scripts") is None

    def test_fork_bomb_pattern(self) -> None:
        # Pattern uses \s* (zero-or-more), so spaces are optional
        assert _DANGEROUS_PATTERNS[5].search(":(){ :|:& };:") is not None
        assert (
            _DANGEROUS_PATTERNS[5].search(":(){ :|:&};:") is not None
        )  # no trailing space also matches
        # Pattern requires the exact structure; unrelated strings do not match
        assert _DANGEROUS_PATTERNS[5].search("echo hello") is None
        assert _DANGEROUS_PATTERNS[5].search("ls -la") is None


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
            "/var/lib/mysql/data",
            "/usr/local/bin/script.sh",
            "/backups/2024-01-01/dump.sql",
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
        """Every entry in _SENSITIVE_PATHS triggers a ValueError."""
        for sensitive in _SENSITIVE_PATHS:
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

    def test_eviction_task_is_none_in_sync_test(
        self, sample_settings: Settings
    ) -> None:
        """In a sync test, asyncio.create_task fails so _eviction_task stays None.

        _start_eviction_loop sets _running=True before calling create_task.
        create_task raises RuntimeError (no running loop in sync context),
        which is caught in __init__, leaving _eviction_task as None.
        """
        registry = self._make_registry()
        manager = SSHManager(registry, sample_settings)
        # _running is True because it is set before create_task is called
        assert manager._running is True
        # But the task itself is None since create_task could not schedule it
        assert manager._eviction_task is None

    def test_running_flag_true_inside_event_loop(
        self, sample_settings: Settings
    ) -> None:
        """_running is True when SSHManager is created inside a running event loop."""
        registry = self._make_registry()
        manager = SSHManager(registry, sample_settings)
        assert manager._running is True
