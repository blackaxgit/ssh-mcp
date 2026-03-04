"""Unit tests for SSH MCP output formatting functions.

Tests cover text table formatting for servers, groups, execution results,
and group execution summaries.
"""

from __future__ import annotations


from ssh_mcp.formatting import (
    format_exec_result,
    format_group_results,
    format_group_table,
    format_server_table,
)
from ssh_mcp.models import ExecResult, GroupConfig, ServerConfig


class TestFormatServerTable:
    """Tests for format_server_table function."""

    def test_format_server_table_with_servers(
        self, sample_servers: list[ServerConfig]
    ) -> None:
        """Test formatting a list of servers into a table."""
        output = format_server_table(sample_servers)

        # Should contain header
        assert "SERVER" in output
        assert "GROUPS" in output
        assert "DESCRIPTION" in output

        # Should contain server names
        assert "web1" in output
        assert "web2" in output
        assert "db1" in output
        assert "bastion" in output

        # Should contain group names
        assert "prod" in output
        assert "web" in output
        assert "database" in output

        # Should contain footer with count
        assert "Total: 4 servers" in output

    def test_format_server_table_empty_list(self) -> None:
        """Test formatting empty server list."""
        output = format_server_table([])

        assert "No servers found" in output

    def test_format_server_table_with_filter_label(
        self, sample_servers: list[ServerConfig]
    ) -> None:
        """Test formatting server table with filter label."""
        output = format_server_table(sample_servers, filter_label="in group 'prod'")

        assert "Total: 4 servers (in group 'prod')" in output

    def test_format_server_table_single_server(self) -> None:
        """Test formatting table with single server."""
        servers = [
            ServerConfig(name="web1", description="Web server", groups=("prod",))
        ]
        output = format_server_table(servers)

        assert "Total: 1 server" in output
        assert "servers" not in output.split("Total:")[1]  # Should use singular form

    def test_format_server_table_server_no_groups(self) -> None:
        """Test formatting server with no groups."""
        servers = [
            ServerConfig(name="standalone", description="Standalone server", groups=())
        ]
        output = format_server_table(servers)

        assert "standalone" in output
        # Groups column should be empty for this server
        lines = output.split("\n")
        assert any("standalone" in line for line in lines)


class TestFormatGroupTable:
    """Tests for format_group_table function."""

    def test_format_group_table_with_groups(
        self, sample_groups: list[GroupConfig]
    ) -> None:
        """Test formatting a list of groups into a table."""
        server_counts = {"prod": 5, "web": 3, "database": 2}
        output = format_group_table(sample_groups, server_counts)

        # Should contain header
        assert "GROUP" in output
        assert "SERVERS" in output
        assert "DESCRIPTION" in output

        # Should contain group names
        assert "prod" in output
        assert "web" in output
        assert "database" in output

        # Should contain server counts
        assert "5" in output
        assert "3" in output
        assert "2" in output

        # Should contain descriptions
        assert "Production servers" in output
        assert "Web application servers" in output

    def test_format_group_table_empty_list(self) -> None:
        """Test formatting empty group list."""
        output = format_group_table([], {})

        assert "No groups found" in output

    def test_format_group_table_missing_count(
        self, sample_groups: list[GroupConfig]
    ) -> None:
        """Test formatting groups with missing server counts."""
        # Only provide counts for some groups
        server_counts = {"prod": 5}
        output = format_group_table(sample_groups, server_counts)

        # Should show 0 for groups without counts
        assert "0" in output

    def test_format_group_table_zero_servers(self) -> None:
        """Test formatting group with zero servers."""
        groups = [GroupConfig(name="empty", description="Empty group")]
        server_counts = {"empty": 0}
        output = format_group_table(groups, server_counts)

        assert "empty" in output
        assert "0" in output


class TestFormatExecResult:
    """Tests for format_exec_result function."""

    def test_format_exec_result_success(self, sample_exec_result: ExecResult) -> None:
        """Test formatting successful execution result."""
        output = format_exec_result(sample_exec_result)

        # Should contain server and command
        assert "[web1]" in output
        assert "uptime" in output

        # Should contain stdout
        assert "142 days" in output

        # Should contain exit code and duration
        assert "Exit code: 0" in output
        assert "150ms" in output

    def test_format_exec_result_with_error(self, sample_exec_error: ExecResult) -> None:
        """Test formatting execution result with error."""
        output = format_exec_result(sample_exec_error)

        # Should contain server and error message
        assert "[web1]" in output
        assert "ERROR" in output
        assert "Command not found" in output

    def test_format_exec_result_with_stderr(self) -> None:
        """Test formatting result with stderr output."""
        result = ExecResult(
            server="web1",
            command="cat missing.txt",
            stdout="",
            stderr="cat: missing.txt: No such file or directory",
            exit_code=1,
            duration_ms=10,
        )
        output = format_exec_result(result)

        # Should contain stderr label and content
        assert "STDERR:" in output
        assert "No such file or directory" in output
        assert "Exit code: 1" in output

    def test_format_exec_result_no_stdout(self) -> None:
        """Test formatting result with no stdout."""
        result = ExecResult(
            server="web1",
            command="rm file.txt",
            stdout="",
            stderr="",
            exit_code=0,
            duration_ms=5,
        )
        output = format_exec_result(result)

        assert "[web1]" in output
        assert "rm file.txt" in output
        assert "Exit code: 0" in output

    def test_format_exec_result_unknown_exit_code(self) -> None:
        """Test formatting result with None exit code."""
        result = ExecResult(
            server="web1",
            command="uptime",
            stdout="up 142 days",
            stderr="",
            exit_code=None,
            duration_ms=150,
        )
        output = format_exec_result(result)

        assert "Exit code: unknown" in output


class TestFormatGroupResults:
    """Tests for format_group_results function."""

    def test_format_group_results_mixed_success_failure(self) -> None:
        """Test formatting group results with mixed success/failure."""
        results = [
            ExecResult(
                server="web1",
                command="uptime",
                stdout="up 142 days",
                stderr="",
                exit_code=0,
                duration_ms=150,
            ),
            ExecResult(
                server="web2",
                command="uptime",
                stdout="",
                stderr="",
                exit_code=None,
                error="Connection timeout",
                duration_ms=30000,
            ),
            ExecResult(
                server="web3",
                command="uptime",
                stdout="up 89 days",
                stderr="",
                exit_code=0,
                duration_ms=120,
            ),
        ]
        output = format_group_results(results, "prod")

        # Should contain header
        assert "Executing on group 'prod' (3 servers)" in output

        # Should contain all server results
        assert "[web1]" in output
        assert "[web2]" in output
        assert "[web3]" in output

        # Should contain summary
        assert "Summary: 2 succeeded, 1 failed" in output

    def test_format_group_results_all_success(self) -> None:
        """Test formatting group results with all successes."""
        results = [
            ExecResult(
                server="web1",
                command="uptime",
                stdout="up 142 days",
                stderr="",
                exit_code=0,
                duration_ms=150,
            ),
            ExecResult(
                server="web2",
                command="uptime",
                stdout="up 89 days",
                stderr="",
                exit_code=0,
                duration_ms=120,
            ),
        ]
        output = format_group_results(results, "prod")

        assert "Summary: 2 succeeded, 0 failed" in output

    def test_format_group_results_all_failure(self) -> None:
        """Test formatting group results with all failures."""
        results = [
            ExecResult(
                server="web1",
                command="uptime",
                stdout="",
                stderr="",
                exit_code=1,
                duration_ms=10,
            ),
            ExecResult(
                server="web2",
                command="uptime",
                stdout="",
                stderr="",
                exit_code=None,
                error="Connection failed",
                duration_ms=5,
            ),
        ]
        output = format_group_results(results, "prod")

        assert "Summary: 0 succeeded, 2 failed" in output

    def test_format_group_results_empty_list(self) -> None:
        """Test formatting empty group results."""
        output = format_group_results([], "empty-group")

        assert "Executing on group 'empty-group' (0 servers)" in output
        assert "No servers in group" in output

    def test_format_group_results_with_stderr(self) -> None:
        """Test formatting group results including stderr."""
        results = [
            ExecResult(
                server="web1",
                command="cat missing.txt",
                stdout="",
                stderr="cat: missing.txt: No such file or directory",
                exit_code=1,
                duration_ms=10,
            ),
        ]
        output = format_group_results(results, "test")

        assert "STDERR: cat: missing.txt: No such file or directory" in output
        assert "Summary: 0 succeeded, 1 failed" in output

    def test_format_group_results_nonzero_exit_is_failure(self) -> None:
        """Test that non-zero exit codes are counted as failures."""
        results = [
            ExecResult(
                server="web1",
                command="false",
                stdout="",
                stderr="",
                exit_code=1,
                duration_ms=5,
            ),
        ]
        output = format_group_results(results, "test")

        assert "Summary: 0 succeeded, 1 failed" in output
        assert "exit 1" in output
