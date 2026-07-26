"""Output formatting functions for SSH MCP server tools.

This module converts data models into human-readable text tables that the LLM
can easily parse. All formatting uses standard library only.
"""

from __future__ import annotations

from ssh_mcp.models import ExecResult, GroupConfig, ServerConfig


def format_server_table(servers: list[ServerConfig], filter_label: str = "") -> str:
    """Format a list of servers into a text table.

    Args:
        servers: List of server configurations to display
        filter_label: Optional filter description, rendered in parentheses in
            the footer. Callers supply the whole phrase including any leading
            space — ``server.py`` passes ``" in group 'prod'"``.

    Returns:
        Formatted text table with columns: SERVER, GROUPS, DESCRIPTION, or
        the bare string "No servers found." when ``servers`` is empty

    Example:
        >>> servers = [ServerConfig(name="web1", description="Web server", groups=("prod",))]
        >>> print(format_server_table(servers))
        SERVER  GROUPS  DESCRIPTION
        web1    prod    Web server
        <BLANKLINE>
        Total: 1 server
    """
    if not servers:
        return "No servers found."

    # Calculate column widths
    max_name = max(len("SERVER"), max(len(s.name) for s in servers))
    max_groups = max(
        len("GROUPS"), max(len(", ".join(s.groups)) if s.groups else 0 for s in servers)
    )

    # Build header
    lines = [
        f"{'SERVER':<{max_name}}  {'GROUPS':<{max_groups}}  DESCRIPTION",
    ]

    # Build rows
    for server in servers:
        groups_str = ", ".join(server.groups) if server.groups else ""
        lines.append(
            f"{server.name:<{max_name}}  {groups_str:<{max_groups}}  {server.description}"
        )

    # Build footer
    lines.append("")
    count = len(servers)
    plural = "server" if count == 1 else "servers"
    if filter_label:
        lines.append(f"Total: {count} {plural} ({filter_label})")
    else:
        lines.append(f"Total: {count} {plural}")

    return "\n".join(lines)


def format_group_table(groups: list[GroupConfig], server_counts: dict[str, int]) -> str:
    """Format a list of groups into a text table.

    Args:
        groups: List of group configurations to display
        server_counts: Mapping of group name to number of servers in that group

    Returns:
        Formatted text table with columns: GROUP, SERVERS, DESCRIPTION, or
        the bare string "No groups found." when ``groups`` is empty

    Example:
        >>> groups = [GroupConfig(name="prod", description="Production servers")]
        >>> counts = {"prod": 5}
        >>> print(format_group_table(groups, counts))
        GROUP  SERVERS  DESCRIPTION
        prod   5        Production servers
    """
    if not groups:
        return "No groups found."

    # Calculate column widths
    max_name = max(len("GROUP"), max(len(g.name) for g in groups))
    max_count = max(
        len("SERVERS"), max(len(str(server_counts.get(g.name, 0))) for g in groups)
    )

    # Build header
    lines = [
        f"{'GROUP':<{max_name}}  {'SERVERS':<{max_count}}  DESCRIPTION",
    ]

    # Build rows
    for group in groups:
        count = server_counts.get(group.name, 0)
        lines.append(
            f"{group.name:<{max_name}}  {count:<{max_count}}  {group.description}"
        )

    return "\n".join(lines)


def format_exec_result(result: ExecResult) -> str:
    """Format a single command execution result.

    N3 fix: ``models.py`` (``ExecResult`` docstring) documents the states of
    the ``(error, exit_code)`` pair. The previous version of this function
    treated *any* non-empty ``error`` as a pure execution failure and
    returned immediately, discarding ``stdout``/``stderr``/``exit_code`` —
    exactly the diagnostic evidence a user needs when a command ran but the
    server also flagged an issue. This version renders every field that is
    actually populated, for all four states of the pair:

      * ``error is None`` + numeric ``exit_code``: command + output + exit
        code. ``-1`` lands here too — asyncssh reports it for a process
        killed by a signal, most often our own terminate() after the output
        budget was spent, so the output carries the truncation marker.
      * ``error is None`` + ``exit_code is None``: same as above with an
        "unknown" exit code (should not happen per the model contract, but
        rendered rather than crashing).
      * ``error is not None`` + ``exit_code is None``: execution never
        produced a result (SSH error, timeout, server not found, tripwire
        block, fail_fast cancellation) — no exit-code line, since there
        isn't one.
      * ``error is not None`` + numeric ``exit_code``: not reachable today —
        ``models.py`` guarantees every path that sets ``error`` also sets
        ``exit_code=None`` — but handled defensively rather than swallowed:
        command + output + ERROR line + exit code, so a future "ran, but the
        server flagged it" state would still show both.

    Args:
        result: Execution result to format

    Returns:
        Formatted text showing command, output, error (if any), and exit
        status — the exit line is omitted only when ``error`` is set and
        there is no exit code to report

    Example:
        >>> result = ExecResult(
        ...     server="web1",
        ...     command="uptime",
        ...     stdout=" 14:32:01 up 142 days",
        ...     stderr="",
        ...     exit_code=0,
        ...     duration_ms=150
        ... )
        >>> print(format_exec_result(result))
        [web1] $ uptime
         14:32:01 up 142 days
        <BLANKLINE>
        Exit code: 0 (150ms)
    """
    lines = [f"[{result.server}] $ {result.command}"]

    # Add stdout if present
    if result.stdout:
        lines.append(result.stdout)

    # Add stderr if present
    if result.stderr:
        lines.append("")
        lines.append("STDERR:")
        lines.append(result.stderr)

    # Add error if present (does not, by itself, imply the command never ran)
    if result.error:
        lines.append("")
        lines.append(f"ERROR: {result.error}")

    # A None exit_code alongside an error means the command never completed
    # (see docstring above) — there is no exit status to report. Otherwise
    # (including the "should not happen" error-is-None/exit_code-is-None
    # case) report the exit code, falling back to the literal "unknown"
    # rather than fabricating a value.
    if result.exit_code is None and result.error:
        return "\n".join(lines)

    lines.append("")
    exit_code = result.exit_code if result.exit_code is not None else "unknown"
    lines.append(f"Exit code: {exit_code} ({result.duration_ms}ms)")

    return "\n".join(lines)


def format_group_results(results: list[ExecResult], group_name: str) -> str:
    """Format multiple command execution results from a group.

    This is a per-server digest, not the full diagnostic dump that
    ``format_exec_result`` produces: a result carrying an ``error`` is
    rendered as a lone ``[server] ERROR: ...`` line, and its ``stdout``,
    ``stderr``, ``exit_code`` and ``duration_ms`` are deliberately dropped.

    Args:
        results: List of execution results to format
        group_name: Name of the group that was executed

    Returns:
        Formatted text showing all results with a summary. A result counts as
        succeeded only when ``error`` is None and ``exit_code == 0``; a
        non-zero code and a missing one (``None``, rendered "unknown") both
        count as failed. When ``results`` is empty, returns a "(0 servers)"
        header followed by "No servers in group."

    Example:
        >>> results = [
        ...     ExecResult("web1", "uptime", "up 142 days", "", 0, None, 150),
        ...     ExecResult("web2", "uptime", "up 89 days", "", 0, None, 89),
        ... ]
        >>> print(format_group_results(results, "prod"))
        Executing on group 'prod' (2 servers)...
        <BLANKLINE>
        [web1] (exit 0, 150ms)
        up 142 days
        <BLANKLINE>
        [web2] (exit 0, 89ms)
        up 89 days
        <BLANKLINE>
        Summary: 2 succeeded, 0 failed
    """
    if not results:
        return (
            f"Executing on group '{group_name}' (0 servers)...\n\nNo servers in group."
        )

    lines = [
        f"Executing on group '{group_name}' ({len(results)} servers)...",
        "",
    ]

    # Track success/failure counts
    succeeded = 0
    failed = 0

    # Format each result
    for result in results:
        if result.error:
            failed += 1
            lines.append(f"[{result.server}] ERROR: {result.error}")
        else:
            is_success = result.exit_code == 0
            if is_success:
                succeeded += 1
            else:
                failed += 1

            exit_code = result.exit_code if result.exit_code is not None else "unknown"
            lines.append(
                f"[{result.server}] (exit {exit_code}, {result.duration_ms}ms)"
            )

            if result.stdout:
                lines.append(result.stdout)

            if result.stderr:
                lines.append(f"STDERR: {result.stderr}")

        lines.append("")

    # Add summary
    lines.append(f"Summary: {succeeded} succeeded, {failed} failed")

    return "\n".join(lines)
