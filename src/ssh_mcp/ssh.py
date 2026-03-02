"""SSH connection manager with pooling and jump host support.

This module provides the SSHManager class that handles async SSH connections
to multiple servers with connection pooling, idle eviction, and parallel
group execution capabilities.
"""

from __future__ import annotations

import asyncio
import logging
import re
import shlex
import time
from pathlib import Path

import asyncssh

from ssh_mcp.config import ServerRegistry
from ssh_mcp.models import ExecResult, ServerConfig, Settings

logger = logging.getLogger(__name__)

# Dangerous command patterns that could be destructive
_DANGEROUS_PATTERNS = [
    re.compile(r"rm\s+-rf\s+/"),
    re.compile(r"mkfs"),
    re.compile(r"dd\s+if="),
    re.compile(r">\s*/dev/sd"),
    re.compile(r"chmod\s+777\s+/"),
    re.compile(r":\(\)\{\s*:\|:&\s*\};:"),  # fork bomb
]

# Sensitive paths that should be blocked in SFTP operations
_SENSITIVE_PATHS = [
    "/etc/shadow",
    "/etc/passwd",
    ".ssh/authorized_keys",
    ".ssh/id_rsa",
    ".ssh/id_ed25519",
    ".ssh/id_ecdsa",
    ".ssh/id_dsa",
]


def _is_dangerous_command(command: str) -> bool:
    """Check if command matches any dangerous patterns.

    Args:
        command: Command string to check

    Returns:
        True if command matches a dangerous pattern
    """
    for pattern in _DANGEROUS_PATTERNS:
        if pattern.search(command):
            return True
    return False


def _validate_remote_path(path: str) -> None:
    """Validate remote path for SFTP operations.

    Args:
        path: Remote path to validate

    Raises:
        ValueError: If path contains parent traversal or sensitive paths
    """
    # Block parent directory traversal
    if ".." in path:
        raise ValueError(f"Path traversal detected: {path}")

    # Block access to sensitive paths
    normalized_path = path.lower()
    for sensitive in _SENSITIVE_PATHS:
        if sensitive in normalized_path:
            raise ValueError(f"Access to sensitive path blocked: {path}")


class SSHManager:
    """Manages SSH connections with pooling and jump host support.

    Provides async command execution, SFTP file transfer, and group operations
    across multiple servers. Connections are pooled and reused, with idle
    eviction to prevent resource exhaustion.

    Attributes:
        registry: Server configuration registry
        settings: Global SSH settings
    """

    def __init__(self, registry: ServerRegistry, settings: Settings) -> None:
        """Initialize SSH manager with registry and settings.

        Args:
            registry: Server configuration registry
            settings: Global SSH settings
        """
        self.registry = registry
        self.settings = settings

        # Connection pool and state tracking
        self._connections: dict[str, asyncssh.SSHClientConnection] = {}
        self._last_used: dict[str, float] = {}
        self._locks: dict[str, asyncio.Lock] = {}

        # Background eviction task
        self._eviction_task: asyncio.Task | None = None
        self._running = False

        # Audit logger for command tracking
        self._audit = logging.getLogger("ssh_mcp.audit")

        # Start eviction loop (deferred if no event loop yet)
        try:
            self._start_eviction_loop()
        except RuntimeError:
            # No event loop running yet; will be started on first use
            pass

    async def execute(
        self,
        server_name: str,
        command: str,
        timeout: int = 30,
        working_dir: str | None = None,
        force: bool = False,
    ) -> ExecResult:
        """Execute command on a remote server.

        Args:
            server_name: Server name from registry
            command: Command to execute
            timeout: Command timeout in seconds
            working_dir: Working directory for command execution
            force: Bypass dangerous command detection (use with caution)

        Returns:
            ExecResult with command output and metadata
        """
        try:
            server = self.registry.get_server(server_name)

            # Check for dangerous commands unless force is enabled
            if not force and _is_dangerous_command(command):
                logger.warning(
                    f"Blocked potentially destructive command on {server_name}: {command}"
                )
                return ExecResult(
                    server=server_name,
                    command=command,
                    stdout="",
                    stderr="",
                    exit_code=None,
                    error="Blocked: potentially destructive command detected. Review and use with caution.",
                )

            # Use server-specific timeout if configured
            effective_timeout = server.timeout or timeout

            # Prepend working directory if specified
            effective_command = command
            if working_dir:
                effective_command = f"cd {shlex.quote(working_dir)} && {command}"
            elif server.default_dir:
                effective_command = f"cd {shlex.quote(server.default_dir)} && {command}"

            # Get or create connection
            conn = await self._get_connection(server_name)

            # Execute command and track duration
            start_time = time.monotonic()
            try:
                result = await conn.run(effective_command, timeout=effective_timeout)
                duration_ms = int((time.monotonic() - start_time) * 1000)

                # Truncate output if needed
                stdout = result.stdout or ""
                stderr = result.stderr or ""

                if len(stdout) > self.settings.max_output_bytes:
                    stdout = (
                        stdout[: self.settings.max_output_bytes]
                        + f"\n[... output truncated at {self.settings.max_output_bytes} bytes]"
                    )

                if len(stderr) > self.settings.max_output_bytes:
                    stderr = (
                        stderr[: self.settings.max_output_bytes]
                        + f"\n[... output truncated at {self.settings.max_output_bytes} bytes]"
                    )

                exec_result = ExecResult(
                    server=server_name,
                    command=command,
                    stdout=stdout,
                    stderr=stderr,
                    exit_code=result.exit_status,
                    duration_ms=duration_ms,
                )

                # Audit log successful execution
                self._audit.info(
                    "server=%s command=%s exit_code=%s duration_ms=%s",
                    server_name,
                    command,
                    exec_result.exit_code,
                    exec_result.duration_ms,
                )

                return exec_result

            except asyncio.TimeoutError as e:
                duration_ms = int((time.monotonic() - start_time) * 1000)
                logger.error(f"Command timeout on {server_name}: {command}")
                exec_result = ExecResult(
                    server=server_name,
                    command=command,
                    stdout="",
                    stderr="",
                    exit_code=None,
                    error=f"Command timeout after {effective_timeout}s: {e}",
                    duration_ms=duration_ms,
                )

                # Audit log timeout
                self._audit.info(
                    "server=%s command=%s exit_code=%s duration_ms=%s error=timeout",
                    server_name,
                    command,
                    exec_result.exit_code,
                    exec_result.duration_ms,
                )

                return exec_result

        except KeyError as e:
            logger.error(f"Server not found: {server_name}")
            return ExecResult(
                server=server_name,
                command=command,
                stdout="",
                stderr="",
                exit_code=None,
                error=f"Server not found: {e}",
            )

        except (
            asyncssh.DisconnectError,
            asyncssh.PermissionDenied,
            OSError,
        ) as e:
            logger.error(f"SSH error on {server_name}: {e}")
            return ExecResult(
                server=server_name,
                command=command,
                stdout="",
                stderr="",
                exit_code=None,
                error=f"SSH error: {e}",
            )

        except Exception as e:
            logger.error(f"Unexpected error on {server_name}: {e}")
            return ExecResult(
                server=server_name,
                command=command,
                stdout="",
                stderr="",
                exit_code=None,
                error=f"Unexpected error: {e}",
            )

    async def execute_on_group(
        self,
        group_name: str,
        command: str,
        timeout: int = 30,
        working_dir: str | None = None,
        fail_fast: bool = False,
        force: bool = False,
    ) -> list[ExecResult]:
        """Execute command on all servers in a group in parallel.

        Args:
            group_name: Group name from registry
            command: Command to execute
            timeout: Command timeout in seconds
            working_dir: Working directory for command execution
            fail_fast: Cancel remaining tasks on first failure
            force: Bypass dangerous command detection (use with caution)

        Returns:
            List of ExecResult, one per server in the group
        """
        try:
            servers = self.registry.servers_in_group(group_name)

            if not servers:
                logger.warning(f"Group '{group_name}' has no servers")
                return []

            # Limit concurrent connections
            semaphore = asyncio.Semaphore(10)

            async def execute_with_semaphore(server: ServerConfig) -> ExecResult:
                async with semaphore:
                    return await self.execute(
                        server.name, command, timeout, working_dir, force
                    )

            # Execute in parallel
            tasks = [execute_with_semaphore(server) for server in servers]

            if fail_fast:
                # Cancel remaining tasks on first failure
                actual_tasks = [asyncio.create_task(coro) for coro in tasks]
                results = []
                for future in asyncio.as_completed(actual_tasks):
                    result = await future
                    results.append(result)
                    if result.error or (result.exit_code is not None and result.exit_code != 0):
                        for task in actual_tasks:
                            if not task.done():
                                task.cancel()
                        break
                return results
            else:
                # Wait for all tasks to complete
                results = await asyncio.gather(*tasks, return_exceptions=True)

                # Convert exceptions to ExecResult
                normalized_results = []
                for i, result in enumerate(results):
                    if isinstance(result, Exception):
                        server_name = servers[i].name
                        normalized_results.append(
                            ExecResult(
                                server=server_name,
                                command=command,
                                stdout="",
                                stderr="",
                                exit_code=None,
                                error=f"Exception during execution: {result}",
                            )
                        )
                    else:
                        normalized_results.append(result)

                return normalized_results

        except KeyError as e:
            logger.error(f"Group not found: {group_name}")
            return [
                ExecResult(
                    server=group_name,
                    command=command,
                    stdout="",
                    stderr="",
                    exit_code=None,
                    error=f"Group not found: {e}",
                )
            ]

        except Exception as e:
            logger.error(f"Unexpected error in group execution: {e}")
            return [
                ExecResult(
                    server=group_name,
                    command=command,
                    stdout="",
                    stderr="",
                    exit_code=None,
                    error=f"Unexpected error: {e}",
                )
            ]

    async def upload(
        self, server_name: str, local_path: str, remote_path: str
    ) -> str:
        """Upload file to remote server via SFTP.

        Args:
            server_name: Server name from registry
            local_path: Local file path
            remote_path: Remote destination path

        Returns:
            Confirmation message with file size
        """
        try:
            # Validate remote path
            _validate_remote_path(remote_path)

            start_time = time.monotonic()
            conn = await self._get_connection(server_name)

            # Start SFTP client
            async with conn.start_sftp_client() as sftp:
                # Upload file
                await sftp.put(local_path, remote_path)

                # Get file size for confirmation
                local_size = Path(local_path).stat().st_size
                duration_ms = int((time.monotonic() - start_time) * 1000)

                # Audit log upload
                self._audit.info(
                    "server=%s operation=upload local_path=%s remote_path=%s bytes=%s duration_ms=%s",
                    server_name,
                    local_path,
                    remote_path,
                    local_size,
                    duration_ms,
                )

                return f"Uploaded {local_path} to {server_name}:{remote_path} ({local_size} bytes)"

        except FileNotFoundError as e:
            error_msg = f"Local file not found: {e}"
            logger.error(error_msg)
            raise ValueError(error_msg) from e

        except (
            asyncssh.DisconnectError,
            asyncssh.PermissionDenied,
            asyncssh.SFTPError,
            OSError,
        ) as e:
            error_msg = f"Upload failed to {server_name}: {e}"
            logger.error(error_msg)
            raise RuntimeError(error_msg) from e

    async def download(
        self, server_name: str, remote_path: str, local_path: str
    ) -> str:
        """Download file from remote server via SFTP.

        Args:
            server_name: Server name from registry
            remote_path: Remote file path
            local_path: Local destination path

        Returns:
            Confirmation message with file size
        """
        try:
            # Validate remote path
            _validate_remote_path(remote_path)

            start_time = time.monotonic()
            conn = await self._get_connection(server_name)

            # Start SFTP client
            async with conn.start_sftp_client() as sftp:
                # Download file
                await sftp.get(remote_path, local_path)

                # Get file size for confirmation
                local_size = Path(local_path).stat().st_size
                duration_ms = int((time.monotonic() - start_time) * 1000)

                # Audit log download
                self._audit.info(
                    "server=%s operation=download remote_path=%s local_path=%s bytes=%s duration_ms=%s",
                    server_name,
                    remote_path,
                    local_path,
                    local_size,
                    duration_ms,
                )

                return f"Downloaded {server_name}:{remote_path} to {local_path} ({local_size} bytes)"

        except (
            asyncssh.DisconnectError,
            asyncssh.PermissionDenied,
            asyncssh.SFTPError,
            OSError,
        ) as e:
            error_msg = f"Download failed from {server_name}: {e}"
            logger.error(error_msg)
            raise RuntimeError(error_msg) from e

    async def close_all(self) -> None:
        """Close all active SSH connections and stop eviction task."""
        self._running = False

        if self._eviction_task:
            self._eviction_task.cancel()
            try:
                await self._eviction_task
            except asyncio.CancelledError:
                pass

        for server_name, conn in list(self._connections.items()):
            try:
                conn.close()
                await conn.wait_closed()
                logger.info(f"Closed connection to {server_name}")
            except Exception as e:
                logger.warning(f"Error closing connection to {server_name}: {e}")

        self._connections.clear()
        self._last_used.clear()

    async def _get_connection(
        self, server_name: str, _depth: int = 0
    ) -> asyncssh.SSHClientConnection:
        """Get or create SSH connection to server.

        Reuses existing connections if available and not closed.
        Handles jump host connections transparently.

        Args:
            server_name: Server name from registry
            _depth: Internal recursion depth counter for jump hosts

        Returns:
            Active SSH connection

        Raises:
            KeyError: If server not found in registry
            RuntimeError: If jump host depth exceeds maximum
            Various SSH exceptions on connection failure
        """
        # Check recursion depth
        if _depth > 5:
            raise RuntimeError(
                f"Maximum jump host depth exceeded (depth={_depth}, server={server_name})"
            )

        # Ensure eviction loop is started
        if not self._running:
            self._start_eviction_loop()

        # Get or create lock for this server
        lock = self._locks.setdefault(server_name, asyncio.Lock())

        async with lock:
            # Check if we have a valid cached connection
            if server_name in self._connections:
                conn = self._connections[server_name]
                if not conn.is_closed():
                    # Update last used time and return cached connection
                    self._last_used[server_name] = time.monotonic()
                    return conn
                else:
                    # Connection is stale, remove it
                    logger.info(f"Connection to {server_name} is closed, reconnecting")
                    del self._connections[server_name]
                    del self._last_used[server_name]

            # Create new connection
            server = self.registry.get_server(server_name)
            conn = await self._create_connection(server, _depth)

            # Cache connection and update last used time
            self._connections[server_name] = conn
            self._last_used[server_name] = time.monotonic()

            logger.info(f"Created new connection to {server_name}")
            return conn

    async def _create_connection(
        self, server: ServerConfig, _depth: int = 0
    ) -> asyncssh.SSHClientConnection:
        """Create new SSH connection with jump host support.

        Args:
            server: Server configuration
            _depth: Internal recursion depth counter for jump hosts

        Returns:
            New SSH connection

        Raises:
            Various SSH exceptions on connection failure
        """
        # Build connection parameters
        connect_params = {
            "config": [self.settings.ssh_config_path],
        }

        # Set known_hosts based on settings
        if not self.settings.known_hosts:
            connect_params["known_hosts"] = None

        # Apply server-specific overrides
        host = server.hostname or server.name
        if server.port:
            connect_params["port"] = server.port
        if server.user:
            connect_params["username"] = server.user
        if server.identity_file:
            connect_params["client_keys"] = [server.identity_file]

        # Handle jump host (tunnel)
        if server.jump_host:
            logger.info(f"Connecting to {server.name} via jump host {server.jump_host}")
            tunnel_conn = await self._get_connection(server.jump_host, _depth + 1)
            connect_params["tunnel"] = tunnel_conn

        # Create connection
        try:
            conn = await asyncio.wait_for(
                asyncssh.connect(host, **connect_params),
                timeout=self.settings.command_timeout,
            )
            return conn
        except asyncssh.DisconnectError as e:
            logger.error(f"SSH disconnect error connecting to {server.name}: {e}")
            raise
        except asyncssh.PermissionDenied as e:
            logger.error(f"SSH permission denied for {server.name}: {e}")
            raise
        except OSError as e:
            logger.error(f"OS error connecting to {server.name}: {e}")
            raise
        except asyncio.TimeoutError as e:
            logger.error(f"Timeout connecting to {server.name}: {e}")
            raise

    def _start_eviction_loop(self) -> None:
        """Start background task for idle connection eviction."""
        if self._running:
            return

        self._running = True
        self._eviction_task = asyncio.create_task(self._eviction_loop())

    async def _eviction_loop(self) -> None:
        """Background task that evicts idle connections.

        Runs every 60 seconds and closes connections idle longer than
        settings.connection_idle_timeout.
        """
        logger.info("Started connection eviction loop")

        try:
            while self._running:
                await asyncio.sleep(60)

                if not self._running:
                    break

                now = time.monotonic()
                idle_threshold = self.settings.connection_idle_timeout

                # Find idle connections
                to_evict = []
                for server_name, last_used in self._last_used.items():
                    idle_time = now - last_used
                    if idle_time > idle_threshold:
                        to_evict.append((server_name, idle_time))

                # Evict idle connections
                for server_name, idle_time in to_evict:
                    # Get lock for this server (if it exists)
                    lock = self._locks.get(server_name)
                    if lock is None:
                        # No lock means connection already cleaned up
                        continue

                    # Acquire lock before evicting
                    async with lock:
                        if server_name in self._connections:
                            conn = self._connections[server_name]
                            try:
                                conn.close()
                                await conn.wait_closed()
                                logger.info(
                                    f"Evicted idle connection to {server_name} (idle {idle_time:.0f}s)"
                                )
                            except Exception as e:
                                logger.warning(
                                    f"Error evicting connection to {server_name}: {e}"
                                )
                            finally:
                                self._connections.pop(server_name, None)
                                self._last_used.pop(server_name, None)
                                # Keep lock in _locks for reuse

        except asyncio.CancelledError:
            logger.info("Connection eviction loop cancelled")
        except Exception as e:
            logger.error(f"Unexpected error in eviction loop: {e}")
