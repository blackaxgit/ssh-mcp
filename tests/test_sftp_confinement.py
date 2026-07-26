"""Regression tests for the B1 SFTP path-confinement rewrite.

``SSHManager.upload``/``download`` used to hand the caller's local path
*string* to ``sftp.put``/``sftp.get``, which resolved it independently of
whatever ``_validate_local_path`` had checked (RC1). Three verified
consequences: anything not on the denylist passed, asyncssh's
directory-destination rewrite bypassed validation entirely, and a
downloaded remote symlink was recreated locally and then followed by
asyncssh's own local ``open()`` on a later write.

The fix removes the class rather than hardening the filter: local paths are
now resolved beneath a pinned ``transfer_root`` file descriptor via
``ssh_mcp.paths.open_beneath`` (refusing a symlink at every path
component), and the SFTP transfer itself is driven directly through the
public ``sftp.open()`` / ``SFTPClientFile.read``/``write`` API instead of
``sftp.get``/``put``. That makes asyncssh's vulnerable local-path resolution
**unreachable**, not merely defended against — which is why every test
below that exercises a successful transfer also asserts ``sftp.get``/
``sftp.put`` were never called. A test that only checked "sensitive path
blocked" would have passed against the old denylist too.
"""

from __future__ import annotations

import os
import tempfile
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import asyncssh
import pytest
from asyncssh.constants import FILEXFER_TYPE_REGULAR, FILEXFER_TYPE_SYMLINK

from ssh_mcp.config import ServerRegistry
from ssh_mcp.models import Settings
from ssh_mcp.ssh import SSHManager

pytestmark = pytest.mark.asyncio


def _make_registry() -> ServerRegistry:
    config_content = """
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


def _async_cm(value: object) -> MagicMock:
    """A MagicMock usable as ``async with x() as y`` returning ``value``."""
    ctx = MagicMock()
    ctx.__aenter__ = AsyncMock(return_value=value)
    ctx.__aexit__ = AsyncMock(return_value=None)
    return ctx


class _FakeSFTP:
    """Stand-in for ``asyncssh.SFTPClient``.

    ``get``/``put`` are present as plain ``AsyncMock``s (never wired to do
    anything) specifically so tests can assert ``assert_not_called()`` on
    them — the structural claim B1 makes. ``open``/``stat``/``limits`` are
    wired to behave like a real SFTP server for the confined copy loop.
    """

    def __init__(
        self,
        *,
        remote_type: int = FILEXFER_TYPE_REGULAR,
        remote_data: bytes = b"remote file contents",
    ) -> None:
        self.get = AsyncMock(return_value=None)
        self.put = AsyncMock(return_value=None)
        self.limits = MagicMock(max_read_len=16384, max_write_len=16384)

        attrs = MagicMock()
        attrs.type = remote_type
        self.stat = AsyncMock(return_value=attrs)

        self.remote_file = MagicMock()
        self.remote_file.read = AsyncMock(side_effect=[remote_data, b""])
        self.remote_file.write = AsyncMock(return_value=None)
        self.open = MagicMock(return_value=_async_cm(self.remote_file))


def _make_manager(transfer_root: Path, fake_sftp: _FakeSFTP) -> SSHManager:
    settings = Settings(transfer_root=str(transfer_root))
    manager = SSHManager(_make_registry(), settings)

    mock_conn = MagicMock()
    mock_conn.is_closed = MagicMock(return_value=False)
    mock_conn.start_sftp_client = MagicMock(return_value=_async_cm(fake_sftp))

    # Bypass real SSH connection setup entirely — B1 is about local-path
    # confinement, not connection handling, which is covered elsewhere.
    manager._get_connection = AsyncMock(return_value=mock_conn)  # type: ignore[method-assign]
    manager._connection_ids["test-host"] = "test-host-1-fake"
    return manager


@pytest.fixture
def root(tmp_path: Path) -> Path:
    d = tmp_path / "transfers"
    d.mkdir(mode=0o700)
    return d


# ---------------------------------------------------------------------------
# The structural claim: sftp.get/put are never called
# ---------------------------------------------------------------------------


async def test_upload_never_calls_sftp_put(root: Path) -> None:
    """Happy-path upload proves _begin_copy's directory-rewrite (route b)
    and LocalFS's symlink-following open() (route c) are unreachable —
    they only exist behind sftp.put, which this never calls."""
    (root / "payload.txt").write_bytes(b"hello")
    fake_sftp = _FakeSFTP()
    manager = _make_manager(root, fake_sftp)

    result = await manager.upload("test-host", "payload.txt", "/remote/dest.txt")

    fake_sftp.put.assert_not_called()
    fake_sftp.open.assert_called_once_with("/remote/dest.txt", "wb")
    assert "5 bytes" in result


async def test_download_never_calls_sftp_get(root: Path) -> None:
    """Happy-path download: same structural claim, other direction."""
    fake_sftp = _FakeSFTP(remote_data=b"remote file contents")
    manager = _make_manager(root, fake_sftp)

    result = await manager.download("test-host", "/remote/src.txt", "out.txt")

    fake_sftp.get.assert_not_called()
    fake_sftp.stat.assert_called_once_with("/remote/src.txt", follow_symlinks=False)
    assert (root / "out.txt").read_bytes() == b"remote file contents"
    assert f"{len(b'remote file contents')} bytes" in result


# ---------------------------------------------------------------------------
# Local path confinement — absolute paths and '..' rejected
# ---------------------------------------------------------------------------


async def test_upload_absolute_local_path_rejected(root: Path) -> None:
    fake_sftp = _FakeSFTP()
    manager = _make_manager(root, fake_sftp)

    with pytest.raises(ValueError, match="absolute"):
        await manager.upload("test-host", "/etc/passwd", "/remote/dest.txt")

    # Rejected lexically, before ever touching the network.
    manager._get_connection.assert_not_called()  # type: ignore[attr-defined]
    fake_sftp.put.assert_not_called()


async def test_download_absolute_local_path_rejected(root: Path) -> None:
    fake_sftp = _FakeSFTP()
    manager = _make_manager(root, fake_sftp)

    with pytest.raises(ValueError, match="absolute"):
        await manager.download("test-host", "/remote/src.txt", "/etc/passwd")

    manager._get_connection.assert_not_called()  # type: ignore[attr-defined]
    fake_sftp.get.assert_not_called()


async def test_upload_parent_traversal_rejected(root: Path) -> None:
    manager = _make_manager(root, _FakeSFTP())

    with pytest.raises(ValueError, match="traversal"):
        await manager.upload("test-host", "../escape.txt", "/remote/dest.txt")

    manager._get_connection.assert_not_called()  # type: ignore[attr-defined]


async def test_download_parent_traversal_rejected(root: Path) -> None:
    manager = _make_manager(root, _FakeSFTP())

    with pytest.raises(ValueError, match="traversal"):
        await manager.download("test-host", "/remote/src.txt", "../escape.txt")

    manager._get_connection.assert_not_called()  # type: ignore[attr-defined]


# ---------------------------------------------------------------------------
# Symlink confinement — the case final-component-only guarding misses
# ---------------------------------------------------------------------------


async def test_upload_symlink_at_intermediate_component_rejected(
    root: Path, tmp_path: Path
) -> None:
    """The read side (upload) must refuse a symlinked intermediate directory,
    not just a symlinked final component — this is upload_file's
    exfiltration route if the walk only guarded the leaf."""
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret.txt").write_text("classified")
    (root / "hop").symlink_to(outside)

    fake_sftp = _FakeSFTP()
    manager = _make_manager(root, fake_sftp)

    with pytest.raises(ValueError, match="symbolic link"):
        await manager.upload("test-host", "hop/secret.txt", "/remote/dest.txt")

    fake_sftp.put.assert_not_called()
    fake_sftp.open.assert_not_called()


async def test_download_symlink_at_intermediate_component_rejected(
    root: Path, tmp_path: Path
) -> None:
    """The write side (download) must refuse the same, not just overwrite
    protection on the leaf — this is the ~/.ssh/config redirect route."""
    outside = tmp_path / "outside"
    outside.mkdir()
    victim = outside / "config"
    victim.write_text("original")
    (root / "hop").symlink_to(outside)

    fake_sftp = _FakeSFTP()
    manager = _make_manager(root, fake_sftp)

    with pytest.raises(ValueError, match="symbolic link"):
        await manager.download("test-host", "/remote/src.txt", "hop/config")

    assert victim.read_text() == "original", "victim file must be untouched"
    fake_sftp.get.assert_not_called()


# ---------------------------------------------------------------------------
# Remote symlink refused before opening (route c, mirrored on the remote side)
# ---------------------------------------------------------------------------


async def test_download_remote_symlink_refused(root: Path) -> None:
    """sftp.get() used to default to follow_symlinks=False and recreate a
    remote symlink locally; sftp.open() FOLLOWS symlinks. Swapping one for
    the other without this check would have newly exposed remote
    symlink-following — this is what stat(follow_symlinks=False) guards."""
    fake_sftp = _FakeSFTP(remote_type=FILEXFER_TYPE_SYMLINK)
    manager = _make_manager(root, fake_sftp)

    with pytest.raises(ValueError, match="non-regular"):
        await manager.download("test-host", "/remote/evil-link", "out.txt")

    fake_sftp.get.assert_not_called()
    fake_sftp.open.assert_not_called()
    assert not (root / "out.txt").exists()


# ---------------------------------------------------------------------------
# No-clobber download (O_CREAT | O_EXCL) — behaviour change from sftp.get()
# ---------------------------------------------------------------------------


async def test_download_no_clobber_existing_file(root: Path) -> None:
    (root / "existing.txt").write_bytes(b"already here")
    fake_sftp = _FakeSFTP()
    manager = _make_manager(root, fake_sftp)

    with pytest.raises(ValueError, match="already exists"):
        await manager.download("test-host", "/remote/src.txt", "existing.txt")

    assert (root / "existing.txt").read_bytes() == b"already here"
    fake_sftp.get.assert_not_called()


# ---------------------------------------------------------------------------
# Audit record reports the real transferred file and byte count (S13/TOCTOU)
# ---------------------------------------------------------------------------


async def test_upload_audit_record_reports_real_transferred_bytes(
    root: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """S13: the audit record must reflect the descriptor ACTUALLY
    transferred, not a directory stat or a re-resolved path."""
    (root / "payload.txt").write_bytes(b"0123456789")  # exactly 10 bytes
    fake_sftp = _FakeSFTP()
    manager = _make_manager(root, fake_sftp)

    with caplog.at_level("INFO", logger="ssh_mcp.audit"):
        result = await manager.upload("test-host", "payload.txt", "/remote/dest.txt")

    assert "10 bytes" in result
    complete_msgs = [
        r.getMessage()
        for r in caplog.records
        if "sftp.upload.complete" in r.getMessage()
    ]
    assert any("bytes=10" in m for m in complete_msgs), complete_msgs


async def test_download_audit_record_reports_real_transferred_bytes(
    root: Path, caplog: pytest.LogCaptureFixture
) -> None:
    fake_sftp = _FakeSFTP(remote_data=b"exactly-19-bytes!!!")
    assert len(b"exactly-19-bytes!!!") == 19
    manager = _make_manager(root, fake_sftp)

    with caplog.at_level("INFO", logger="ssh_mcp.audit"):
        result = await manager.download("test-host", "/remote/src.txt", "out.txt")

    assert "19 bytes" in result
    complete_msgs = [
        r.getMessage()
        for r in caplog.records
        if "sftp.download.complete" in r.getMessage()
    ]
    assert any("bytes=19" in m for m in complete_msgs), complete_msgs


# ---------------------------------------------------------------------------
# Local file identity checks
# ---------------------------------------------------------------------------


async def test_upload_missing_local_file_rejected(root: Path) -> None:
    manager = _make_manager(root, _FakeSFTP())

    with pytest.raises(ValueError, match="not found"):
        await manager.upload("test-host", "missing.txt", "/remote/dest.txt")


async def test_upload_rejects_non_regular_local_file(root: Path) -> None:
    (root / "adir").mkdir()
    manager = _make_manager(root, _FakeSFTP())

    with pytest.raises(ValueError, match="not a regular file"):
        await manager.upload("test-host", "adir", "/remote/dest.txt")


# ---------------------------------------------------------------------------
# N1: unknown server raises the documented ValueError, not a raw KeyError
# ---------------------------------------------------------------------------


async def test_upload_unknown_server_raises_value_error(root: Path) -> None:
    (root / "payload.txt").write_bytes(b"hi")
    settings = Settings(transfer_root=str(root))
    manager = SSHManager(_make_registry(), settings)

    with pytest.raises(ValueError, match="Server not found"):
        await manager.upload("nonexistent-host", "payload.txt", "/remote/dest.txt")


async def test_download_unknown_server_raises_value_error(root: Path) -> None:
    settings = Settings(transfer_root=str(root))
    manager = SSHManager(_make_registry(), settings)

    with pytest.raises(ValueError, match="Server not found"):
        await manager.download("nonexistent-host", "/remote/src.txt", "out.txt")


# ---------------------------------------------------------------------------
# Sub-directories are permitted — confinement comes from the component walk
# ---------------------------------------------------------------------------


async def test_upload_subdirectory_path_allowed(root: Path) -> None:
    (root / "sub").mkdir()
    (root / "sub" / "file.txt").write_bytes(b"nested")
    fake_sftp = _FakeSFTP()
    manager = _make_manager(root, fake_sftp)

    result = await manager.upload("test-host", "sub/file.txt", "/remote/dest.txt")

    assert "6 bytes" in result
    fake_sftp.put.assert_not_called()


# ---------------------------------------------------------------------------
# Defect 3 (panel iteration 2): upload never checked the remote path type —
# sftp.open() follows symlinks, so a remote symlink at the destination let
# an attacker redirect an upload's write to an arbitrary remote file. This
# mirrors the download guard (test_download_remote_symlink_refused above)
# on the write side, and the "missing path is fine" half download never
# needed to prove (a download target must already exist).
# ---------------------------------------------------------------------------


async def test_upload_new_remote_path_allowed(root: Path) -> None:
    """A MISSING remote path is fine — upload legitimately creates new
    files. stat() reporting 'no such file' must not block the upload."""
    (root / "payload.txt").write_bytes(b"hello")
    fake_sftp = _FakeSFTP()
    fake_sftp.stat = AsyncMock(side_effect=asyncssh.SFTPNoSuchFile("no such file"))
    manager = _make_manager(root, fake_sftp)

    result = await manager.upload("test-host", "payload.txt", "/remote/new-dest.txt")

    fake_sftp.stat.assert_called_once_with(
        "/remote/new-dest.txt", follow_symlinks=False
    )
    fake_sftp.open.assert_called_once_with("/remote/new-dest.txt", "wb")
    assert "5 bytes" in result


async def test_upload_refuses_existing_remote_symlink(root: Path) -> None:
    """sftp.open() follows symlinks — a remote symlink at the destination
    would let an attacker redirect our write to an arbitrary remote file.
    Upload previously had NO preceding stat() at all (the asymmetry with
    download, which got this guard); this proves the write side now
    refuses it too."""
    (root / "payload.txt").write_bytes(b"hello")
    fake_sftp = _FakeSFTP(remote_type=FILEXFER_TYPE_SYMLINK)
    manager = _make_manager(root, fake_sftp)

    with pytest.raises(ValueError, match="non-regular"):
        await manager.upload("test-host", "payload.txt", "/remote/evil-link")

    fake_sftp.stat.assert_called_once_with("/remote/evil-link", follow_symlinks=False)
    fake_sftp.open.assert_not_called()
    fake_sftp.put.assert_not_called()


async def test_upload_existing_regular_remote_file_allowed(root: Path) -> None:
    """Upload legitimately OVERWRITES an existing regular remote file
    (e.g. updating a config) — only a non-regular entry is refused."""
    (root / "payload.txt").write_bytes(b"hello")
    fake_sftp = _FakeSFTP(remote_type=FILEXFER_TYPE_REGULAR)
    manager = _make_manager(root, fake_sftp)

    result = await manager.upload("test-host", "payload.txt", "/remote/existing.txt")

    fake_sftp.open.assert_called_once_with("/remote/existing.txt", "wb")
    assert "5 bytes" in result


# ---------------------------------------------------------------------------
# Defect 2 (panel iteration 2): a failed download used to leave an orphan
# partial file under transfer_root (O_CREAT|O_EXCL creates it BEFORE the
# remote copy completes), permanently bricking the destination — every
# retry to the same name failed no-clobber with EEXIST.
# ---------------------------------------------------------------------------


async def test_download_removes_orphan_file_on_mid_transfer_failure(
    root: Path,
) -> None:
    """A read failure partway through a download must not leave a partial
    file behind, and a retry to the same destination must then succeed —
    proving the destination isn't permanently bricked by a stale
    no-clobber file (docs/fixes/01-approach.md:165-171 required this)."""
    fake_sftp = _FakeSFTP()
    fake_sftp.remote_file.read = AsyncMock(
        side_effect=[b"partial-data", asyncssh.SFTPError(asyncssh.FX_FAILURE, "boom")]
    )
    manager = _make_manager(root, fake_sftp)

    with pytest.raises(RuntimeError, match="Download failed"):
        await manager.download("test-host", "/remote/src.txt", "out.txt")

    assert not (root / "out.txt").exists(), (
        "orphan partial file must not survive a failed download"
    )

    # Retry with a working transfer must now succeed.
    fake_sftp2 = _FakeSFTP(remote_data=b"second try works")
    manager2 = _make_manager(root, fake_sftp2)
    result = await manager2.download("test-host", "/remote/src.txt", "out.txt")

    assert "16 bytes" in result
    assert (root / "out.txt").read_bytes() == b"second try works"


async def test_download_failure_before_local_create_leaves_nothing(
    root: Path,
) -> None:
    """Failure-path control case: if the remote ``stat`` itself fails (no
    local file is ever created), there is nothing to clean up and the
    destination must simply not exist — proves the cleanup logic is keyed
    on "did we create it", not "did anything fail"."""
    fake_sftp = _FakeSFTP()
    fake_sftp.stat = AsyncMock(
        side_effect=asyncssh.SFTPError(asyncssh.FX_PERMISSION_DENIED, "denied")
    )
    manager = _make_manager(root, fake_sftp)

    with pytest.raises(RuntimeError, match="Download failed"):
        await manager.download("test-host", "/remote/src.txt", "never-created.txt")

    assert not (root / "never-created.txt").exists()


# ---------------------------------------------------------------------------
# Defect D (panel iteration 3): _unlink_beneath cannot prove identity —
# a concurrent rename onto the same destination name between creation and
# cleanup must not have its replacement removed by the orphan-file cleanup.
# ---------------------------------------------------------------------------


async def test_download_cleanup_refuses_to_unlink_a_renamed_replacement(
    root: Path,
) -> None:
    """Defect D (panel iteration 3, verified by executing code): the
    orphan-cleanup path used in
    ``test_download_removes_orphan_file_on_mid_transfer_failure`` above
    proves only that the LEAF PATH is confined, not that the file still
    at that path is the one this call created. Here, the mid-transfer
    read failure is preceded by simulating a concurrent process that
    renames an UNRELATED file onto the exact same destination name —
    exactly the race the orphan-file cleanup did not previously guard
    against. The replacement must survive the cleanup untouched.
    """
    fake_sftp = _FakeSFTP()
    dest = root / "out.txt"
    calls = {"n": 0}

    async def _read_with_race(*args: object, **kwargs: object) -> bytes:
        calls["n"] += 1
        if calls["n"] == 1:
            return b"partial-data"
        # Simulate the race: something else renames an unrelated file
        # onto this exact destination name before the read (and thus
        # the cleanup) fails.
        replacement = root / "replacement.txt"
        replacement.write_bytes(b"unrelated replacement contents")
        os.replace(replacement, dest)
        raise asyncssh.SFTPError(asyncssh.FX_FAILURE, "boom")

    fake_sftp.remote_file.read = AsyncMock(side_effect=_read_with_race)
    manager = _make_manager(root, fake_sftp)

    with pytest.raises(RuntimeError, match="Download failed"):
        await manager.download("test-host", "/remote/src.txt", "out.txt")

    assert dest.exists(), (
        "cleanup unlinked a file it did not create — Defect D identity gap"
    )
    assert dest.read_bytes() == b"unrelated replacement contents"
