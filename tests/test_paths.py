"""Regression tests for symlink-safe path confinement and path expansion.

Covers three findings from the v0.6.0 security review:

* **B1** — SFTP local-path validation was a denylist of strings rather than a
  confinement of the operation, giving three routes to code execution on the
  MCP host. These tests assert the confinement primitive that replaces it.
* **S5** — ``~`` was expanded only when ``[settings]`` was present in the
  TOML, so a minimal config left the default unexpanded and every connection
  failed with ``FileNotFoundError: '~/.ssh/config'``.
* **S14** — ``identity_file`` was never expanded anywhere, so a ``~``-prefixed
  key path silently failed to authenticate.

The most important test here is
``test_symlink_at_intermediate_component_is_refused``: guarding only the final
component was one of the rejected fix designs, and an intermediate symlink is
exactly what it misses.
"""

from __future__ import annotations

import os
import tomllib
from pathlib import Path

import pytest

from ssh_mcp.config import ServerRegistry
from ssh_mcp.models import ServerConfig, Settings
from ssh_mcp.paths import (
    PathConfinementError,
    default_transfer_root,
    ensure_root,
    open_beneath,
    validate_relative,
)


@pytest.fixture
def root(tmp_path: Path) -> Path:
    d = tmp_path / "transfers"
    d.mkdir(mode=0o700)
    return d


@pytest.fixture
def root_fd(root: Path):
    fd = ensure_root(str(root))
    yield fd
    os.close(fd)


# --------------------------------------------------------------------------
# Confinement — the B1 fix
# --------------------------------------------------------------------------


def test_legitimate_nested_path_is_allowed(root: Path, root_fd: int) -> None:
    """Sub-directories are permitted — confinement comes from the walk."""
    (root / "sub").mkdir()
    (root / "sub" / "file.txt").write_text("ok")

    fd = open_beneath(root_fd, "sub/file.txt", os.O_RDONLY)
    try:
        assert os.read(fd, 2) == b"ok"
    finally:
        os.close(fd)


def test_symlink_at_final_component_is_refused(
    root: Path, root_fd: int, tmp_path: Path
) -> None:
    secret = tmp_path / "secret.txt"
    secret.write_text("classified")
    (root / "innocent.pub").symlink_to(secret)

    with pytest.raises(PathConfinementError, match="symbolic link"):
        open_beneath(root_fd, "innocent.pub", os.O_RDONLY)


def test_symlink_at_intermediate_component_is_refused(
    root: Path, root_fd: int, tmp_path: Path
) -> None:
    """The case that final-component-only guarding misses.

    ``O_NOFOLLOW`` on the last element alone leaves every parent directory as
    an escape route. This asserts the walk checks each component.
    """
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "file.txt").write_text("escaped")
    (root / "hop").symlink_to(outside)

    with pytest.raises(PathConfinementError, match="symbolic link"):
        open_beneath(root_fd, "hop/file.txt", os.O_RDONLY)


def test_symlink_inside_root_cannot_redirect_a_write(
    root: Path, root_fd: int, tmp_path: Path
) -> None:
    """Escape on the *write* path — the download-to-`~/.ssh/config` route."""
    victim = tmp_path / "config"
    victim.write_text("original")
    (root / "payload").symlink_to(victim)

    with pytest.raises(PathConfinementError):
        open_beneath(root_fd, "payload", os.O_WRONLY | os.O_CREAT, 0o600)

    assert victim.read_text() == "original", "victim file must be untouched"


def test_symlink_inside_root_cannot_redirect_a_read(
    root: Path, root_fd: int, tmp_path: Path
) -> None:
    """Escape on the *read* path — upload_file exfiltration.

    Confining only destinations would leave this open, which is why the fix
    applies the same walk in both directions.
    """
    secret = tmp_path / "id_rsa"
    secret.write_text("PRIVATE KEY")
    (root / "harmless.txt").symlink_to(secret)

    with pytest.raises(PathConfinementError):
        open_beneath(root_fd, "harmless.txt", os.O_RDONLY)


@pytest.mark.parametrize(
    "bad",
    [
        "/etc/shadow",
        "/Users/op/.ssh/config",
        "../escape",
        "sub/../../escape",
        "..",
        "",
        "   ",
    ],
)
def test_unconfinable_paths_are_rejected(bad: str) -> None:
    with pytest.raises(PathConfinementError):
        validate_relative(bad)


def test_nul_byte_is_rejected() -> None:
    with pytest.raises(PathConfinementError, match="NUL"):
        validate_relative("evil\x00.txt")


def test_absolute_path_error_names_the_setting() -> None:
    """Fail fast with an actionable message (CLAUDE.md)."""
    with pytest.raises(PathConfinementError, match="transfer_root"):
        validate_relative("/etc/passwd")


# --------------------------------------------------------------------------
# Root establishment — fail closed
# --------------------------------------------------------------------------


def test_ensure_root_creates_owner_only_directory(tmp_path: Path) -> None:
    target = tmp_path / "nested" / "transfers"
    fd = ensure_root(str(target))
    try:
        assert target.is_dir()
        assert target.stat().st_mode & 0o777 == 0o700, "must not be widened by umask"
    finally:
        os.close(fd)


def test_ensure_root_refuses_group_or_world_accessible_root(tmp_path: Path) -> None:
    loose = tmp_path / "loose"
    loose.mkdir(mode=0o755)
    with pytest.raises(PathConfinementError, match="group/other"):
        ensure_root(str(loose))


def test_ensure_root_refuses_a_non_directory(tmp_path: Path) -> None:
    regular = tmp_path / "afile"
    regular.write_text("x")
    with pytest.raises(PathConfinementError):
        ensure_root(str(regular))


def test_ensure_root_refuses_a_symlinked_root(tmp_path: Path) -> None:
    """The root itself must be a real directory.

    Caught in cross-model review: an earlier revision opened the root without
    ``O_NOFOLLOW``, so pointing ``transfer_root`` at a symlink to a self-owned
    0700 directory — ``~/.ssh`` being the obvious target — sailed through the
    ownership and mode checks and became the pinned root. Every subsequent
    "confined" transfer would then have operated on the wrong tree for the
    lifetime of the process.
    """
    real = tmp_path / "elsewhere"
    real.mkdir(mode=0o700)
    link = tmp_path / "transfers"
    link.symlink_to(real, target_is_directory=True)

    with pytest.raises(PathConfinementError, match="symbolic link"):
        ensure_root(str(link))


def test_ensure_root_accepts_a_symlinked_ancestor(tmp_path: Path) -> None:
    """Only the root component matters — a linked *ancestor* is fine.

    This is the distinction that justifies keeping ``O_NOFOLLOW``: it
    constrains the final component only, so platforms whose temp paths sit
    under a symlink (macOS ``/var`` -> ``/private/var``) still work.
    """
    real_parent = tmp_path / "real_parent"
    real_parent.mkdir()
    linked_parent = tmp_path / "linked_parent"
    linked_parent.symlink_to(real_parent, target_is_directory=True)

    fd = ensure_root(str(linked_parent / "transfers"))
    os.close(fd)


# --------------------------------------------------------------------------
# Default resolution — the defect the review panel caught
# --------------------------------------------------------------------------


def test_default_transfer_root_honours_xdg_data_home(monkeypatch) -> None:
    monkeypatch.setenv("XDG_DATA_HOME", "/custom/data")
    assert default_transfer_root() == "/custom/data/ssh-mcp/transfers"


def test_default_transfer_root_falls_back_to_home(monkeypatch) -> None:
    monkeypatch.delenv("XDG_DATA_HOME", raising=False)
    monkeypatch.setenv("HOME", "/home/someone")
    assert default_transfer_root() == "/home/someone/.local/share/ssh-mcp/transfers"


def test_default_transfer_root_is_never_literal_shell_syntax(monkeypatch) -> None:
    """Guards the exact defect two panel reviewers caught independently.

    The default was originally specified as the string
    ``${XDG_DATA_HOME:-~/.local/share}/ssh-mcp/transfers``. Python expands
    neither form — ``expanduser`` handles only a leading ``~`` and
    ``expandvars`` does not implement ``:-`` — so it would have created a
    directory literally named ``${XDG_DATA_HOME:-~/.local/share}`` on first
    run. The value must always be a real, absolute, expanded path.
    """
    monkeypatch.delenv("XDG_DATA_HOME", raising=False)
    resolved = default_transfer_root()
    assert "$" not in resolved
    assert "{" not in resolved
    assert "~" not in resolved
    assert os.path.isabs(resolved)


# --------------------------------------------------------------------------
# Path expansion at the model boundary — S5 and S14
# --------------------------------------------------------------------------


def test_default_ssh_config_path_is_expanded(monkeypatch) -> None:
    """S5: the default itself must be expanded, not only TOML-supplied values."""
    monkeypatch.setenv("HOME", "/home/someone")
    assert Settings().ssh_config_path == "/home/someone/.ssh/config"


def test_transfer_root_is_expanded(monkeypatch) -> None:
    monkeypatch.setenv("HOME", "/home/someone")
    assert Settings(transfer_root="~/xfer").transfer_root == "/home/someone/xfer"


def test_transfer_root_is_made_absolute(tmp_path: Path, monkeypatch) -> None:
    """A relative root would bind to whatever CWD the launcher happened to use.

    Caught in cross-model review: expansion alone left a relative value (from
    TOML, the env override, or a relative ``XDG_DATA_HOME``) to be resolved
    against the process CWD when the root is pinned, so the confinement
    boundary could move between launches.
    """
    monkeypatch.chdir(tmp_path)
    resolved = Settings(transfer_root="relative/xfer").transfer_root
    assert os.path.isabs(resolved)
    assert resolved == str(tmp_path / "relative" / "xfer")


def test_identity_file_is_expanded(monkeypatch) -> None:
    """S14: passed straight to asyncssh client_keys, which does not expand."""
    monkeypatch.setenv("HOME", "/home/someone")
    server = ServerConfig(name="h", description="d", identity_file="~/.ssh/id_ed25519")
    assert server.identity_file == "/home/someone/.ssh/id_ed25519"


def test_identity_file_none_stays_none() -> None:
    assert ServerConfig(name="h", description="d").identity_file is None


def test_config_without_settings_block_still_expands(
    tmp_path: Path, monkeypatch
) -> None:
    """S5 end-to-end: the exact failing case.

    A servers.toml with no ``[settings]`` section used to skip expansion
    entirely, leaving the literal ``~/.ssh/config`` and failing every
    connection with ``FileNotFoundError``.
    """
    monkeypatch.setenv("HOME", "/home/someone")
    cfg = tmp_path / "servers.toml"
    cfg.write_text(
        '[groups]\nprod = { description = "p" }\n\n'
        '[servers.web]\ndescription = "w"\ngroups = ["prod"]\n'
    )
    registry = ServerRegistry(str(cfg))
    assert "~" not in registry.settings.ssh_config_path
    assert registry.settings.ssh_config_path == "/home/someone/.ssh/config"


def test_transfer_root_env_override_beats_toml(tmp_path: Path, monkeypatch) -> None:
    """``Settings`` is not ``BaseSettings``; the override is explicit."""
    monkeypatch.setenv("SSH_MCP_TRANSFER_ROOT", "/from/env")
    cfg = tmp_path / "servers.toml"
    cfg.write_text('[settings]\ntransfer_root = "/from/toml"\n')
    assert ServerRegistry(str(cfg)).settings.transfer_root == "/from/env"


def test_transfer_root_toml_used_when_env_absent(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.delenv("SSH_MCP_TRANSFER_ROOT", raising=False)
    cfg = tmp_path / "servers.toml"
    cfg.write_text('[settings]\ntransfer_root = "/from/toml"\n')
    assert ServerRegistry(str(cfg)).settings.transfer_root == "/from/toml"


def test_max_command_bytes_default_and_bounds() -> None:
    """B2's non-regex half: the cap a regex fix cannot provide."""
    assert Settings().max_command_bytes == 65536
    with pytest.raises(Exception):
        Settings(max_command_bytes=10)


def test_settings_still_rejects_unknown_keys(tmp_path: Path) -> None:
    """The new fields must not have loosened ``extra='forbid'``."""
    cfg = tmp_path / "servers.toml"
    cfg.write_text("[settings]\nnot_a_real_key = 1\n")
    # Pydantic dataclasses surface an unexpected kwarg as
    # "Unexpected keyword argument", not the "extra_forbidden" shape the
    # loader maps to "unknown key" — assert on the loader's own framing plus
    # the offending key, which is what an operator actually needs to see.
    with pytest.raises(ValueError, match=r"Invalid \[settings\].*not_a_real_key"):
        ServerRegistry(str(cfg))


def test_pyproject_and_config_example_stay_parseable() -> None:
    """Sanity: the shipped example config still validates after the change."""
    example = Path(__file__).resolve().parent.parent / "config" / "servers.example.toml"
    with open(example, "rb") as fh:
        tomllib.load(fh)
