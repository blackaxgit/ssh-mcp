"""Symlink-safe confinement of local filesystem paths beneath a trusted root.

Why this module exists
----------------------
Before v0.6.0, SFTP transfers validated the caller-supplied path *string*
against a denylist (``_SENSITIVE_PATHS``) and then handed that string to
asyncssh, which resolved it independently. Three consequences, all verified
against a live SFTP server:

1. Anything not enumerated passed — ``~/.zshenv``, ``~/.bashrc``,
   ``~/Library/LaunchAgents/*.plist``, ``~/.config/ssh-mcp/servers.toml``
   and the installed package itself were all writable, so a single
   ``download_file`` yielded code execution on the MCP host.
2. asyncssh rewrites an existing-*directory* destination to
   ``<dir>/<basename>`` — a path the validator never saw.
3. A downloaded symlink is recreated locally, and asyncssh's local writer
   follows symlinks, so a later write went *through* it.

A denylist cannot fix (2) or (3), and (1) is unbounded by construction. The
fix is therefore not a better denylist but a different shape: **confine the
operation instead of validating the name.** Every local path is resolved
component-by-component beneath a pinned root directory descriptor, refusing
every symlink on the way. Combined with driving ``SFTPClient.open()``
directly rather than ``get``/``put``, asyncssh never resolves a local path at
all, so (2) and (3) become unreachable code rather than defended-against
behaviour.

The denylist itself was not deleted: ``_SENSITIVE_PATHS`` in ``ssh.py``
survives as a *remote*-path tripwire, which is all it was ever fit to be.
Local paths no longer consult it at all.

Portability and residual risk
-----------------------------
This requires POSIX ``openat``-style semantics (``dir_fd=`` plus both
``O_NOFOLLOW`` and ``O_DIRECTORY``) and is not supported on Windows;
``ensure_root`` fails fast there rather than silently degrading.

Three races are **not** closed. They are stated rather than hidden:

1. A same-filesystem ``rename()`` of an intermediate directory between two
   ``os.open`` calls. Only Linux ``openat2`` with ``RESOLVE_BENEATH`` closes
   it, and as of 2026 CPython has declined to expose it
   (python/cpython#141878, closed "not planned") with no macOS equivalent
   existing at all. The exposure is mitigated by requiring the root to be
   owner-only (0700) and owned by the running user, so an attacker who could
   win that race already has write access to the root.
2. The *remote* check-to-open gap that ``ssh.py`` points here for:
   ``download_file`` refuses non-regular remote files via
   ``sftp.stat(follow_symlinks=False)`` before opening anything, but SFTP v3
   has no atomic no-follow open, so a hostile remote server can still swap
   the path in between. The local destination stays confined regardless.
3. ``_unlink_beneath``'s ``stat``-then-``unlink`` identity gap in ``ssh.py``:
   POSIX has no "unlink iff inode matches" primitive, so a rename landing in
   that exact gap could still slip through. See that function's docstring.
"""

from __future__ import annotations

import errno
import os
import stat
from pathlib import PurePosixPath

__all__ = [
    "PathConfinementError",
    "default_transfer_root",
    "ensure_root",
    "open_beneath",
    "validate_relative",
]


class PathConfinementError(ValueError):
    """A caller-supplied path cannot be confined beneath the transfer root.

    Subclasses ``ValueError`` deliberately: the SFTP tools document that they
    raise ``ValueError``/``RuntimeError``, and the MCP layer converts those to
    ``ToolError``. Keeping that contract means callers need no new except
    clause, and mirrors ``ConfigError`` in ``config.py``.
    """


# Intermediate components are opened read-only as directories, never
# following a symlink. O_CLOEXEC keeps these descriptors out of any child
# process (the SSH ProxyCommand path spawns subprocesses).
#
# Resolved via getattr because O_DIRECTORY/O_NOFOLLOW/O_CLOEXEC do not exist
# on Windows: dereferencing them at import time would raise AttributeError
# when `ssh_mcp.models` is merely imported, pre-empting the actionable
# platform check in ``ensure_root`` with an opaque traceback.
_O_DIRECTORY = getattr(os, "O_DIRECTORY", 0)
_O_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
_O_CLOEXEC = getattr(os, "O_CLOEXEC", 0)
_DIR_FLAGS = os.O_RDONLY | _O_DIRECTORY | _O_NOFOLLOW | _O_CLOEXEC

# The getattr fallbacks above exist so that merely *importing* this module on
# a platform without these constants does not explode. They must never let the
# module RUN without symlink protection: a security flag that silently becomes
# a no-op is the worst possible failure mode, since every guard would appear to
# be in place while enforcing nothing. Both entry points therefore refuse to
# operate unless the real flags are present.
_SYMLINK_PROTECTION = bool(_O_NOFOLLOW and _O_DIRECTORY)


def _require_symlink_protection() -> None:
    """Fail closed when the platform cannot enforce the confinement guarantee."""
    if not _SYMLINK_PROTECTION:
        raise PathConfinementError(
            "this platform does not provide O_NOFOLLOW/O_DIRECTORY, so "
            "symlink-safe file transfer cannot be enforced. Refusing to "
            "proceed without the guarantee rather than transferring files "
            "through an unprotected path."
        )


def default_transfer_root() -> str:
    """Return the default transfer root, honouring ``XDG_DATA_HOME``.

    Computed in code rather than written as a string default: the shell form
    ``${XDG_DATA_HOME:-~/.local/share}`` is not something Python expands.
    ``os.path.expanduser`` handles only a leading ``~`` and
    ``os.path.expandvars`` does not implement the ``:-`` fallback, so that
    form would be taken literally and create a directory with that name on
    first run. (A plain ``~/.local/share/...`` string default *would* be
    expanded — the ``transfer_root`` validator in ``models.py`` runs
    ``expanduser`` + ``abspath``, and ``validate_default=True`` applies it to
    the default too — but it could not honour ``XDG_DATA_HOME``.)
    """
    base = os.environ.get("XDG_DATA_HOME") or os.path.expanduser("~/.local/share")
    return os.path.join(base, "ssh-mcp", "transfers")


def validate_relative(relpath: str) -> tuple[str, ...]:
    """Split ``relpath`` into components, rejecting anything not confinable.

    Rejects absolute paths, ``..``, a path that is only ``.``, and embedded
    NUL bytes. Empty and ``.`` components *inside* a path are collapsed
    rather than rejected: ``PurePosixPath`` already drops them, so ``"a//b"``
    and ``"a/./b"`` both yield ``("a", "b")``. Sub-directories *are*
    permitted — confinement comes from the component-wise walk in
    :func:`open_beneath`, not from forbidding depth.

    Returns:
        The path components, e.g. ``("sub", "file.txt")``.

    Raises:
        PathConfinementError: with an actionable message; the two that mean
            "this escapes the root" name the ``transfer_root`` setting.
    """
    if not isinstance(relpath, str) or not relpath.strip():
        raise PathConfinementError("path must be a non-empty string")

    if "\x00" in relpath:
        raise PathConfinementError("path contains a NUL byte")

    if os.path.isabs(relpath):
        raise PathConfinementError(
            f"absolute paths are no longer accepted: {relpath!r}. "
            "Local paths are relative to the configured 'transfer_root' "
            "(see [settings] in servers.toml, or SSH_MCP_TRANSFER_ROOT)."
        )

    parts = PurePosixPath(relpath).parts
    if not parts:
        raise PathConfinementError(f"path resolves to no components: {relpath!r}")

    for part in parts:
        # Defensive, not load-bearing: ``.parts`` never yields "" or "."
        # (PurePosixPath collapses both) and yields os.sep only for absolute
        # paths, already rejected above. Kept so the invariant is enforced
        # rather than assumed, should that normalisation ever change.
        if part in ("", ".", os.sep):
            raise PathConfinementError(f"path contains an empty component: {relpath!r}")
        if part == "..":
            raise PathConfinementError(
                f"parent traversal is not permitted: {relpath!r}. "
                "Local paths must stay inside 'transfer_root'."
            )
    return parts


def ensure_root(path: str) -> int:
    """Create/validate the transfer root and return a pinned directory fd.

    The descriptor is opened once and then held by ``SSHManager`` — pinned
    lazily on the first SFTP transfer rather than at startup, refcounted
    across concurrent transfers, and closed by ``close_all()`` — so later
    transfers resolve against the directory that was validated here rather
    than re-resolving a path that may since have been replaced.

    Fails closed, in this order: a platform without POSIX ``dir_fd`` or
    without ``O_NOFOLLOW``/``O_DIRECTORY``; then a root that cannot be
    created, is itself a symbolic link (the check the comment below calls the
    whole point), is not a directory, is not owned by this user, or is
    group/other-accessible. Each raises rather than silently proceeding with
    a weaker boundary. Note ``makedirs`` runs *before* the symlink, ownership
    and mode checks, so the directory is created as a side effect even on the
    paths that then refuse to use it.

    Raises:
        PathConfinementError: if the root cannot be established safely.
    """
    # NB: os.supports_dir_fd holds the *function objects* that accept dir_fd,
    # not their names — membership must be tested with ``os.open``, not
    # ``"open"``, which would always be False and reject every platform.
    if os.name != "posix" or os.open not in os.supports_dir_fd:
        raise PathConfinementError(
            "ssh-mcp file transfers require POSIX openat semantics "
            f"(dir_fd), which this platform ({os.name}) does not provide."
        )
    _require_symlink_protection()

    existed = os.path.isdir(path)
    try:
        os.makedirs(path, mode=0o700, exist_ok=True)
        if not existed:
            # makedirs' mode is masked by umask; set it explicitly so a
            # permissive umask cannot widen a security boundary.
            os.chmod(path, 0o700)
    except OSError as exc:
        raise PathConfinementError(
            f"could not create transfer_root {path!r}: {exc}"
        ) from exc

    # O_NOFOLLOW is deliberately KEPT here. It constrains only the *final*
    # component, so it does not object to a symlinked ancestor such as
    # macOS's /var -> /private/var; it objects to `transfer_root` itself
    # being a link. That distinction is the whole point: a symlink at the
    # root pointing to a self-owned 0700 tree (~/.ssh being the obvious
    # target) would sail through the ownership and mode checks below and
    # become the pinned root, defeating confinement for the process
    # lifetime. An earlier revision stripped this flag and was caught in
    # review.
    if os.path.islink(path):
        raise PathConfinementError(
            f"transfer_root {path!r} is a symbolic link. The root must be a "
            "real directory — otherwise everything 'confined' beneath it "
            "resolves somewhere else entirely."
        )
    try:
        fd = os.open(path, _DIR_FLAGS)
    except OSError as exc:
        # Belt-and-braces for the symlink swapped in after the islink check.
        raise PathConfinementError(
            f"could not open transfer_root {path!r} safely: {exc}"
        ) from exc
    try:
        st = os.fstat(fd)
        if not stat.S_ISDIR(st.st_mode):
            raise PathConfinementError(f"transfer_root is not a directory: {path!r}")
        if st.st_uid != os.getuid():
            raise PathConfinementError(
                f"transfer_root {path!r} is owned by uid {st.st_uid}, "
                f"not by the running user (uid {os.getuid()}). Refusing to "
                "use a directory this process does not own."
            )
        if st.st_mode & 0o077:
            raise PathConfinementError(
                f"transfer_root {path!r} is accessible to group/other "
                f"(mode {stat.filemode(st.st_mode)}). Run: chmod 700 {path}"
            )
    except BaseException:
        os.close(fd)
        raise
    return fd


def open_beneath(root_fd: int, relpath: str, flags: int, mode: int = 0o600) -> int:
    """Open ``relpath`` beneath ``root_fd``, refusing every symlink component.

    Each intermediate component is opened with ``O_DIRECTORY | O_NOFOLLOW``
    relative to the previous one, so a symlink *anywhere* in the path — not
    merely the final element — aborts the walk. This is the difference that
    matters: guarding only the last component leaves every parent directory
    as an escape route, and leaves an ``upload_file`` *read* free to follow a
    link planted inside the root.

    The same walk is duplicated in ``ssh.py``'s ``_unlink_beneath``, which
    needs the *parent* descriptor this function does not hand back. Keep the
    two in step — but note their error contracts deliberately differ: that
    copy does **not** translate ``ELOOP``/``ENOTDIR`` into
    ``PathConfinementError``, because its only caller treats every
    ``OSError`` as best-effort-cleanup-failed anyway.

    Args:
        root_fd: Directory descriptor from :func:`ensure_root`.
        relpath: Root-relative path; sub-directories are permitted but must
            already exist — the walk never passes ``O_CREAT``, so a missing
            intermediate directory surfaces as a bare ``OSError`` (ENOENT).
        flags: ``os.open`` flags for the final component. ``O_NOFOLLOW`` and
            ``O_CLOEXEC`` are always added.
        mode: Creation mode when ``flags`` includes ``O_CREAT``.

    Returns:
        An open file descriptor. The caller owns it and must close it.

    Raises:
        PathConfinementError: on a symlink component or an unconfinable path.
        OSError: for ordinary filesystem errors (missing file, EEXIST, ...),
            which callers translate into their own messages.
    """
    _require_symlink_protection()
    *directories, leaf = validate_relative(relpath)

    opened: list[int] = []
    parent = root_fd
    current = leaf
    try:
        for component in directories:
            current = component
            fd = os.open(component, _DIR_FLAGS, dir_fd=parent)
            opened.append(fd)
            parent = fd
        current = leaf
        return os.open(leaf, flags | _O_NOFOLLOW | _O_CLOEXEC, mode, dir_fd=parent)
    except OSError as exc:
        # O_NOFOLLOW on a symlink gives ELOOP — except when combined with
        # O_DIRECTORY on a symlink-to-directory, where macOS reports ENOTDIR
        # instead. Both mean "refused"; lstat tells us which to report so the
        # operator gets an accurate reason rather than a guess.
        if exc.errno in (errno.ELOOP, errno.ENOTDIR):
            reason = "is not a directory"
            try:
                if stat.S_ISLNK(os.lstat(current, dir_fd=parent).st_mode):
                    reason = "is a symbolic link"
            except OSError:  # pragma: no cover - racing removal
                pass
            raise PathConfinementError(
                f"refusing to open {relpath!r}: component {current!r} {reason}. "
                "Every component must be a real directory or file inside "
                "'transfer_root'."
            ) from exc
        raise
    finally:
        # Intermediate descriptors are no longer needed once the leaf is
        # open; the returned descriptor stays valid after they close.
        for fd in opened:
            os.close(fd)
