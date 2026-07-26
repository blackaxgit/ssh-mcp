"""SSH connection manager with pooling and jump host support.

This module provides the SSHManager class that handles async SSH connections
to multiple servers with connection pooling, idle eviction, and parallel
group execution capabilities.

It also holds the three security-relevant surfaces that account for most of
this file: the credential-redaction pipeline applied to every command before
it reaches a logger (``_redact_secrets``), the destructive-command tripwire
(``_is_dangerous_command``), and the SFTP upload/download implementations,
whose local paths are resolved beneath a pinned ``transfer_root`` file
descriptor (B1) via ``ssh_mcp.paths.open_beneath`` rather than handed to
asyncssh as path strings.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import os
import re
import shlex
import stat
import time
import uuid
from collections.abc import AsyncIterator, Callable
from typing import Any, TypeVar

import asyncssh
import structlog.contextvars
from asyncssh.constants import FILEXFER_TYPE_REGULAR

from ssh_mcp.config import ServerRegistry
from ssh_mcp.models import ExecResult, ServerConfig, Settings
from ssh_mcp.paths import (
    PathConfinementError,
    ensure_root,
    open_beneath,
    validate_relative,
)

logger = logging.getLogger(__name__)

# Soft OTel import — see server.py for rationale. When the extras aren't
# installed, ``_ssh_tracer`` is None and inner ops skip span creation.
try:
    from opentelemetry import trace as _otel_trace

    _ssh_tracer: Any = _otel_trace.get_tracer("ssh_mcp.ssh")
except ImportError:  # pragma: no cover - exercised by env without extras
    _ssh_tracer = None

# ---------------------------------------------------------------------------
# Tunable constants — promoted from inline literals for discoverability.
#
# These are deliberately NOT promoted to Settings fields: they are
# implementation details that operators should not need to tune. Lifting
# them to module-level makes them greppable and testable without widening
# the public config surface. (``_MAX_SFTP_BYTES`` is the one candidate for
# promotion — see its own comment below.)
# ---------------------------------------------------------------------------

# Eviction loop wakes this often to scan for idle connections. Smaller =
# tighter idle enforcement, more wake-ups; larger = looser enforcement,
# fewer wake-ups. 60s matches a typical SSH keepalive cadence.
_EVICTION_LOOP_INTERVAL_S: int = 60

# Maximum recursion depth for chained jump hosts. Prevents infinite loops
# from mis-configured circular ProxyJump chains (the config loader also
# detects this at load time — this is a belt-and-suspenders guard at
# runtime in case the registry is mutated between loads).
_MAX_JUMP_HOST_DEPTH: int = 5

# Maximum file size (in bytes) allowed for a single SFTP transfer.
# 100 MiB is a sensible default for an MCP tool — larger files should use
# rsync, scp streaming, or chunked transfer. Upload is hard-blocked;
# download emits a warning (the bytes are already on disk by then).
_MAX_SFTP_BYTES: int = 104_857_600  # 100 MiB default; future: promote to Settings field


def _make_connection_id(server_name: str) -> str:
    """Return a short, grep-friendly connection identifier.

    Format: ``{server}-{pid}-{short-uuid}``. Short enough to read in logs,
    unique enough to distinguish reconnects. The UUID suffix is 8 hex chars
    which gives ~4 billion possibilities — collisions in a single process
    lifetime are effectively impossible.
    """
    return f"{server_name}-{os.getpid()}-{uuid.uuid4().hex[:8]}"


def _safe_log_value(value: Any) -> str:
    """Escape a potentially attacker-controlled value for safe log interpolation.

    Red Team R3 finding C4: a valid MCP client can set ``server_name`` or
    ``command`` to a value containing embedded newlines or CR/LF sequences.
    When the default console log format interpolates such a value, SIEM
    parsers treating each line as a separate event see forged log records.

    This helper converts the value to its ``repr()`` form, which escapes
    ``\\n``, ``\\r``, ``\\t``, and other control characters as literal
    backslash sequences. The quoted output is slightly noisier for normal
    values but impossible to misparse as a separate log line.

    Using ``repr()`` is preferable to ``json.dumps()`` because it preserves
    the visual identity of the value for operators reading console logs
    while still escaping every ASCII control character.
    """
    return repr(value)


# ---------------------------------------------------------------------------
# Credential redaction (production incident 2026-04-11)
#
# Audit logs previously wrote the raw ``command`` value for every tool
# call, which meant ``mysql -pSecret``, ``PGPASSWORD=xxx psql``, and
# ``curl -H 'Authorization: Bearer <jwt>' ...`` arrived in stderr, got
# forwarded to centralized log aggregators (Loki / Datadog / Splunk),
# and leaked the plaintext secret to every operator with log access.
#
# ``_redact_secrets`` runs a set of targeted regex substitutions against
# a command string before it reaches any logger. The list is a TRIPWIRE
# for the most common credential patterns — it is NOT a substitute for
# handling secrets outside of command arguments entirely. When possible,
# pass credentials via env vars, Docker/K8s secrets, or dedicated config
# files, NOT on the command line.
# ---------------------------------------------------------------------------

_REDACTION_PLACEHOLDER: str = "{REDACTED}"

# Environment variables that are known credential sinks. Matched
# case-insensitively as ``<NAME>=<value>`` substrings.
_SECRET_ENV_NAMES: tuple[str, ...] = (
    # Database passwords
    "PGPASSWORD",
    "MYSQL_PWD",
    "REDIS_PASSWORD",
    "MONGODB_PASSWORD",
    "DB_PASSWORD",
    "DATABASE_PASSWORD",
    # Cloud providers
    "AWS_SECRET_ACCESS_KEY",
    "AWS_SESSION_TOKEN",
    "GCP_API_KEY",
    "AZURE_CLIENT_SECRET",
    # Source control / CI
    "GH_TOKEN",
    "GITHUB_TOKEN",
    "GITLAB_TOKEN",
    "NPM_TOKEN",
    # Generic / OAuth
    "TOKEN",
    "API_KEY",
    "API_TOKEN",
    "SECRET",
    "SECRET_KEY",
    "BEARER_TOKEN",
    "ACCESS_TOKEN",
    "REFRESH_TOKEN",
    "CLIENT_SECRET",
    "PRIVATE_KEY",
)


def _long_flag_is_credential(flag: str) -> bool:
    """Return True if ``flag`` (e.g. ``--db-password``) names a credential.

    Defect 1 (panel iteration 2, all three reviewers): the previous regex
    tried to express "optional bounded junk, then one of these keywords"
    as a SINGLE pattern (``(?:[\\w-]{0,40}[-_])?(?:password|...)``), which
    forced a length bound on the junk to stay linear — the junk's
    character class (``[\\w-]``) overlaps the keyword alternation that
    follows it, so an unbounded possessive prefix would greedily swallow
    the keyword itself and never redact anything (see
    ``_redact_long_flags`` for why plain unbounded backtracking isn't safe
    either). That bound is exactly what let
    ``--aaa...(41 a's)...-password=Secret123`` leak past.

    Splitting the concern in two removes the tension: the flag NAME is
    captured with no length limit at all (see ``_redact_long_flags``), and
    this plain Python suffix check — which has no bound of its own —
    decides whether that name is credential-shaped.
    """
    body = flag[2:] if flag.startswith("--") else flag
    body_lower = body.lower()
    for kw in _LONG_FLAG_KEYWORDS:
        if (
            body_lower == kw
            or body_lower.endswith(f"-{kw}")
            or body_lower.endswith(f"_{kw}")
        ):
            return True
    return False


_LONG_FLAG_KEYWORDS: tuple[str, ...] = (
    "password",
    "pass",
    "token",
    "secret",
    "key",
    "credential",
)

# Character set used by the token-wise URL scanner below
# (``_redact_url_basic_auth``). Defect A (panel iteration 3, verified by
# executing code): a THIRD implementation of these two rules — a
# whole-text positional scanner — replaced the length-bounded regexes
# from iteration 2. It was fast and, for the URL rule, unbounded in
# theory, but it carried a shape bug of its own:
#
#   * ``_redact_long_flags`` (the old whole-text version) assumed that
#     for a space-separated flag the NEXT token was always that flag's
#     value, and jumped its scan position straight past it
#     (``i = value_end``). For a routine command shape — a boolean flag
#     immediately followed by a credential flag, e.g.
#     ``docker run --rm --password=Secret99`` or
#     ``cmd --verbose --password=Secret123`` — that jump landed
#     ``i`` in the middle of ``--password=Secret99``'s own token, so it
#     was never classified at all. Not a rare edge case: ``--rm``,
#     ``--verbose``, ``--detach``, ``--help``, ``--dry-run`` are all
#     ordinary boolean flags.
#   * ``_redact_url_basic_auth`` (the old whole-text version) capped the
#     backward scheme walk at 32 chars for O(1)-per-candidate lookup.
#     Real schemes are short, but a scheme *shape* longer than 32 chars
#     (``a`` + 40 digits + ``://user:Secret123@host``) walked back only
#     32 chars, landed on a digit instead of the leading letter, was
#     judged "not alpha-led", and the entire URL — including its
#     password — was skipped rather than redacted.
#
# Adding a fourth special case for each of these would only fix the
# instance, not the class (this is the third time that has happened).
# The fix is a shape change: tokenize the command ONCE, in original
# order, with exact whitespace preserved (``_split_ws_preserving``,
# Unicode-aware via ``str.isspace()`` rather than a hardcoded
# ``" \t\r\n"`` set — a hardcoded set is exactly what silently narrowed
# the old regex's ``\s+`` and would let NBSP/vertical-tab-separated
# flags slip past unclassified), then classify EVERY non-whitespace
# token on its own turn in ``_redact_long_flags`` and
# ``_redact_url_basic_auth``. A flag may look exactly one token ahead to
# consume a value, but nothing can cause a LATER token to be skipped
# without first being classified — that is what makes "skip a
# candidate" impossible rather than merely unobserved so far. Both
# scanners stay O(n): tokenizing is one linear pass, and every rule
# after that only ever looks at TOKEN-local text (a token has no
# internal whitespace by construction), so there is no unbounded
# quantifier to bound in the first place — which is also what makes the
# URL scheme walk safe to leave unbounded (see ``_redact_url_in_token``).
_URL_TERMINATORS: frozenset[str] = frozenset(":@/?#")


def _split_ws_preserving(text: str) -> list[tuple[str, bool]]:
    """Split ``text`` into alternating ``(chunk, is_whitespace)`` runs, in
    original order, that reassemble byte-identical via
    ``"".join(chunk for chunk, _ in result)``.

    Uses ``str.isspace()`` (Unicode-aware) rather than a fixed character
    set — see the module comment above ``_URL_TERMINATORS`` for why a
    hardcoded set is itself a leak vector here.
    """
    n = len(text)
    if n == 0:
        return []
    chunks: list[tuple[str, bool]] = []
    start = 0
    cur_ws = text[0].isspace()
    for i in range(1, n):
        c_ws = text[i].isspace()
        if c_ws != cur_ws:
            chunks.append((text[start:i], cur_ws))
            start = i
            cur_ws = c_ws
    chunks.append((text[start:n], cur_ws))
    return chunks


def _redact_url_in_token(token: str) -> str:
    """Redact ``scheme://user:password@host`` within a single
    whitespace-delimited token. O(len(token)); scheme, userinfo, and
    password are all unbounded — see the module comment above
    ``_URL_TERMINATORS``.

    Precomputing "nearest terminator" and "nearest '@'" once, in a
    single reverse pass, keeps each ``"://"`` candidate's forward lookups
    O(1); the backward scheme walk has no precomputed bound; it is safe
    to leave unbounded because it is scoped to one token and the ``'/'``
    inside ``"://"`` itself stops the NEXT candidate's walk immediately,
    so no span of the token is ever walked twice.
    """
    n = len(token)
    if "://" not in token:
        return token

    next_terminator = [n] * (n + 1)
    next_at = [n] * (n + 1)
    t_term = t_at = n
    for idx in range(n - 1, -1, -1):
        c = token[idx]
        if c in _URL_TERMINATORS:
            t_term = idx
        if c == "@":
            t_at = idx
        next_terminator[idx] = t_term
        next_at[idx] = t_at

    out: list[str] = []
    last_emit = 0
    i = 0
    while True:
        idx = token.find("://", i)
        if idx == -1:
            break

        j = idx
        while j > 0 and (token[j - 1].isalnum() or token[j - 1] in "+.-"):
            j -= 1
        if j == idx or not token[j].isalpha():
            i = idx + 3
            continue

        p = idx + 3
        term = next_terminator[p] if p <= n else n
        if term >= n or token[term] != ":":
            i = idx + 3
            continue
        colon_pos = term

        pass_start = colon_pos + 1
        at_pos = next_at[pass_start] if pass_start <= n else n
        if at_pos >= n:
            i = idx + 3
            continue

        out.append(token[last_emit : colon_pos + 1])
        out.append(_REDACTION_PLACEHOLDER)
        out.append("@")
        last_emit = at_pos + 1
        i = at_pos + 1

    out.append(token[last_emit:])
    return "".join(out)


def _redact_url_basic_auth(text: str) -> str:
    """Token-wise redaction of ``scheme://user:password@host``.

    Replaces the old whole-text positional scanner. See the module
    comment above ``_URL_TERMINATORS`` for the specific leak
    (32-char-capped scheme walk) this closes.
    """
    if "://" not in text:
        return text
    chunks = _split_ws_preserving(text)
    return "".join(
        chunk if is_ws or "://" not in chunk else _redact_url_in_token(chunk)
        for chunk, is_ws in chunks
    )


# Matches a ``--<name>=`` flag shape anywhere within a single token (not
# anchored to the token start) — see ``_redact_credential_in_token``.
_LONG_FLAG_EQ_RE: re.Pattern[str] = re.compile(r"--[\w-]+=")


def _redact_credential_in_token(token: str) -> str:
    """Redact the first credential-shaped ``--<name>=`` occurring
    ANYWHERE within ``token`` — not only at offset 0 — from that name's
    ``=`` through the end of the token.

    Defect 1 (panel iteration 4, cursor, verified by executing code and
    diffing against main): the original whole-text ``re.sub`` scanned
    every position in the command string, so a credential flag nested
    inside another token's value — ``--flag=--password=secret`` — was
    still found and redacted (the match starts wherever ``--password=``
    begins, regardless of what precedes it). The token-wise rewrite
    (Defect A) that replaced it classified only the flag NAME at a
    token's start (before the first ``=``), so ``--flag`` (not
    credential-shaped) short-circuited the whole token and the nested
    ``--password=secret`` was never looked at — regressing a case the
    original handled. ``finditer`` restores the "scan every position"
    property within THIS token: it walks left to right past each
    non-credential ``--name=`` candidate (e.g. ``--flag=``) until it
    finds one that is credential-shaped, then redacts from there. This
    keeps the token-wise property that made Defect A's fix work — no
    TOKEN can be skipped, because the caller below still visits every
    token on its own turn — while no longer stopping at the first ``=``
    within a token.
    """
    for match in _LONG_FLAG_EQ_RE.finditer(token):
        name = match.group()[2:-1]  # strip leading "--" and trailing "="
        if _long_flag_is_credential(name):
            return token[: match.end()] + _REDACTION_PLACEHOLDER
    return token


def _redact_long_flags(text: str) -> str:
    """Token-wise redaction of ``--<flag>=<value>`` / ``--<flag> <value>``.

    Replaces the old whole-text positional scanner. See the module
    comment above ``_URL_TERMINATORS`` for the specific leak (skipping a
    credential flag that immediately follows a boolean flag) this
    closes. Every non-whitespace token is classified on its own loop
    turn:

    * ``--<name>=<value>`` — a credential-shaped ``--<name>=`` occurring
      ANYWHERE in the token (see ``_redact_credential_in_token``, Defect
      1) redacts from that ``=`` to the end of THIS token.
    * ``--<name>`` alone — credential-shaped ``<name>`` looks at exactly
      the next non-whitespace token and redacts it, UNLESS that token
      itself starts with ``-`` (then this flag was boolean/valueless;
      the next token is left untouched here and gets its own turn on
      the next loop iteration — it is never silently skipped).
    * anything else — passed through unchanged.

    Note (Defect 1 follow-up, scope note): a credential value that is
    itself shell-quoted and contains whitespace (``--password="a b"``)
    is only partially redacted here, same as on ``main`` — matching
    ``\\S+``-style value matching is inherently quote-unaware. This
    module is a TRIPWIRE, not a proof of correctness (see the module
    docstring above ``_REDACTION_PLACEHOLDER``); the documented
    mitigation is to pass credentials via env files or stdin rather than
    argv, not to widen this scanner into a shell-quoting parser.
    """
    if "--" not in text:
        return text
    chunks = _split_ws_preserving(text)
    out = [chunk for chunk, _is_ws in chunks]
    n = len(chunks)
    i = 0
    while i < n:
        chunk, is_ws = chunks[i]
        if is_ws or not chunk.startswith("--"):
            i += 1
            continue

        flag_name, eq, _value = chunk.partition("=")
        if eq:
            out[i] = _redact_credential_in_token(chunk)
            i += 1
            continue

        if _long_flag_is_credential(flag_name):
            j = i + 1
            if j < n and chunks[j][1]:  # skip exactly one whitespace run
                j += 1
            if j < n and not chunks[j][1] and not chunks[j][0].startswith("-"):
                out[j] = _REDACTION_PLACEHOLDER
                i = j + 1
                continue
        i += 1

    return "".join(out)


def _build_credential_subs() -> list[Callable[[str], str]]:
    """Compile the ordered redaction pipeline.

    Each entry is a single-argument callable that returns the redacted
    string. Order matters: URL basic-auth runs first so the ``@``
    separator can't be swallowed by a later rule. Env-var patterns run
    before short-flag patterns because ``PGPASSWORD=xxx`` is more
    specific than any flag-based match, and the two hand-written scanners
    (Defect A) that replaced the old regex rules 1 and 8/9 keep their
    original relative position — URL first, long-flags last.

    Rules 4/5/6 use lookbehind, which is why this pipeline stays on
    Python's ``re`` engine for everything except the two rules that
    needed hand-written scanners (RE2 was considered and rejected for
    that reason).
    """
    env_alt = "|".join(re.escape(name) for name in _SECRET_ENV_NAMES)

    def _regex_step(pattern: re.Pattern[str], repl: Any) -> Callable[[str], str]:
        return lambda text: pattern.sub(repl, text)

    return [
        # 1. Basic auth credentials embedded in a URL:
        #    ``scheme://user:password@host``. See _redact_url_basic_auth.
        _redact_url_basic_auth,
        # 2. HTTP ``Authorization:`` header with Bearer/Basic/Digest/Token.
        _regex_step(
            re.compile(
                r"(Authorization:\s*(?:Bearer|Basic|Digest|Token)\s+)(\S+)",
                re.IGNORECASE,
            ),
            lambda m: f"{m.group(1)}{_REDACTION_PLACEHOLDER}",
        ),
        # 3a. Known credential env vars (enumerated list, exact match).
        _regex_step(
            re.compile(
                r"\b(" + env_alt + r")=(\S+)",
                re.IGNORECASE,
            ),
            lambda m: f"{m.group(1)}={_REDACTION_PLACEHOLDER}",
        ),
        # 3b. (v0.4.3 G2) Generic env var SUFFIX patterns:
        #     ``*_PASSWORD=``, ``*_SECRET=``, ``*_TOKEN=``, ``*_KEY=``,
        #     ``*_CREDENTIAL=``, ``*_PWD=``. Catches ``VAULT_TOKEN``,
        #     ``STRIPE_SECRET_KEY``, ``MY_CUSTOM_PASSWORD``, etc. without
        #     needing to enumerate every possible prefix. Safe unbounded:
        #     the leading ``\b`` anchors the number of match ATTEMPTS to
        #     the number of word-boundary starts, not every character
        #     position, so a long run with no ``=`` costs O(run length)
        #     once, not once per position within it.
        _regex_step(
            re.compile(
                r"\b(\w+(?:_PASSWORD|_SECRET|_TOKEN|_KEY|_CREDENTIAL|_PWD))=(\S+)",
                re.IGNORECASE,
            ),
            lambda m: f"{m.group(1)}={_REDACTION_PLACEHOLDER}",
        ),
        # 4. MySQL/MariaDB short password flag QUOTED form.
        _regex_step(
            re.compile(r"(?<![\w-])(-p)(['\"])([^'\"]*)(\2)"),
            lambda m: f"{m.group(1)}{m.group(2)}{_REDACTION_PLACEHOLDER}{m.group(4)}",
        ),
        # 5. MySQL/MariaDB short password flag UNQUOTED form (≥3 chars).
        _regex_step(
            re.compile(r"(?<![\w-])(-p)(\S{3,})"),
            lambda m: f"{m.group(1)}{_REDACTION_PLACEHOLDER}",
        ),
        # 6. (v0.4.3 G4) ``curl -u user:password`` basic auth flag.
        #    Redacts the password portion after the colon.
        _regex_step(
            re.compile(r"(?<!\w)(-u\s+\S+:)(\S+)"),
            lambda m: f"{m.group(1)}{_REDACTION_PLACEHOLDER}",
        ),
        # 7. (v0.4.3 G4) ``sshpass -p PASSWORD`` (space-separated).
        #    sshpass uses ``-p`` with a SPACE before the password, unlike
        #    MySQL which uses no space. Match ``sshpass`` prefix to
        #    disambiguate from the MySQL rule.
        _regex_step(
            re.compile(r"(sshpass\s+-p\s+)(\S+)", re.IGNORECASE),
            lambda m: f"{m.group(1)}{_REDACTION_PLACEHOLDER}",
        ),
        # 8/9. Long flags with ``=`` or whitespace separator. See
        #      _redact_long_flags — merges the old rules 8 and 9 into one
        #      scanner since both forms share the same flag-name/keyword
        #      logic.
        _redact_long_flags,
    ]


_CREDENTIAL_SUBS: list[Callable[[str], str]] = _build_credential_subs()


def _redact_secrets(value: Any) -> Any:
    """Replace known credential patterns in ``value`` with a placeholder.

    Runs a targeted pipeline of substitutions for the most common
    command-line credential leak patterns (``-pSecret``,
    ``--password=xxx``, ``PGPASSWORD=xxx``, ``Authorization: Bearer xxx``,
    ``https://user:pass@host``, and the other patterns compiled by
    ``_build_credential_subs``).

    Idempotent: applying the function to already-redacted text produces
    identical output — the placeholder itself does not match any rule.
    Safe for ``None`` and empty strings (passed through unchanged).
    Non-string inputs are returned as-is so structured values (ints,
    dicts, etc.) are not accidentally coerced by the caller.

    This is a TRIPWIRE, not a proof of correctness — operators must
    still prefer env-file secrets or stdin over command-line arguments.
    """
    if value is None or value == "":
        return value
    if not isinstance(value, str):
        return value
    out = value
    for step in _CREDENTIAL_SUBS:
        out = step(out)
    return out


# Dangerous command patterns that could be destructive.
#
# This list is a TRIPWIRE for obvious accidents, NOT a security boundary.
# Sophisticated attackers can bypass it with base64-encoded payloads,
# shell hex escapes, Unicode homoglyphs, or subshell indirection. The
# patterns below catch the highest-frequency mistakes — they are NOT
# expected to resist a motivated adversary. Operators who need real
# isolation must sandbox at a lower layer (containers, SELinux, etc.).
# Red Team R4 hardening: every letter-bearing pattern is compiled with
# ``re.IGNORECASE`` so ``rm -RF /`` / ``RM -rf /`` don't bypass (the
# fork-bomb pattern below matches no letters, so it needs no flag). The
# rm-flag patterns use lookaheads instead of ordered character classes so
# `-rfv`, `-vfr`, `-rfvi` (any order with extra flags) all match.
_DANGEROUS_PATTERNS = [
    # Filesystem root wipe via rm -rf — catches `/`, `~`, `$HOME`, `$USER`
    # forms. Flag cluster must contain BOTH `r` and `f` anywhere, plus
    # optional `v`, `i`, `I`, `d`, `h`, `n`, `N` flags in any order.
    re.compile(
        r"rm\s+-(?=[rfvhidIn]*r)(?=[rfvhidIn]*f)[rfvhidIn]+"
        r"\s+(?:/|~|\$\{?HOME\}?|\$\{?USER\}?)",
        re.IGNORECASE,
    ),
    # S11 (RC7): the combined-cluster pattern above only matches a SINGLE
    # token like -rf/-fr. It misses recursive and force given as separate
    # tokens (`rm -r -f /`) or as GNU long options (`rm --recursive
    # --force /`), which operators reasonably expect to be caught. Both
    # flag orders are covered; short/long forms are independent per slot,
    # so this also matches `rm -r --force /` and `rm --recursive -f /`.
    re.compile(
        r"rm\s+(?:-r|--recursive)\s+(?:-f|--force)\s+"
        r"(?:/|~|\$\{?HOME\}?|\$\{?USER\}?)",
        re.IGNORECASE,
    ),
    re.compile(
        r"rm\s+(?:-f|--force)\s+(?:-r|--recursive)\s+"
        r"(?:/|~|\$\{?HOME\}?|\$\{?USER\}?)",
        re.IGNORECASE,
    ),
    # Filesystem creation over raw devices
    re.compile(r"mkfs", re.IGNORECASE),
    # dd to/from a block device. The plain `dd\s+if=` rule below requires
    # if= immediately after `dd `; `dd of=/dev/sda if=/dev/zero` puts of=
    # first and slipped past it (RC7/S11). Bounded (0-10 tokens, non-greedy)
    # so this stays O(n) rather than an unbounded scan.
    re.compile(r"\bdd\b(?:\s+\S+){0,10}?\s+if=", re.IGNORECASE),
    re.compile(r"dd\s+if=", re.IGNORECASE),
    # Redirect into a block device or system auth database
    re.compile(r">\s*/dev/sd", re.IGNORECASE),
    re.compile(r">\s*/dev/nvme", re.IGNORECASE),
    re.compile(r">\s*/dev/hd", re.IGNORECASE),
    re.compile(
        r">\s*/etc/(passwd|shadow|gshadow|sudoers)\b",
        re.IGNORECASE,
    ),
    # chmod / chown on root or home
    re.compile(r"chmod\s+-?R?\s*777\s+/", re.IGNORECASE),
    # S11 (RC7): the pattern above requires -R/R BEFORE the mode
    # (`chmod -R 777 /`). `chmod 777 -R /` — mode first, flag after — is
    # equally destructive and equally valid to `chmod`, but slipped past.
    re.compile(r"chmod\s+777\s+(?:-R|--recursive)\s+/", re.IGNORECASE),
    # find-based recursive delete — equivalent destructive power. Match
    # /, ~, $HOME roots; tolerate any expression between root and -delete.
    re.compile(
        r"find\s+(?:/|~|\$\{?HOME\}?)(?:\S*)?\s+.*-delete",
        re.IGNORECASE,
    ),
    re.compile(
        r"find\s+(?:/|~|\$\{?HOME\}?)(?:\S*)?\s+.*-exec\s+rm\b",
        re.IGNORECASE,
    ),
    # Block-level wipes
    re.compile(r"shred\s+(-\w*\s+)*/dev/", re.IGNORECASE),
    re.compile(r"wipefs\s+(-\w+\s+|--\w+\s+)*/dev/", re.IGNORECASE),
    re.compile(r"blkdiscard\s+/dev/", re.IGNORECASE),
    re.compile(r"sgdisk\s+-[Zz]\s+/dev/", re.IGNORECASE),
    # Partition-table destruction
    re.compile(r"parted\s+/dev/\S+\s+mklabel", re.IGNORECASE),
    re.compile(r"fdisk\s+/dev/sd", re.IGNORECASE),
    # Classic fork bomb — tolerates spaced variants.
    re.compile(r":\s*\(\s*\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:"),
    # P10: Encoded payload execution wrappers (tripwire, not boundary)
    re.compile(
        r"base64\s+(-d|--decode)\s*\|\s*(bash|sh|zsh|python|perl|ruby)", re.IGNORECASE
    ),
    re.compile(r"\beval\s+[\"'\$\(]", re.IGNORECASE),
    re.compile(r"\b(python|python3|perl|ruby)\s+-(c|e)\s+", re.IGNORECASE),
    re.compile(r"\bbash\s+-c\s+", re.IGNORECASE),
]

# Sensitive paths that should be blocked in SFTP operations.
#
# Matches are substring-based AFTER path normalization (see _normalize_path).
# Normalization collapses double slashes and dot components so that
# ``/etc//shadow`` and ``/etc/./shadow`` are caught. Entries without a
# leading ``/`` match anywhere in the normalized path (e.g. ``.aws/credentials``
# catches both ``/home/alice/.aws/credentials`` and ``/root/.aws/credentials``).
#
# There is NO ``*.pub`` exemption: B1/RC1 dropped it, so ``.ssh/id_rsa.pub``
# still matches the ``.ssh/id_rsa`` entry below and is blocked — see
# ``_is_sensitive_path`` for why the exemption was removed rather than
# hardened. Do not reintroduce it.
_SENSITIVE_PATHS = [
    # Unix system secrets
    "/etc/shadow",
    "/etc/gshadow",
    "/etc/passwd",
    "/etc/sudoers",
    "/etc/ssh/ssh_host_",  # private host keys
    # SSH key material (relative match — catches any home dir)
    ".ssh/authorized_keys",
    ".ssh/id_rsa",
    ".ssh/id_ed25519",
    ".ssh/id_ecdsa",
    ".ssh/id_dsa",
    ".ssh/identity",
    ".ssh/config",
    ".ssh/known_hosts",
    # Cloud provider credentials
    ".aws/credentials",
    ".aws/config",
    ".azure/accesstokens.json",
    ".config/gcloud/credentials.db",
    ".config/gcloud/access_tokens.db",
    # Kubernetes secrets
    ".kube/config",
    "/etc/kubernetes/admin.conf",
    "/etc/kubernetes/kubelet.conf",
    "/var/lib/kubelet/pki/",
    # Shell credential caches and developer secrets
    ".netrc",
    ".pgpass",
    ".git-credentials",
    ".docker/config.json",
    # Kernel / process memory
    "/proc/self/mem",
    "/proc/self/environ",
    "/proc/kcore",
    "/proc/kallsyms",
    # Database data files
    "/var/lib/mysql/",
    "/var/lib/postgresql/",
    "/var/lib/mongodb/",
    # Windows (OpenSSH Windows server)
    "\\windows\\system32\\config\\sam",
    "\\windows\\system32\\config\\security",
    "\\users\\administrator\\.ssh\\",
]


def _normalize_path(path: str) -> str:
    """Normalize a path for substring-based sensitive-path matching.

    Uses ``posixpath.normpath`` which collapses ``//`` → ``/`` and removes
    ``./`` components, so ``/etc//shadow`` and ``/etc/./shadow`` both
    normalize to ``/etc/shadow``. Lowercases the result so matching is
    case-insensitive (defends against ``/ETC/SHADOW`` on case-insensitive
    filesystems and caseless-hostname shells).

    ``normpath`` also collapses ``..`` components LEXICALLY, which is not
    a traversal defence on its own (a lexical collapse can rewrite a path
    across a symlinked component). Traversal is rejected earlier, by
    ``_validate_remote_path``, before this function is ever reached — that
    ordering is load-bearing. Does NOT follow symlinks (that would require
    filesystem access).

    Args:
        path: Raw path as supplied by the caller.

    Returns:
        Lowercased, normalized path suitable for substring matching.
    """
    import posixpath

    return posixpath.normpath(path).lower()


# Regex guard for ``/proc/<pid>/{environ,mem,cmdline,maps,stack}`` which
# can reveal secrets from any running process. Covers ``/proc/self/...``
# AND arbitrary numeric PIDs. Kept separate from ``_SENSITIVE_PATHS`` because
# substring matching can't express "digits here".
_PROC_SENSITIVE_RE = re.compile(
    r"/proc/(self|\d+)/(environ|mem|cmdline|maps|stack|status)",
    re.IGNORECASE,
)


def _is_sensitive_path(path: str) -> bool:
    """Return True if ``path`` resolves to a sensitive location.

    Normalizes before matching so obfuscations like ``/etc//shadow`` and
    ``/etc/./shadow`` are caught.

    B1 (RC1): the previous ``*.pub`` exemption was a pure string-suffix
    check on the caller-supplied name, unrelated to what the path actually
    identifies — nothing stops a caller naming a symlink or a sensitive
    file ``foo.pub``. Dropped rather than hardened, matching the rest of
    B1's fix: this function is now reached only by remote-path validation
    (a tripwire, not a confinement boundary), and local paths no longer go
    through a denylist at all — see ``open_beneath`` in ``paths.py``.
    """
    normalized = _normalize_path(path)
    if _PROC_SENSITIVE_RE.search(normalized):
        return True
    for sensitive in _SENSITIVE_PATHS:
        if sensitive.lower() in normalized:
            return True
    return False


def _is_dangerous_command(command: str) -> bool:
    """Check if command matches any dangerous patterns.

    Replaces null bytes and ASCII control characters with a space before
    matching so that null-byte / control-character injection cannot bypass
    the regex patterns (see the inline comment below for why replacement
    rather than deletion). Unicode homoglyphs are NOT normalized — they
    remain a known bypass, per the tripwire caveat above
    ``_DANGEROUS_PATTERNS``.

    Args:
        command: Command string to check

    Returns:
        True if command matches a dangerous pattern
    """
    # Replace null bytes and ASCII control characters (0x00–0x1F, 0x7F) with a
    # space before matching.  Deletion would collapse adjacent tokens (e.g.
    # "rm\x00-rf" → "rm-rf") and miss the pattern; replacement preserves
    # token boundaries while removing the bypass character.
    sanitized = re.sub(r"[\x00-\x1f\x7f]", " ", command)
    for pattern in _DANGEROUS_PATTERNS:
        if pattern.search(sanitized):
            return True
    return False


def _validate_remote_path(path: str) -> None:
    """Validate remote path for SFTP operations.

    Normalizes the path before checking so obfuscations like ``/etc//shadow``
    and ``/etc/./shadow`` are caught.

    Args:
        path: Remote path to validate

    Raises:
        ValueError: If path contains parent traversal or sensitive paths
    """
    # Block parent directory traversal
    if ".." in path:
        raise ValueError(f"Path traversal detected: {path!r}")

    if _is_sensitive_path(path):
        raise ValueError(f"Access to sensitive path blocked: {path!r}")


# NOTE (B1 / RC1): there is deliberately no ``_validate_local_path`` here
# any more. It used to check the caller-supplied local path *string*
# against ``_SENSITIVE_PATHS`` and then hand that string to asyncssh's
# ``sftp.get``/``sftp.put``, which resolved it independently — a second,
# unguarded resolution that let (a) anything not enumerated in the
# denylist through, (b) asyncssh's directory-destination rewrite bypass
# validation entirely, and (c) a downloaded symlink be recreated locally
# and then followed by asyncssh's plain ``open()`` on a later write. Three
# successive "harden the validator" designs were each shown insufficient
# during review. Local paths are now resolved beneath a pinned
# ``transfer_root`` file descriptor, refusing a symlink at every
# component, via ``ssh_mcp.paths.open_beneath`` — see ``_upload_impl`` and
# ``_download_impl`` below. That makes the vulnerable asyncssh subsystem
# unreachable rather than defended against.


# Bounded read chunk for the S10 output-draining loop below. This governs
# process stdout/stderr draining via ``SSHReader.read()`` only — it is
# unrelated to the SFTP block sizes, which the transfer paths take from
# ``sftp.limits`` separately. It only caps how much a single ``read()``
# call may request, so a single call can never over-allocate far past the
# configured budget.
_STREAM_READ_CHUNK_BYTES: int = 65536


async def _drain_stream_bounded(
    reader: asyncssh.SSHReader[bytes], budget: int
) -> tuple[bytes, bool]:
    """Read ``reader`` up to ``budget`` raw bytes, then stop.

    S10: replaces ``conn.run()``'s behaviour of buffering the ENTIRE
    remote output before ``max_output_bytes`` truncates it, which bounded
    only the *response* handed back to the caller, never the allocation —
    a mistyped ``cat`` of a large file could OOM the host regardless of
    the setting. Each ``read()`` call is capped to at most
    ``budget - already_read + 1`` bytes, so the instant the budget is
    exceeded is detected without ever reading a full chunk past it —
    allocation stays bounded to ``budget`` plus at most one byte, not
    ``budget`` plus a whole chunk.

    Counts RAW bytes, not decoded characters — the previous check used
    ``len(str)`` on an already-fully-buffered, already-decoded string,
    which measured a 4x overrun on multibyte/emoji output (each character
    can be up to 4 UTF-8 bytes). Decoding happens only in the caller,
    after the byte-accurate cut point below is known.

    Returns:
        ``(data, truncated)``. ``data`` is at most ``budget`` bytes.
        ``truncated`` is ``True`` iff the stream produced more than
        ``budget`` bytes — the overflow bytes were read and then dropped by
        the slice below; whether anything further remains unread on the
        stream is not implied.
    """
    chunks: list[bytes] = []
    total = 0
    while True:
        remaining = budget - total
        read_size = min(_STREAM_READ_CHUNK_BYTES, remaining + 1)
        data = await reader.read(read_size)
        if not data:
            return b"".join(chunks), False
        chunks.append(data)
        total += len(data)
        if total > budget:
            return b"".join(chunks)[:budget], True


def _unlink_beneath(
    root_fd: int, relpath: str, *, expected_ino: tuple[int, int] | None = None
) -> None:
    """Remove ``relpath`` beneath ``root_fd``, as confined as its creation.

    Defect 2 (panel iteration 2, cursor/codex): a failed download's
    partial local file must be removed no less confined than
    ``open_beneath`` created it — a bare ``os.unlink(local_path)`` would
    re-resolve the path *string* from scratch through ordinary
    (symlink-following) path resolution, exactly the confinement
    ``open_beneath`` exists to avoid. This walks the same
    O_NOFOLLOW|O_DIRECTORY per-component path as ``paths.open_beneath``
    to reach the immediate parent directory, then removes the leaf via
    ``os.unlink(leaf, dir_fd=parent)`` — a single-component name, which
    cannot be redirected through a symlink swapped in after the file was
    created.

    Defect D (panel iteration 3): the walk above proves the *path* is
    confined (no symlink component can redirect it outside
    ``root_fd``), but on its own it does NOT prove *identity* — nothing
    stopped a concurrent process from renaming an unrelated file onto
    this exact leaf name after this call's own file was created (or
    already removed) but before this cleanup ran, in which case a bare
    ``unlink(leaf, dir_fd=parent)`` would remove that replacement
    instead. When the caller passes ``expected_ino`` (the
    ``(st_dev, st_ino)`` pair captured from the fd it created, via
    ``os.fstat``, before that fd was ever closed), this function
    ``os.stat``s the leaf with ``dir_fd=parent, follow_symlinks=False``
    immediately before unlinking and refuses to remove anything whose
    identity doesn't match — turning "unlinks whatever currently has
    this name" into "unlinks the file this call created, or nothing".
    This narrows, but per POSIX cannot fully close, the TOCTOU: the
    stat and the unlink are still two syscalls, so a rename landing in
    that exact gap could in principle still slip through — there is no
    "unlink iff inode matches" atomic primitive in POSIX. Callers that
    care should treat ``expected_ino`` as mandatory; it is optional here
    only so a caller without a captured identity can still get the
    path-confinement guarantee on its own.

    Cannot import the walk from ``paths.open_beneath`` directly: that
    function only returns the final leaf fd and closes every
    intermediate descriptor before returning (by design — its only
    caller needs the leaf, not the parent), so it has nothing to hand
    back here. Duplicating the short walk keeps that module's public
    surface unchanged for this one caller rather than widening it.

    Raises:
        PathConfinementError: on a malformed ``relpath`` (from
            ``validate_relative``), or — when ``expected_ino`` is given —
            on an identity mismatch (something else now has this name).
            NOTE this is narrower than ``open_beneath``: a symlink
            component here surfaces as a plain ``OSError`` (ELOOP or,
            on some platforms, ENOTDIR) — unlike ``open_beneath``, this
            function does not translate that into ``PathConfinementError``,
            since its only caller already treats every ``OSError`` from
            this function as best-effort-cleanup-failed regardless of
            subtype (see the caller's ``contextlib.suppress``).
        OSError: for ordinary filesystem errors, including a symlink
            component (see above) or the file/an intermediate directory
            already being gone.
    """
    *directories, leaf = validate_relative(relpath)
    opened: list[int] = []
    parent = root_fd
    for component in directories:
        try:
            fd = os.open(
                component,
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                dir_fd=parent,
            )
        except OSError:
            for opened_fd in opened:
                os.close(opened_fd)
            raise
        opened.append(fd)
        parent = fd
    try:
        if expected_ino is not None:
            st = os.stat(leaf, dir_fd=parent, follow_symlinks=False)
            if (st.st_dev, st.st_ino) != expected_ino:
                raise PathConfinementError(
                    f"refusing to unlink {relpath!r}: current (dev, ino) "
                    f"{(st.st_dev, st.st_ino)} does not match the file this "
                    "call created — a different file now has this name"
                )
        os.unlink(leaf, dir_fd=parent)
    finally:
        for opened_fd in opened:
            os.close(opened_fd)


_T = TypeVar("_T")


async def _await_shielded_until_done(task: asyncio.Future[_T]) -> _T:
    """Await ``task`` to actual completion, absorbing an UNLIMITED number
    of cancellations aimed at the calling coroutine, then return the
    task's result (or re-raise whatever exception — including its own
    ``CancelledError`` — the task itself produced).

    Defect 2 (panel iteration 4, cursor, verified by executing code with
    two cancels in a row): ``asyncio.shield`` only absorbs the FIRST
    cancellation delivered while awaiting it. Both cleanup call sites
    that use this helper used to follow the shielded await with a BARE
    ``await task`` inside their ``except CancelledError:`` handler —
    reasoning "the task is already running, shield already protected it
    once, a plain await just retrieves the result". That reasoning holds
    for exactly one cancellation. A SECOND cancel landing on that bare
    await raises ``CancelledError`` there too, and — critically —
    ``contextlib.suppress(Exception)`` does NOT catch it, since
    ``CancelledError`` derives from ``BaseException``, not ``Exception``.
    The second cancel therefore skips the cleanup step gated on "wait
    for the task" entirely (``os.close`` for the leaked transfer-root
    fd, or the confirmation that ``wait_closed()`` actually finished for
    the process channel) and propagates past the ``raise`` at the end of
    the handler, silently reopening the exact resource leak each of
    those functions was written to close.

    The fix: re-``shield`` on every retry. Each cancellation only ever
    cancels the OUTER future ``shield`` hands back — the shielded INNER
    task keeps running underneath regardless of how many times that
    happens — so looping until the inner task reports itself ``done()``
    makes this robust to any number of repeated cancellations, not just
    one.
    """
    while True:
        try:
            return await asyncio.shield(task)
        except asyncio.CancelledError:
            if task.done():
                # The task itself is what produced this CancelledError
                # (e.g. it was cancelled directly, not just our await of
                # it) — nothing left to wait for; propagate as-is.
                raise
            # Our own (possibly repeated) cancellation; the shielded
            # task is still running underneath. Retry the shield.
            continue


def _safe_terminate_process(process: asyncssh.SSHClientProcess[bytes]) -> None:
    """Best-effort ``process.terminate()`` that never raises past its
    caller.

    Defect B (panel iteration 3, verified by executing code): every
    ``terminate()`` call in ``_execute_impl`` used to be a bare
    statement ahead of further cleanup (pending-task cancellation, the
    gather, ``wait_closed()``). The underlying channel can already be in
    a state where ``terminate()`` itself raises, and when it did, every
    cleanup step after it was skipped — permanently orphaning the
    remote channel instead of just failing to send one more signal to a
    process that may already be gone. Logged at debug, not raised: a
    failed best-effort terminate during cleanup must never mask
    whatever original exception is already propagating.
    """
    try:
        process.terminate()
    except Exception:
        logger.debug("process.terminate() raised during cleanup", exc_info=True)


async def _await_process_closed(
    process: asyncssh.SSHClientProcess[bytes], *, terminated: bool
) -> None:
    """Await ``process.wait_closed()``, defensively terminating first if
    cancellation strikes before we know whether the process actually
    finished.

    Defect B (panel iteration 3): the FINAL ``await
    process.wait_closed()`` on the normal (non-truncated) completion
    path used to sit outside any exception handler. A cancellation
    landing specifically during that await — e.g. the surrounding
    ``asyncio.timeout`` firing at that exact instant — propagated
    immediately with no cleanup at all: the process had never been
    explicitly terminated on that path (reaching real EOF on both
    streams does not guarantee the remote process has actually exited),
    and its channel was never confirmed closed either.

    ``asyncio.shield`` means OUR cancellation cannot stop the close
    itself from completing; on cancellation we additionally terminate
    (if not already) before still waiting for the shielded close to
    finish — cleanup happens before the cancellation is allowed to
    propagate, never instead of it. A non-cancellation exception raised
    by ``wait_closed()`` itself is intentionally NOT swallowed here: it
    propagates exactly as it did before this fix, because
    ``process.exit_status`` is read immediately after this call on the
    success path, and silently treating a failed close as a clean one
    would fabricate a bogus exit code instead of surfacing the real
    failure.

    Defect 2 (panel iteration 4, cursor): the wait-for-completion step
    below used a BARE ``await close_task`` — good for exactly one
    cancellation (the one ``shield`` already absorbed), but a SECOND
    cancel landing on that bare await raised ``CancelledError`` there
    too, and ``contextlib.suppress(Exception)`` cannot catch it
    (``CancelledError`` derives from ``BaseException``). That second
    cancel skipped the wait entirely and propagated past ``raise``,
    reopening the orphaned-channel failure this function exists to
    close. ``_await_shielded_until_done`` re-shields on every retry so
    ANY number of repeated cancellations still lets ``wait_closed()``
    actually finish before we let the cancellation through.
    """
    close_task = asyncio.ensure_future(process.wait_closed())
    try:
        await asyncio.shield(close_task)
    except asyncio.CancelledError:
        if not terminated:
            _safe_terminate_process(process)
        # close_task keeps running regardless of our own cancellation
        # (that's what shield guarantees); wait for it to actually
        # finish — the entire point of this function — before letting
        # the cancellation continue propagating. Survives repeated
        # cancellation; see _await_shielded_until_done and Defect 2
        # above.
        with contextlib.suppress(Exception):
            await _await_shielded_until_done(close_task)
        raise


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
        # Per-connection stable id, generated at first connect and reused
        # until eviction. Bound via structlog contextvars for every op so
        # operators can grep all log lines from a single SSH session.
        self._connection_ids: dict[str, str] = {}

        # S1: bound to the PROCESS, not the call. A Semaphore built inside
        # execute_on_group() only bounds that one invocation — 8 concurrent
        # execute_on_group() calls would allow 8 x max_parallel_hosts
        # connections in flight, well past what the fd/HTTP-concurrency
        # limits were sized for. Hoisting it here means the bound is
        # process-wide, at the cost of independent group calls now
        # serialising against each other for their share of the pool — an
        # intentional behaviour change, not an oversight.
        self._group_semaphore = asyncio.Semaphore(settings.max_parallel_hosts)

        # B1: the transfer-root directory fd is pinned lazily, on first
        # SFTP transfer, NOT here. A misconfigured transfer_root (wrong
        # owner, group-writable, unwritable parent) must fail SFTP
        # transfers closed without preventing the server from starting or
        # breaking execute(), which never touches the transfer root at
        # all.
        #
        # Defect 5 (panel iteration 2): a bare "lock the first open, then
        # cache" scheme (the original B1 design) has two lifetime races
        # against close_all(): (a) close_all() can observe
        # `_transfer_root_fd is None` while `ensure_root()` is in flight
        # on another transfer, decide there is nothing to close, and then
        # that transfer's fd lands AFTER shutdown with nothing left to
        # ever close it; (b) close_all() can close the cached fd out from
        # under a transfer that already read it into a local variable and
        # is about to pass it to `open_beneath` — a use-after-close, with
        # descriptor-reuse implications since the OS is free to hand that
        # fd number to an unrelated resource the instant it closes.
        # `_transfer_root_refcount`, held for a transfer's ENTIRE
        # duration via the `_transfer_root()` context manager below (not
        # just the moment of retrieval), lets close_all() wait for every
        # in-flight transfer to finish before it closes anything, and
        # `_transfer_root_closing` makes a transfer that starts during or
        # after shutdown fail fast instead of racing ensure_root() against
        # os.close(). Both are guarded by the same lock/condition so
        # "check refcount" and "close" can never interleave.
        self._transfer_root_fd: int | None = None
        self._transfer_root_lock: asyncio.Lock = asyncio.Lock()
        self._transfer_root_cond: asyncio.Condition = asyncio.Condition(
            self._transfer_root_lock
        )
        self._transfer_root_refcount: int = 0
        self._transfer_root_closing: bool = False

        # Background eviction task
        self._eviction_task: asyncio.Task | None = None
        self._running = False

        # Audit logger for command tracking
        self._audit = logging.getLogger("ssh_mcp.audit")

        # Eviction loop starts on first connection (deferred if no event loop)

    @contextlib.asynccontextmanager
    async def _transfer_root(self) -> AsyncIterator[int]:
        """Yield the pinned transfer-root fd, safe against concurrent shutdown.

        See the ``__init__`` comment (Defect 5) for the races this closes.
        Callers must hold this for as long as ``root_fd`` — or anything
        opened relative to it, including cleanup performed on a failure
        path — might still be used; ``_upload_impl``/``_download_impl``
        wrap their entire transfer body in it for exactly that reason.

        Raises:
            RuntimeError: if ``close_all()`` has already started shutting
                down — refuses to start a new transfer rather than race
                ``ensure_root()`` against the close it knows is coming.
        """
        async with self._transfer_root_cond:
            if self._transfer_root_closing:
                raise RuntimeError(
                    "SSH manager is shutting down; refusing to start a new "
                    "SFTP transfer"
                )
            if self._transfer_root_fd is None:
                # ensure_root does blocking filesystem syscalls
                # (makedirs, chmod, open, fstat), so it runs off the event
                # loop thread; holding the condition's lock across the
                # await still serialises concurrent first-transfers
                # (asyncio.Condition/Lock are single-task-owned, not
                # thread primitives, so this is safe).
                #
                # Defect C (panel iteration 3, verified by executing
                # code): a plain ``await asyncio.to_thread(ensure_root,
                # ...)`` here leaks the fd on cancellation. The worker
                # THREAD cannot be interrupted once it starts — it runs
                # ensure_root() to completion regardless of what happens
                # to this coroutine — so if this task is cancelled while
                # the thread is mid-flight, the bare await raises
                # CancelledError before ``self._transfer_root_fd = ...``
                # ever executes, and the fd the thread went on to open is
                # never stored anywhere and never closed. ``asyncio.shield``
                # keeps the underlying task alive across our own
                # cancellation; on cancellation we still await it to
                # retrieve whatever it produced and close a
                # successfully-created fd we are never going to use,
                # before re-raising.
                #
                # Defect 2 (panel iteration 4, cursor, verified by
                # executing code with two cancels in a row): that
                # retrieval used to be a BARE ``await ensure_task`` here,
                # which survives exactly one cancellation (the one
                # ``shield`` above already absorbed). A SECOND cancel
                # landing on this bare await raised ``CancelledError``
                # again, and ``contextlib.suppress(Exception)`` does NOT
                # catch it — ``CancelledError`` derives from
                # ``BaseException`` — so it skipped ``os.close()``
                # entirely and propagated past ``raise``, leaking the
                # worker-thread's fd. ``_await_shielded_until_done``
                # re-shields on every retry, so this survives any number
                # of repeated cancellations.
                ensure_task = asyncio.ensure_future(
                    asyncio.to_thread(ensure_root, self.settings.transfer_root)
                )
                try:
                    self._transfer_root_fd = await asyncio.shield(ensure_task)
                except asyncio.CancelledError:
                    with contextlib.suppress(Exception):
                        leaked_fd = await _await_shielded_until_done(ensure_task)
                        os.close(leaked_fd)
                    raise
            self._transfer_root_refcount += 1
        try:
            yield self._transfer_root_fd
        finally:
            async with self._transfer_root_cond:
                self._transfer_root_refcount -= 1
                if self._transfer_root_refcount == 0:
                    self._transfer_root_cond.notify_all()

    async def execute(
        self,
        server_name: str,
        command: str,
        timeout: int = 30,
        working_dir: str | None = None,
        force: bool = False,
        dry_run: bool = False,
    ) -> ExecResult:
        """Execute command on a remote server.

        Thin tracing wrapper around ``_execute_impl``. When OTel is
        available it opens a ``ssh.execute`` span with ``ssh.host``,
        ``ssh.command_length`` (NOT the raw command — avoids leaking
        secrets into traces), ``ssh.force``, and ``ssh.dry_run`` attributes
        at entry, and populates ``ssh.exit_code`` / ``ssh.duration_ms`` /
        ``ssh.error`` from the final ExecResult before returning.

        Args:
            server_name: Server name from registry
            command: Command to execute
            timeout: Command timeout in seconds. A per-server
                ``server.timeout`` in the registry takes precedence and
                silently overrides this argument whenever it is set.
            working_dir: Working directory for command execution
            force: Bypass dangerous command detection (use with caution)
            dry_run: If True, skip connection and execution — return a
                preview describing what WOULD run. Dangerous-command detection
                still applies so rejection can be previewed. The preview text
                is returned in ``stdout`` with ``exit_code=0`` and
                ``duration_ms=0``, so a caller must NOT read ``exit_code == 0``
                as "the command ran".

        Returns:
            ExecResult with command output and metadata. This method never
            raises: every failure path (unknown server, SSH error, timeout,
            unexpected exception) is reported as an ExecResult with
            ``exit_code=None`` and ``error`` set. ``execute_on_group``
            depends on that contract.
        """
        if _ssh_tracer is None:
            return await self._execute_impl(
                server_name, command, timeout, working_dir, force, dry_run
            )
        with _ssh_tracer.start_as_current_span("ssh.execute") as span:
            span.set_attribute("ssh.host", server_name)
            span.set_attribute("ssh.command_length", len(command))
            span.set_attribute("ssh.force", force)
            span.set_attribute("ssh.dry_run", dry_run)
            result = await self._execute_impl(
                server_name, command, timeout, working_dir, force, dry_run
            )
            if result.exit_code is not None:
                span.set_attribute("ssh.exit_code", result.exit_code)
            if result.duration_ms:
                span.set_attribute("ssh.duration_ms", result.duration_ms)
            if result.error:
                # Truncate error messages into spans — some operators ingest
                # traces into cost-sensitive backends.
                span.set_attribute("ssh.error", _redact_secrets(result.error[:200]))
                span.set_status(_otel_trace.Status(_otel_trace.StatusCode.ERROR))
            return result

    async def _execute_impl(
        self,
        server_name: str,
        command: str,
        timeout: int = 30,
        working_dir: str | None = None,
        force: bool = False,
        dry_run: bool = False,
    ) -> ExecResult:
        """Internal implementation of execute without tracing.

        See ``execute`` for public contract. Separated so the span wrapper
        stays thin and the complex exit-path logic below does not need
        per-branch tracing glue.
        """
        try:
            server = self.registry.get_server(server_name)

            # Check for dangerous commands unless force is enabled. Dangerous-
            # command detection ALSO runs in dry_run mode so users can preview
            # rejection without connecting.
            if not force and _is_dangerous_command(command):
                logger.warning(
                    "Blocked potentially destructive command on %s: %s",
                    _safe_log_value(server_name),
                    _safe_log_value(_redact_secrets(command)),
                )
                return ExecResult(
                    server=server_name,
                    command=command,
                    stdout="",
                    stderr="",
                    exit_code=None,
                    error="Blocked: potentially destructive command detected. Review and use with caution.",
                )

            # Dry-run mode: don't connect, don't execute — just describe
            # what WOULD happen. Useful for LLM-driven plans that want to
            # preview destructive cascades before committing.
            if dry_run:
                effective_wd = working_dir or server.default_dir or "<login dir>"
                effective_to = server.timeout or timeout
                # Red Team R3 finding H1: when force=True bypasses a
                # dangerous-command match, the dry_run preview must surface
                # a visible warning so LLM planners can't overlook it.
                dangerous_banner = ""
                if force and _is_dangerous_command(command):
                    dangerous_banner = (
                        "\n"
                        "  ⚠️  DANGEROUS: matched the destructive-command tripwire.\n"
                        "      force=True would bypass the block on real execution.\n"
                        "      Review carefully before removing dry_run=True."
                    )
                preview = (
                    f"[DRY RUN] Would execute on {server_name}\n"
                    f"  command:     {_redact_secrets(command)}\n"
                    f"  working_dir: {effective_wd}\n"
                    f"  timeout:     {effective_to}s\n"
                    f"  force:       {force}"
                    f"{dangerous_banner}"
                )
                return ExecResult(
                    server=server_name,
                    command=command,
                    stdout=preview,
                    stderr="",
                    exit_code=0,
                    duration_ms=0,
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

            # S10: conn.run() buffers the ENTIRE remote output before
            # max_output_bytes truncates it — the setting bounded the
            # *response*, never the *allocation*, so a mistyped `cat` of a
            # large file could exhaust host memory regardless of the
            # configured limit. create_process() + our own bounded drain
            # loop (below) caps the allocation itself. encoding=None keeps
            # everything in bytes so truncation is measured in raw bytes,
            # not decoded characters — the old character-based check
            # measured a 4x overrun on multibyte/emoji output.
            start_time = time.monotonic()
            budget = self.settings.max_output_bytes
            # Per-stream budget: stdout and stderr are each capped at
            # max_output_bytes INDEPENDENTLY (not shared), so the combined
            # worst case is 2x the configured setting. This mirrors the
            # pre-S10 conn.run() semantics, which truncated each stream
            # independently, and is an accepted trade-off (panel iteration
            # 2 — opencode flagged it, cursor confirmed keeping it), not
            # an oversight.
            process = await conn.create_process(effective_command, encoding=None)
            try:
                async with asyncio.timeout(effective_timeout):
                    stdout_task = asyncio.create_task(
                        _drain_stream_bounded(process.stdout, budget)
                    )
                    stderr_task = asyncio.create_task(
                        _drain_stream_bounded(process.stderr, budget)
                    )
                    pending: set[asyncio.Task[tuple[bytes, bool]]] = {
                        stdout_task,
                        stderr_task,
                    }
                    stdout_bytes = stderr_bytes = b""
                    stdout_truncated = stderr_truncated = False
                    terminated = False
                    try:
                        # Defect 4(b) (panel iteration 2, codex): drive the
                        # two drains with a manual FIRST_COMPLETED wait
                        # instead of a TaskGroup, which only surfaces
                        # results once BOTH tasks finish. Terminating the
                        # instant EITHER stream reports its budget
                        # exhausted means a process still blocked writing
                        # the OTHER stream gets killed immediately — under
                        # the TaskGroup shape it kept running (and stayed
                        # unterminated) until the outer command timeout
                        # fired, so the caller got a timeout result
                        # instead of the in-band truncated one the
                        # contract promises.
                        while pending:
                            done, pending = await asyncio.wait(
                                pending, return_when=asyncio.FIRST_COMPLETED
                            )
                            for task in done:
                                data, truncated = await task
                                if task is stdout_task:
                                    stdout_bytes, stdout_truncated = (
                                        data,
                                        truncated,
                                    )
                                else:
                                    stderr_bytes, stderr_truncated = (
                                        data,
                                        truncated,
                                    )
                                if truncated and not terminated:
                                    # At least one stream hit the byte
                                    # budget before EOF, meaning the
                                    # remote process may still be
                                    # producing output we've stopped
                                    # reading. Terminate it rather than
                                    # leave an orphaned channel running in
                                    # the background — bounding the reads
                                    # alone does not stop the remote
                                    # command (S10 contract point 4).
                                    # Defect B: guarded — see
                                    # _safe_terminate_process — so a
                                    # raising terminate() here still lets
                                    # the loop (and, on exception, the
                                    # handler below) continue cleanup.
                                    _safe_terminate_process(process)
                                    terminated = True
                    except BaseException:
                        # Defect 4(a) (panel iteration 2, cursor): a
                        # raised read() — or a cancellation racing the
                        # timeout below — must not skip cleanup. The old
                        # TaskGroup shape let such an exception surface as
                        # an ExceptionGroup straight past the
                        # terminate()/wait_closed() calls, orphaning the
                        # remote channel. Every non-normal exit
                        # terminates, cancels+drains whatever drain
                        # task(s) are still pending, and awaits channel
                        # close before propagating — including a
                        # timeout-triggered cancellation, which reaches
                        # here too (asyncio.timeout() only converts it to
                        # TimeoutError once this block re-raises it).
                        #
                        # Defect B (panel iteration 3): both
                        # _safe_terminate_process and
                        # _await_process_closed are individually
                        # exception-/cancellation-safe, so a raising
                        # terminate() or a cancellation landing mid-close
                        # can no longer skip the step that follows it.
                        if not terminated:
                            _safe_terminate_process(process)
                            terminated = True
                        for task in pending:
                            task.cancel()
                        if pending:
                            await asyncio.gather(*pending, return_exceptions=True)
                        await _await_process_closed(process, terminated=terminated)
                        raise

                    # Wait for the channel to finish closing so exit_status
                    # is populated, mirroring what conn.run()'s
                    # communicate()/wait_closed() did. Defect B: routed
                    # through _await_process_closed so a cancellation
                    # landing exactly during this await still terminates
                    # (if not already) and confirms the close before
                    # propagating, instead of abandoning the process.
                    await _await_process_closed(process, terminated=terminated)
            except TimeoutError as e:
                # Preserve existing timeout behaviour and audit record
                # unchanged (S10 contract point 5) — same error message
                # shape and same audit fields as before. Cleanup
                # (terminate/cancel-pending/wait_closed) already happened
                # in the `except BaseException` block above, which runs
                # BEFORE asyncio.timeout() converts the cancellation it
                # raised into this TimeoutError — so there is nothing left
                # to do here but build the result.
                duration_ms = int((time.monotonic() - start_time) * 1000)
                logger.error(
                    "Command timeout on %s: %s",
                    _safe_log_value(server_name),
                    _safe_log_value(_redact_secrets(command)),
                )
                exec_result = ExecResult(
                    server=server_name,
                    command=command,
                    stdout="",
                    stderr="",
                    exit_code=None,
                    error=f"Command timeout after {effective_timeout}s: {e}",
                    duration_ms=duration_ms,
                )

                # S8: apply _safe_log_value to the redacted command, not
                # just the redacted result, so an embedded CRLF in the
                # command cannot forge a second audit record — redaction
                # removes secrets, it does not neutralise structure.
                self._audit.info(
                    "server=%s command=%s exit_code=%s duration_ms=%s error=timeout",
                    _safe_log_value(server_name),
                    _safe_log_value(_redact_secrets(command)),
                    exec_result.exit_code,
                    exec_result.duration_ms,
                )

                return exec_result

            duration_ms = int((time.monotonic() - start_time) * 1000)

            # Decode only AFTER the byte-accurate truncation cut point is
            # known. errors="replace" because our own truncation can cut a
            # multibyte UTF-8 sequence in half at the boundary — that must
            # not raise, it must degrade gracefully.
            stdout = stdout_bytes.decode("utf-8", errors="replace")
            stderr = stderr_bytes.decode("utf-8", errors="replace")

            if stdout_truncated:
                stdout += f"\n[... output truncated at {budget} bytes]"
            if stderr_truncated:
                stderr += f"\n[... output truncated at {budget} bytes]"

            exec_result = ExecResult(
                server=server_name,
                command=command,
                stdout=stdout,
                stderr=stderr,
                exit_code=process.exit_status,
                duration_ms=duration_ms,
            )

            # Audit log successful execution. Secrets embedded in the
            # command (``-pPassword``, ``PGPASSWORD=xxx``, etc.) are
            # replaced with a placeholder, and the redacted value is then
            # escaped via _safe_log_value (S8) so an embedded CRLF cannot
            # forge a second, byte-perfect audit record — redaction alone
            # does not make a value log-safe.
            self._audit.info(
                "server=%s command=%s exit_code=%s duration_ms=%s",
                _safe_log_value(server_name),
                _safe_log_value(_redact_secrets(command)),
                exec_result.exit_code,
                exec_result.duration_ms,
            )

            return exec_result

        except KeyError as e:
            logger.error("Server not found: %s", _safe_log_value(server_name))
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
            logger.error(
                "SSH error on %s: %s",
                _safe_log_value(server_name),
                _safe_log_value(str(e)),
            )
            return ExecResult(
                server=server_name,
                command=command,
                stdout="",
                stderr="",
                exit_code=None,
                error=f"SSH error: {e}",
            )

        except Exception as e:
            logger.error(
                "Unexpected error on %s: %s",
                _safe_log_value(server_name),
                _safe_log_value(str(e)),
            )
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
        dry_run: bool = False,
    ) -> list[ExecResult]:
        """Execute command on all servers in a group in parallel.

        Parallelism is bounded by a PROCESS-WIDE semaphore sized from
        ``settings.max_parallel_hosts``, not a per-call one, so independent
        ``execute_on_group`` calls serialise against each other for their
        share of the pool — an intentional behaviour change (S1).

        Args:
            group_name: Group name from registry
            command: Command to execute
            timeout: Command timeout in seconds
            working_dir: Working directory for command execution
            fail_fast: Cancel the remaining tasks as soon as one result
                comes back with ``error`` set OR with a non-zero
                ``exit_code`` (not only on an exception).
            force: Bypass dangerous command detection (use with caution)
            dry_run: If True, preview what WOULD run on each server without
                connecting. Dangerous-command detection still applies.

        Returns:
            List of ExecResult, one per server in the group. An unknown
            group name returns a single-element list whose ``server`` field
            holds the GROUP name rather than a server name.
        """
        try:
            servers = self.registry.servers_in_group(group_name)

            if not servers:
                logger.warning("Group %s has no servers", _safe_log_value(group_name))
                return []

            # S1: use the process-wide semaphore built once in __init__, not
            # a fresh one per call. A Semaphore constructed here bounds only
            # THIS invocation of execute_on_group — 8 concurrent calls would
            # allow 8 x max_parallel_hosts connections in flight regardless
            # of the configured limit. Behaviour change, stated plainly:
            # independent execute_on_group() calls now serialise against
            # each other for their share of the shared pool.
            semaphore = self._group_semaphore

            async def execute_with_semaphore(server: ServerConfig) -> ExecResult:
                async with semaphore:
                    return await self.execute(
                        server.name,
                        command,
                        timeout,
                        working_dir,
                        force,
                        dry_run,
                    )

            # Execute in parallel
            tasks = [execute_with_semaphore(server) for server in servers]

            if fail_fast:
                # Cancel remaining tasks on first failure
                actual_tasks = [asyncio.create_task(coro) for coro in tasks]
                # Map each task back to its server name so we can attribute
                # cancelled results after fail_fast triggers.
                task_to_server = {
                    task: server.name for task, server in zip(actual_tasks, servers)
                }
                results: list[ExecResult] = []
                for future in asyncio.as_completed(actual_tasks):
                    try:
                        result = await future
                    except Exception:
                        # B3 (new finding): execute() promises never to
                        # raise, but that promise is only as strong as
                        # every code path inside it. An unguarded `await
                        # future` here would let such an exception escape
                        # this loop and land in the broad `except
                        # Exception` at the bottom of this method, which
                        # discards EVERY partial result already collected
                        # in `results`. Treat it exactly like a failing
                        # result — trigger the same cancel-and-drain
                        # sequence — and let the harvest pass below
                        # attribute it to its actual server via
                        # task_to_server, since we don't have that
                        # attribution from inside this generic loop.
                        for task in actual_tasks:
                            if not task.done():
                                task.cancel()
                        remaining = [t for t in actual_tasks if not t.done()]
                        if remaining:
                            await asyncio.gather(*remaining, return_exceptions=True)
                        break
                    results.append(result)
                    if result.error or (
                        result.exit_code is not None and result.exit_code != 0
                    ):
                        for task in actual_tasks:
                            if not task.done():
                                task.cancel()
                        # Drain cancelled tasks to prevent leaks
                        remaining = [t for t in actual_tasks if not t.done()]
                        if remaining:
                            await asyncio.gather(*remaining, return_exceptions=True)
                        break

                # B3 (RC3): the loop above stops pulling from as_completed
                # the instant one failing/raising result is seen, but
                # multiple tasks can finish around the same time — those
                # results exist and are just sitting unread in
                # as_completed's internal queue. task.cancel() on an
                # ALREADY-DONE task is a no-op, so the old code silently
                # discarded those results and then labelled the host
                # "Cancelled" even though it ran to completion. Harvest
                # them here instead of assuming "no result" means "did not
                # run".
                completed_servers = {r.server for r in results}
                for task in actual_tasks:
                    server_name = task_to_server[task]
                    if server_name in completed_servers:
                        continue
                    if task.done() and not task.cancelled():
                        task_exc = task.exception()
                        if task_exc is None:
                            results.append(task.result())
                        else:
                            results.append(
                                ExecResult(
                                    server=server_name,
                                    command=command,
                                    stdout="",
                                    stderr="",
                                    exit_code=None,
                                    error=(
                                        "Exception during execution: "
                                        f"{_redact_secrets(str(task_exc))}"
                                    ),
                                )
                            )
                        completed_servers.add(server_name)
                        continue
                    # Genuinely never dispatched, or cancelled before
                    # completing. _execute_impl awaits conn.create_process()
                    # before this task becomes locally cancellable, so a
                    # task caught mid-flight may already have sent the
                    # command over the wire — cancelling the LOCAL task
                    # does not stop remote execution. The wording admits
                    # that ambiguity instead of asserting the host was
                    # skipped.
                    results.append(
                        ExecResult(
                            server=server_name,
                            command=command,
                            stdout="",
                            stderr="",
                            exit_code=None,
                            error=(
                                "Cancelled: fail_fast triggered by an earlier "
                                "failure. The command may already have been "
                                "dispatched to this host before local "
                                "cancellation took effect — its actual "
                                "outcome on the remote host is unknown."
                            ),
                        )
                    )
                return results
            else:
                # Wait for all tasks to complete
                gather_results = await asyncio.gather(*tasks, return_exceptions=True)

                # Convert exceptions to ExecResult
                normalized_results = []
                for i, gather_result in enumerate(gather_results):
                    if isinstance(gather_result, BaseException):
                        server_name = servers[i].name
                        normalized_results.append(
                            ExecResult(
                                server=server_name,
                                command=command,
                                stdout="",
                                stderr="",
                                exit_code=None,
                                error=f"Exception during execution: {_redact_secrets(str(gather_result))}",
                            )
                        )
                    else:
                        normalized_results.append(gather_result)

                return normalized_results

        except KeyError as e:
            logger.error("Group not found: %s", _safe_log_value(group_name))
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
            logger.error(
                "Unexpected error in group execution: %s", _safe_log_value(str(e))
            )
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

    async def upload(self, server_name: str, local_path: str, remote_path: str) -> str:
        """Upload file to remote server via SFTP.

        Emits audit logs (``start`` → ``complete`` | ``failed``) with
        ``server``, ``operation``, both paths and the ``connection_id`` bound
        into the structlog context so every log line from a single transfer
        is grep-correlatable; a monotonic ``duration_ms`` is not bound to the
        context but reported on each of those lines. A ``failed`` record is
        emitted only from the ``FileNotFoundError`` and SFTP/OS-error
        handlers — a ``ValueError`` from one of the validation guards
        (non-regular local file, oversize file, non-regular remote target,
        ``PathConfinementError``) leaves ``start`` with no terminal record.
        Also opens an OpenTelemetry ``ssh.upload`` span
        (Green Team H2 fix) with ``ssh.host`` and path-length attributes —
        lengths not contents so nothing sensitive leaks into trace backends.

        Args:
            server_name: Server name from registry
            local_path: Local file path
            remote_path: Remote destination path

        Returns:
            Confirmation message with file size
        """
        if _ssh_tracer is None:
            return await self._upload_impl(server_name, local_path, remote_path)
        with _ssh_tracer.start_as_current_span("ssh.upload") as span:
            span.set_attribute("ssh.host", server_name)
            span.set_attribute("ssh.local_path_length", len(local_path))
            span.set_attribute("ssh.remote_path_length", len(remote_path))
            try:
                return await self._upload_impl(server_name, local_path, remote_path)
            except Exception as e:
                span.set_attribute("ssh.error_type", type(e).__name__)
                span.set_status(_otel_trace.Status(_otel_trace.StatusCode.ERROR))
                raise

    async def _upload_impl(
        self, server_name: str, local_path: str, remote_path: str
    ) -> str:
        """Internal upload implementation without tracing.

        See ``upload`` for the public contract. Separated so the span
        wrapper stays thin.

        B1 (RC1): this no longer calls ``sftp.put()``. That call hard-wires
        asyncssh's module-global ``LocalFS`` and takes only a path *string*,
        which is precisely why the old validator's decision could be
        bypassed — asyncssh re-resolved the same string independently.
        Instead: the local file is opened ourselves under
        ``open_beneath()`` (refusing a symlink at every path component),
        and the remote file is opened via the public ``sftp.open()`` API,
        with our own chunked copy loop between them. asyncssh's
        directory-destination rewrite and symlink-recreation code paths
        are therefore never invoked — not defended against, unreachable.
        """
        # Validate paths BEFORE logging so audit logs do not contain
        # sensitive values when validation blocks the call. validate_relative
        # is a pure lexical check (no syscalls) so this rejects '..' and
        # absolute paths without touching the filesystem or the network.
        _validate_remote_path(remote_path)
        validate_relative(local_path)

        start_time = time.monotonic()
        ctx_tokens: dict[str, Any] = dict(
            structlog.contextvars.bind_contextvars(
                server=server_name,
                operation="upload",
                local_path=local_path,
                remote_path=remote_path,
            )
        )
        local_fd: int | None = None
        try:
            try:
                conn = await self._get_connection(server_name)
            except KeyError as e:
                # N1: get_server() raises a raw KeyError for an unknown
                # server name, outside the documented ValueError/RuntimeError
                # contract for SFTP operations (models.py ExecResult
                # docstring). Convert it here rather than let it escape.
                raise ValueError(f"Server not found: {e}") from e

            # Now that we have (or reused) a connection, bind its id so the
            # start/complete/failed lines all share the connection_id.
            ctx_tokens.update(
                structlog.contextvars.bind_contextvars(
                    connection_id=self._connection_ids.get(server_name, "unknown"),
                )
            )
            self._audit.info("sftp.upload.start")

            async with self._transfer_root() as root_fd:
                # open_beneath does blocking syscalls (openat per
                # component) — off the event loop thread, same as the
                # read loop below.
                local_fd = await asyncio.to_thread(
                    open_beneath, root_fd, local_path, os.O_RDONLY
                )

                # fstat the descriptor we are ABOUT TO READ, not a path —
                # this is what closes the upload TOCTOU (01-approach.md
                # 1.7): the old code stat'd `local_path` as a string and
                # then had sftp.put() open the same string a second time,
                # so anything that could swap the path between the two
                # calls (or a symlink, since Path.stat() follows them)
                # defeated the size guard silently. Off the event loop
                # thread (Defect 6, panel iteration 2): every OTHER
                # filesystem call in this module already runs via
                # asyncio.to_thread — a bare os.fstat() here was the one
                # inconsistent blocking call.
                st = await asyncio.to_thread(os.fstat, local_fd)
                if not stat.S_ISREG(st.st_mode):
                    raise ValueError(
                        f"local path is not a regular file: {local_path!r}"
                    )
                local_size = st.st_size
                if local_size > _MAX_SFTP_BYTES:
                    raise ValueError(
                        f"File too large for SFTP transfer: {local_size} bytes "
                        f"(max {_MAX_SFTP_BYTES}). Reduce file size or adjust _MAX_SFTP_BYTES."
                    )

                async with conn.start_sftp_client() as sftp:
                    # Defect 3 (panel iteration 2, all three reviewers):
                    # refuse to overwrite an EXISTING non-regular remote
                    # file — mirrors the download guard in
                    # _download_impl below. sftp.open() follows symlinks,
                    # so without this check a remote symlink planted at
                    # `remote_path` would let an attacker redirect our
                    # write to an arbitrary remote file (upload had NO
                    # preceding stat at all; download got the guard,
                    # upload did not — this closes that asymmetry). A
                    # MISSING remote path is fine — upload legitimately
                    # creates new files — so only an existing non-regular
                    # entry is refused. Accepted residual (documented,
                    # not "fixed"): this stat-then-open is a best-effort
                    # refusal, not an atomic guarantee — SFTP protocol v3
                    # has no atomic no-follow open. It does not reopen
                    # the MCP-host RCE this module's rewrite closed,
                    # because the local destination stays fd-confined
                    # regardless of what the remote side does.
                    try:
                        attrs = await sftp.stat(remote_path, follow_symlinks=False)
                    except asyncssh.SFTPNoSuchFile:
                        pass
                    else:
                        if attrs.type != FILEXFER_TYPE_REGULAR:
                            raise ValueError(
                                "refusing to overwrite a non-regular remote "
                                f"file (sftp type={attrs.type}): {remote_path!r}. "
                                "Only regular files may be uploaded to — "
                                "symlinks, devices, and FIFOs are refused on "
                                "a best-effort basis."
                            )

                    block = sftp.limits.max_write_len or 16384
                    sent = 0
                    async with sftp.open(remote_path, "wb") as remote_file:
                        with os.fdopen(local_fd, "rb", closefd=True) as local_file:
                            local_fd = None  # ownership transferred; don't double-close
                            while True:
                                chunk = await asyncio.to_thread(local_file.read, block)
                                if not chunk:
                                    break
                                await remote_file.write(chunk, sent)
                                sent += len(chunk)

                    duration_ms = int((time.monotonic() - start_time) * 1000)

                    self._audit.info(
                        "sftp.upload.complete bytes=%s duration_ms=%s",
                        sent,
                        duration_ms,
                    )

                    return (
                        f"Uploaded {local_path} to {server_name}:{remote_path} "
                        f"({sent} bytes)"
                    )

        except FileNotFoundError as e:
            duration_ms = int((time.monotonic() - start_time) * 1000)
            self._audit.warning(
                "sftp.upload.failed error=file_not_found duration_ms=%s",
                duration_ms,
            )
            error_msg = f"Local file not found: {_safe_log_value(str(e))}"
            logger.error("%s", error_msg)
            raise ValueError(error_msg) from e

        except (
            asyncssh.DisconnectError,
            asyncssh.PermissionDenied,
            asyncssh.SFTPError,
            OSError,
        ) as e:
            duration_ms = int((time.monotonic() - start_time) * 1000)
            self._audit.warning(
                "sftp.upload.failed error=%s duration_ms=%s",
                type(e).__name__,
                duration_ms,
            )
            error_msg = (
                f"Upload failed to {_safe_log_value(server_name)}: "
                f"{_safe_log_value(str(e))}"
            )
            logger.error("%s", error_msg)
            raise RuntimeError(error_msg) from e

        finally:
            if local_fd is not None:
                os.close(local_fd)
            structlog.contextvars.reset_contextvars(**ctx_tokens)

    async def download(
        self, server_name: str, remote_path: str, local_path: str
    ) -> str:
        """Download file from remote server via SFTP.

        Emits audit logs (``start`` → ``complete`` | ``failed``) with
        ``server``, ``operation``, both paths and the ``connection_id`` bound
        into the structlog context so every log line from a single transfer
        is grep-correlatable; a monotonic ``duration_ms`` is not bound to the
        context but reported on each of those lines. A ``failed`` record is
        emitted only from the SFTP/OS-error handler — a ``ValueError`` from
        one of the validation guards (non-regular remote file, local
        destination already exists, ``PathConfinementError``) leaves
        ``start`` with no terminal record. Also opens an OpenTelemetry
        ``ssh.download`` span (Green Team H2 fix).

        Args:
            server_name: Server name from registry
            remote_path: Remote file path
            local_path: Local destination path

        Returns:
            Confirmation message with file size
        """
        if _ssh_tracer is None:
            return await self._download_impl(server_name, remote_path, local_path)
        with _ssh_tracer.start_as_current_span("ssh.download") as span:
            span.set_attribute("ssh.host", server_name)
            span.set_attribute("ssh.remote_path_length", len(remote_path))
            span.set_attribute("ssh.local_path_length", len(local_path))
            try:
                return await self._download_impl(server_name, remote_path, local_path)
            except Exception as e:
                span.set_attribute("ssh.error_type", type(e).__name__)
                span.set_status(_otel_trace.Status(_otel_trace.StatusCode.ERROR))
                raise

    async def _download_impl(
        self, server_name: str, remote_path: str, local_path: str
    ) -> str:
        """Internal download implementation without tracing.

        B1 (RC1): this no longer calls ``sftp.get()`` — see ``_upload_impl``
        for the shared rationale. The remote file's type is checked with
        ``follow_symlinks=False`` before it is ever opened: ``sftp.get()``
        used to default to *not* following symlinks (recreating them
        locally instead), and swapping to ``sftp.open()`` (which DOES
        follow) without this check would have newly exposed remote
        symlink-following. The local destination is opened with
        ``O_CREAT | O_EXCL`` (no-clobber) — a behaviour change from
        ``sftp.get()``, which silently overwrote.
        """
        _validate_remote_path(remote_path)
        validate_relative(local_path)

        start_time = time.monotonic()
        ctx_tokens: dict[str, Any] = dict(
            structlog.contextvars.bind_contextvars(
                server=server_name,
                operation="download",
                remote_path=remote_path,
                local_path=local_path,
            )
        )
        local_fd: int | None = None
        # Defect 2 (panel iteration 2, cursor/codex): O_CREAT|O_EXCL below
        # creates the local file BEFORE the remote copy completes. These
        # two flags let the `finally` block distinguish "never created"
        # (nothing to clean up) from "created but the transfer never
        # finished" (must unlink, or every retry to the same name fails
        # no-clobber with EEXIST forever — permanently bricking the
        # destination; docs/fixes/01-approach.md:165-171 required this).
        local_file_created = False
        download_succeeded = False
        # Defect D (panel iteration 3): captured as soon as the local file
        # is created (below) so the cleanup unlink can prove IDENTITY, not
        # just path confinement — see _unlink_beneath's docstring.
        created_ino: tuple[int, int] | None = None
        try:
            try:
                conn = await self._get_connection(server_name)
            except KeyError as e:
                # N1: see _upload_impl — convert to the documented contract.
                raise ValueError(f"Server not found: {e}") from e

            ctx_tokens.update(
                structlog.contextvars.bind_contextvars(
                    connection_id=self._connection_ids.get(server_name, "unknown"),
                )
            )
            self._audit.info("sftp.download.start")

            async with conn.start_sftp_client() as sftp:
                # Refuse remote non-regular files BEFORE opening anything.
                # follow_symlinks=False means a remote symlink is reported
                # AS a symlink rather than silently resolved to its target.
                attrs = await sftp.stat(remote_path, follow_symlinks=False)
                if attrs.type != FILEXFER_TYPE_REGULAR:
                    raise ValueError(
                        "refusing to download a non-regular remote file "
                        f"(sftp type={attrs.type}): {remote_path!r}. Only "
                        "regular files may be downloaded — symlinks, "
                        "devices, and FIFOs are refused on a best-effort "
                        "basis (see paths.py module docstring for the "
                        "documented residual TOCTOU)."
                    )

                async with self._transfer_root() as root_fd:
                    try:
                        local_fd = await asyncio.to_thread(
                            open_beneath,
                            root_fd,
                            local_path,
                            os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                        )
                    except FileExistsError as e:
                        raise ValueError(
                            f"local destination already exists: {local_path!r} "
                            "under transfer_root. Downloads never overwrite an "
                            "existing file — remove or rename it first, or "
                            "choose a different destination name."
                        ) from e
                    local_file_created = True
                    # Capture identity while local_fd is still ours (before
                    # ownership transfers to `local_file` below and the fd
                    # is eventually closed) — this is what lets
                    # _unlink_beneath refuse to remove a file that a
                    # concurrent rename swapped onto this name later.
                    #
                    # Defect 3 (panel iteration 4, cursor): this used to be
                    # ``await asyncio.to_thread(os.fstat, local_fd)``. A
                    # cancellation landing in the gap between
                    # ``local_file_created = True`` (above) and that await
                    # returning left ``created_ino`` at its initial ``None``
                    # — and the cleanup ``finally`` block further down
                    # unconditionally unlinks whenever
                    # ``local_file_created`` is set, passing whatever
                    # ``created_ino`` holds as ``expected_ino``. ``None``
                    # there means "skip the identity check" (see
                    # ``_unlink_beneath``'s docstring), silently reopening
                    # exactly the replacement-file TOCTOU that check exists
                    # to close.
                    #
                    # Chosen fix: capture the identity so it CANNOT be
                    # lost, rather than defending the cleanup path against
                    # it being unknown (failing closed there was the other
                    # option, but this closes the gap outright). The
                    # ``to_thread`` hop was never warranted for
                    # ``os.fstat``: given an fd we already hold open,
                    # ``fstat`` reads cached inode metadata — no disk I/O,
                    # no blocking syscall worth a worker thread. Calling it
                    # inline removes the only await point between
                    # "file created" and "identity captured": with no
                    # ``await`` in between, asyncio has no point at which
                    # to deliver a cancellation into this coroutine, so the
                    # two statements are effectively atomic with respect to
                    # cancellation.
                    fstat_result = os.fstat(local_fd)
                    created_ino = (fstat_result.st_dev, fstat_result.st_ino)

                    try:
                        block = sftp.limits.max_read_len or 16384
                        written = 0
                        async with sftp.open(remote_path, "rb") as remote_file:
                            with os.fdopen(local_fd, "wb", closefd=True) as local_file:
                                local_fd = None  # ownership transferred
                                offset = 0
                                while True:
                                    # asyncssh's SFTPClientFile.read() is
                                    # annotated `-> AnyStr` without the
                                    # class itself being declared Generic,
                                    # so mypy cannot infer bytes from the
                                    # "rb" mode string passed to
                                    # sftp.open() above — pin it explicitly
                                    # via the variable annotation instead
                                    # of a blanket ignore; encoding=None
                                    # (set automatically by the 'b' in
                                    # "rb") guarantees bytes at runtime.
                                    data: bytes = await remote_file.read(block, offset)
                                    if not data:
                                        break
                                    await asyncio.to_thread(local_file.write, data)
                                    offset += len(data)
                                    written += len(data)

                        duration_ms = int((time.monotonic() - start_time) * 1000)

                        # P8: post-download size warning — bytes already
                        # on disk (this is the descriptor we just wrote,
                        # so the number is exact — no re-stat, no second
                        # resolution), so we warn rather than block.
                        if written > _MAX_SFTP_BYTES:
                            logger.warning(
                                "Downloaded file exceeds recommended size limit: %d bytes (limit %d)",
                                written,
                                _MAX_SFTP_BYTES,
                            )

                        self._audit.info(
                            "sftp.download.complete bytes=%s duration_ms=%s",
                            written,
                            duration_ms,
                        )

                        download_succeeded = True
                        return (
                            f"Downloaded {server_name}:{remote_path} to {local_path} "
                            f"({written} bytes)"
                        )
                    finally:
                        if local_file_created and not download_succeeded:
                            # Remove the orphan via the SAME confined walk
                            # used to create it (_unlink_beneath) rather
                            # than a bare os.unlink(local_path) — that
                            # would re-resolve the path string from
                            # scratch through ordinary symlink-following
                            # resolution, exactly what open_beneath exists
                            # to avoid. Best-effort: a secondary failure
                            # here must not mask the original error.
                            # expected_ino (Defect D) makes this refuse to
                            # remove a file that isn't the one this call
                            # created, e.g. after a concurrent rename onto
                            # the same leaf name.
                            with contextlib.suppress(OSError, PathConfinementError):
                                await asyncio.to_thread(
                                    _unlink_beneath,
                                    root_fd,
                                    local_path,
                                    expected_ino=created_ino,
                                )

        except (
            asyncssh.DisconnectError,
            asyncssh.PermissionDenied,
            asyncssh.SFTPError,
            OSError,
        ) as e:
            duration_ms = int((time.monotonic() - start_time) * 1000)
            self._audit.warning(
                "sftp.download.failed error=%s duration_ms=%s",
                type(e).__name__,
                duration_ms,
            )
            error_msg = (
                f"Download failed from {_safe_log_value(server_name)}: "
                f"{_safe_log_value(str(e))}"
            )
            logger.error("%s", error_msg)
            raise RuntimeError(error_msg) from e

        finally:
            if local_fd is not None:
                os.close(local_fd)
            structlog.contextvars.reset_contextvars(**ctx_tokens)

    async def close_all(self) -> None:
        """Close all active SSH connections and stop eviction task.

        Latches the transfer-root shutdown flag FIRST, so any SFTP transfer
        starting after this point is refused with ``RuntimeError``, then
        blocks on the transfer-root condition until every in-flight transfer
        has drained before closing the pinned transfer-root fd. Also clears
        the connection, last-used, connection-id, and per-server lock maps.
        """
        # Defect C (panel iteration 3, verified by executing code): this
        # latch must be set before ANY other await in this method.
        # Previously it was only set at the very end, after cancelling
        # the eviction task and closing every SSH connection — both of
        # which await — leaving a window during which a brand-new
        # transfer could observe `_transfer_root_closing is False`,
        # acquire the refcount via `_transfer_root()`, and start using a
        # root fd this method is about to close underneath it. The
        # refcount-drain wait later in this method still protects that
        # transfer's fd from a use-after-close, but it should never have
        # been allowed to start in the first place once shutdown began.
        # Acquiring the lock here is cheap/uncontended — the goal is
        # ordering (latch, then everything else), not avoiding the lock.
        async with self._transfer_root_cond:
            self._transfer_root_closing = True

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
                logger.info("Closed connection to %s", _safe_log_value(server_name))
            except Exception as e:
                logger.warning(
                    "Error closing connection to %s: %s",
                    _safe_log_value(server_name),
                    _safe_log_value(str(e)),
                )

        self._connections.clear()
        self._last_used.clear()
        self._connection_ids.clear()
        self._locks.clear()  # R5 #11: prune per-server locks on full reset

        # B1/Defect 5: release the pinned transfer-root directory fd, if
        # one was ever established. `_transfer_root_closing` was already
        # set to True at the top of this method (Defect C), before any
        # other await, so no transfer that started after close_all() was
        # called can have slipped in here. Waiting on the condition
        # until the refcount drains to zero means an in-flight transfer
        # that WAS already running before close_all() started has its fd
        # closed out from under it — the exact use-after-close Defect 5
        # reports. Safe even if no transfer ever ran: fd is None and
        # refcount is already 0.
        async with self._transfer_root_cond:
            while self._transfer_root_refcount > 0:
                await self._transfer_root_cond.wait()
            if self._transfer_root_fd is not None:
                os.close(self._transfer_root_fd)
                self._transfer_root_fd = None

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
        if _depth > _MAX_JUMP_HOST_DEPTH:
            raise RuntimeError(
                f"Maximum jump host depth exceeded "
                f"(depth={_depth}, limit={_MAX_JUMP_HOST_DEPTH}, "
                f"server={server_name})"
            )

        # Ensure eviction loop is started
        if not self._running:
            try:
                self._start_eviction_loop()
            except RuntimeError:
                pass  # No event loop yet; will retry on next call

        # S2: validate the server exists BEFORE minting a lock for it.
        # Locks used to be keyed via setdefault() before this lookup ran,
        # so a storm of calls against unknown/typo'd server names (reachable
        # via upload_file/download_file/execute tool args) accumulated one
        # asyncio.Lock per unique bogus name FOREVER — measured 1000 unknown
        # names -> 1000 orphaned locks, since nothing ever evicts a lock for
        # a server that was never a real connection. Raises KeyError, same
        # as before — only the ORDER relative to lock creation changed.
        server = self.registry.get_server(server_name)

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
                    logger.info(
                        "Connection to %s is closed, reconnecting",
                        _safe_log_value(server_name),
                    )
                    del self._connections[server_name]
                    del self._last_used[server_name]

            # Create new connection
            conn = await self._create_connection(server, _depth)

            # Cache connection, update last used time, mint fresh connection id
            self._connections[server_name] = conn
            self._last_used[server_name] = time.monotonic()
            self._connection_ids[server_name] = _make_connection_id(server_name)

            logger.info(
                "Created new connection to %s (id=%s)",
                server_name,
                self._connection_ids[server_name],
            )
            return conn

    async def _create_connection(
        self, server: ServerConfig, _depth: int = 0
    ) -> asyncssh.SSHClientConnection:
        """Create new SSH connection with jump host support.

        Connection establishment is bounded by ``settings.command_timeout``
        — a command-scoped setting reused as the connect timeout, so there
        is no separate connect-timeout knob.

        Args:
            server: Server configuration
            _depth: Internal recursion depth counter for jump hosts

        Returns:
            New SSH connection

        Raises:
            Various SSH exceptions on connection failure
        """
        # Build connection parameters
        connect_params: dict[str, Any] = {
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
            logger.info(
                "Connecting to %s via jump host %s", server.name, server.jump_host
            )
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
            logger.error(
                "SSH disconnect error connecting to %s: %s",
                _safe_log_value(server.name),
                _safe_log_value(str(e)),
            )
            raise
        except asyncssh.PermissionDenied as e:
            logger.error(
                "SSH permission denied for %s: %s",
                _safe_log_value(server.name),
                _safe_log_value(str(e)),
            )
            raise
        except OSError as e:
            logger.error(
                "OS error connecting to %s: %s",
                _safe_log_value(server.name),
                _safe_log_value(str(e)),
            )
            raise
        except asyncio.TimeoutError as e:
            logger.error(
                "Timeout connecting to %s: %s",
                _safe_log_value(server.name),
                _safe_log_value(str(e)),
            )
            raise

    def _start_eviction_loop(self) -> None:
        """Start background task for idle connection eviction."""
        if self._running:
            return

        self._eviction_task = asyncio.create_task(self._eviction_loop())
        self._running = True

    async def _eviction_loop(self) -> None:
        """Background task that evicts idle connections.

        Runs every ``_EVICTION_LOOP_INTERVAL_S`` seconds and closes
        connections idle longer than ``settings.connection_idle_timeout``.
        """
        logger.info("Started connection eviction loop")

        try:
            while self._running:
                await asyncio.sleep(_EVICTION_LOOP_INTERVAL_S)

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

                logger.info(
                    "Connection pool: %d active, %d locks",
                    len(self._connections),
                    len(self._locks),
                )

                # Evict idle connections
                for server_name, idle_time in to_evict:
                    # Get lock for this server (if it exists)
                    lock = self._locks.get(server_name)
                    if lock is None:
                        # No lock means connection already cleaned up
                        continue

                    # Acquire lock before evicting
                    async with lock:
                        # Re-check freshness inside lock — prevents TOCTOU race
                        current_last_used = self._last_used.get(server_name)
                        if current_last_used is None:
                            continue
                        if now - current_last_used <= idle_threshold:
                            continue  # Connection was refreshed while waiting for lock
                        if server_name in self._connections:
                            conn = self._connections[server_name]
                            try:
                                conn.close()
                                await conn.wait_closed()
                                logger.info(
                                    "Evicted idle connection to %s (idle %.0fs)",
                                    server_name,
                                    now - current_last_used,
                                )
                            except Exception as e:
                                logger.warning(
                                    "Error evicting connection to %s: %s",
                                    _safe_log_value(server_name),
                                    _safe_log_value(str(e)),
                                )
                            finally:
                                self._connections.pop(server_name, None)
                                self._last_used.pop(server_name, None)
                                self._connection_ids.pop(server_name, None)
                                # S3: deliberately NOT popping the lock here
                                # (previously "R5 #11"). This ran while
                                # STILL HOLDING `lock` (see `async with
                                # lock:` above) — popping it orphaned any
                                # caller already queued on the same Lock
                                # object, since the next `_get_connection`
                                # call would `setdefault` a brand-new Lock
                                # and start a SECOND, concurrent critical
                                # section over the same server's connection
                                # state, which could leave a connection
                                # opened-then-immediately-orphaned. Safe to
                                # leave the lock in place now that S2
                                # bounds `_locks` to real, registry-validated
                                # server names — it no longer grows
                                # unboundedly, so there is nothing to prune.

        except asyncio.CancelledError:
            logger.info("Connection eviction loop cancelled")
        except Exception as e:
            logger.error(
                "Unexpected error in eviction loop: %s", _safe_log_value(str(e))
            )
            # R5 finding #6: reset _running so _start_eviction_loop() can
            # restart the loop on the next _get_connection() call. Without
            # this, _running stays True after a crash and the loop is
            # permanently dead — connections accumulate without eviction
            # until the fd limit is hit.
            self._running = False
