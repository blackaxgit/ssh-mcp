# Multi-stage build for Python MCP server with uv package manager
# Base: python:3.13-slim-trixie (Debian 13, 2026 standard)
# 3.13 is a deliberate image target; the package itself supports >=3.11 and CI
# runs the 3.11-3.14 matrix (pyproject.toml, .github/workflows/ci.yml).
# Stage 1: Builder - compile dependencies with uv

# python:3.13-slim-trixie
FROM python:3.13-slim-trixie@sha256:d168b8d9eb761f4d3fe305ebd04aeb7e7f2de0297cec5fb2f8f6403244621664 AS builder

# Copy uv from official distribution image (not using as base to keep image small)
# ghcr.io/astral-sh/uv:0.11.3
COPY --from=ghcr.io/astral-sh/uv:0.11.3@sha256:90bbb3c16635e9627f49eec6539f956d70746c409209041800a0280b93152823 /uv /usr/local/bin/uv

# UV_COMPILE_BYTECODE=1 precompiles .pyc for faster cold start.
# UV_LINK_MODE=copy copies out of the uv cache instead of hardlinking — the
# cache is a cross-filesystem mount below, where hardlinks cannot be made.
# UV_PYTHON_DOWNLOADS=0 forbids fetching an interpreter; use the image's.
ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PYTHON_DOWNLOADS=0

WORKDIR /app

# Install runtime dependencies only (no project yet — see the second sync)
# --no-dev is belt-and-braces here: dev deps are declared as the *extra*
# [project.optional-dependencies].dev, and uv installs no extras by default;
# there is no [dependency-groups] / [tool.uv] dev-dependencies in pyproject.toml.
# The otel extra is deliberately NOT installed, so the OpenTelemetry spans in
# server.py/ssh.py are a silent no-op in this image (they only emit when
# opentelemetry-api is importable). Add --extra otel to both syncs to enable them.
# Use cache mounts for uv's package cache to speed up builds
RUN --mount=type=cache,target=/root/.cache/uv \
    --mount=type=bind,source=pyproject.toml,target=pyproject.toml \
    --mount=type=bind,source=uv.lock,target=uv.lock \
    uv sync --no-install-project --no-dev --no-editable --locked

# Copy source code and install the project into the venv (non-editable)
# --no-editable copies the package into site-packages instead of linking it via
# a .pth file — required because only .venv is copied to the runtime stage
COPY . .
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --no-dev --no-editable --locked

# Stage 2: Runtime - minimal production image

# python:3.13-slim-trixie
FROM python:3.13-slim-trixie@sha256:d168b8d9eb761f4d3fe305ebd04aeb7e7f2de0297cec5fb2f8f6403244621664

# Create non-root user for security (uid 1000 standard)
RUN useradd --uid 1000 --create-home --shell /sbin/nologin sshmcp

WORKDIR /app

# Copy virtual environment from builder with proper ownership
COPY --from=builder --chown=sshmcp:sshmcp /app/.venv /app/.venv

# Add venv to PATH and set HOME so expanduser()/Path.home() resolve ~ correctly:
# config discovery step 2 looks at ~/.config/ssh-mcp/servers.toml when
# XDG_CONFIG_HOME is unset, the ssh_config_path setting defaults to
# ~/.ssh/config (compose.yaml mounts /home/sshmcp/.ssh), and transfer_root
# defaults under $XDG_DATA_HOME or ~/.local/share.
ENV PATH=/app/.venv/bin:$PATH \
    PYTHONUNBUFFERED=1 \
    HOME=/home/sshmcp

# Switch to non-root user
USER sshmcp

# Port 8000 is the default for SSH_MCP_TRANSPORT=http (or streamable-http).
# Only relevant when running the streamable-HTTP transport; stdio deployments
# ignore this. Override via SSH_MCP_HTTP_PORT env var and republish with -p.
#
# Publishing the port is NOT enough: the server binds SSH_MCP_HTTP_HOST, which
# defaults to 127.0.0.1, so a published port is unreachable from outside the
# container until SSH_MCP_HTTP_HOST=0.0.0.0. A non-loopback bind then ABORTS
# startup unless SSH_MCP_HTTP_TOKEN is set, or SSH_MCP_HTTP_AUTH=none *plus*
# SSH_MCP_HTTP_NETWORK_NO_AUTH=I_ACCEPT_RCE_RISK. See the ssh-mcp-http service
# in compose.yaml for a complete working set.
EXPOSE 8000

# HEALTHCHECK: use the built-in ``ssh-mcp healthcheck`` subcommand which
# auto-detects transport (stdio vs streamable-http) and performs a real
# MCP initialize handshake in HTTP mode. Transport comes from
# SSH_MCP_TRANSPORT; the HTTP branch then reads SSH_MCP_HTTP_PORT,
# SSH_MCP_HTTP_TOKEN, SSH_MCP_HTTP_TOKEN_FILE and SSH_MCP_HTTP_AUTH, while the
# default stdio branch reads none of those — it resolves the config through the
# server's own chain (SSH_MCP_CONFIG, else XDG_CONFIG_HOME, else HOME) and
# parses it into a ServerRegistry.
#
# The stdio probe is therefore STRICTER than startup: no resolvable config
# means unhealthy, whereas the server only logs a warning and runs. Only
# /app/.venv is copied into this stage, so no config ships in the image —
# `docker run <image>` with neither SSH_MCP_CONFIG nor a mounted
# ~/.config/ssh-mcp/servers.toml reports unhealthy by design. Mount a config
# and point SSH_MCP_CONFIG at it, as compose.yaml does.
#
# start_period=10s covers startup for HTTP transport (FastMCP session
# manager init + uvicorn bind). interval=30s is standard. --timeout=5s is the
# only bound on the stdio branch (healthcheck.py's HEALTHCHECK_TIMEOUT=3
# bounds the HTTP request alone); the stdio import costs ~0.3s.
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD ssh-mcp healthcheck

# Entry point: invoke the console script installed by uv
ENTRYPOINT ["ssh-mcp"]
