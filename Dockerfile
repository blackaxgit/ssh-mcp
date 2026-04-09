# Multi-stage build for Python MCP server with uv package manager
# Base: python:3.13-slim-trixie (Debian 13, 2026 standard)
# Stage 1: Builder - compile dependencies with uv

FROM python:3.13-slim-trixie AS builder

# Copy uv from official distribution image (not using as base to keep image small)
COPY --from=ghcr.io/astral-sh/uv:0.11.3 /uv /usr/local/bin/uv

# Compile bytecode and optimize cache locality for production
ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PYTHON_DOWNLOADS=0

WORKDIR /app

# Install runtime dependencies only (no dev deps, no editable install)
# --no-editable ensures the package is copied into site-packages, not linked via .pth
# Use cache mounts for uv's package cache to speed up builds
RUN --mount=type=cache,target=/root/.cache/uv \
    --mount=type=bind,source=pyproject.toml,target=pyproject.toml \
    --mount=type=bind,source=uv.lock,target=uv.lock \
    uv sync --no-install-project --no-dev --no-editable --locked

# Copy source code and install the project into the venv (non-editable)
# Non-editable install is required because only .venv is copied to runtime stage
COPY . .
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --no-dev --no-editable --locked

# Stage 2: Runtime - minimal production image

FROM python:3.13-slim-trixie

# Create non-root user for security (uid 1000 standard)
RUN useradd --uid 1000 --create-home --shell /sbin/nologin sshmcp

WORKDIR /app

# Copy virtual environment from builder with proper ownership
COPY --from=builder --chown=sshmcp:sshmcp /app/.venv /app/.venv

# Add venv to PATH
ENV PATH=/app/.venv/bin:$PATH \
    PYTHONUNBUFFERED=1

# Switch to non-root user
USER sshmcp

# Port 8000 is the default for SSH_MCP_TRANSPORT=http. Only relevant when
# running the streamable-HTTP transport; stdio deployments ignore this.
# Override via SSH_MCP_HTTP_PORT env var and republish with -p.
EXPOSE 8000

# HEALTHCHECK: Python-based import check (slim image has no `ps`)
# Verifies the ssh_mcp package is importable — signals the runtime is healthy.
# For HTTP transport, operators may prefer a curl-based probe against
# http://127.0.0.1:${SSH_MCP_HTTP_PORT:-8000}/mcp but curl is not in the slim
# image, so the import check is the portable default.
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD python -c "import ssh_mcp" || exit 1

# Entry point: invoke the console script installed by uv
ENTRYPOINT ["ssh-mcp"]
