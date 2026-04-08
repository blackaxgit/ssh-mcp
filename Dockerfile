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

# HEALTHCHECK: Process-based check (no HTTP for stdio servers)
# Verifies ssh-mcp process is still running
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD ps aux | grep -q '[s]sh-mcp' || exit 1

# Entry point: invoke the console script installed by uv
ENTRYPOINT ["ssh-mcp"]
