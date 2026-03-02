# Contributing

## Development Setup

Requires Python 3.11+ and [uv](https://docs.astral.sh/uv/getting-started/installation/).

```bash
git clone https://github.com/blackaxgit/ssh-mcp.git
cd ssh-mcp
uv sync --extra dev
```

## Running Tests

```bash
uv run pytest
```

For verbose output:

```bash
uv run pytest -v
```

## Code Style

This project uses [ruff](https://docs.astral.sh/ruff/) for linting and formatting.

```bash
uv run ruff check .
uv run ruff format .
```

All public functions and methods must have type hints. New code should maintain compatibility with Python 3.11+.

## Making Changes

1. Fork the repository and create a branch from `main`.
2. Write or update tests for any changed behavior.
3. Ensure `uv run pytest` passes and `uv run ruff check .` reports no errors.
4. Open a pull request with a clear description of the change and its motivation.

## Pull Request Guidelines

- Keep PRs focused on a single change or fix.
- Reference any related issues in the PR description.
- Security-sensitive changes (credential handling, command execution) will receive closer review and may require additional testing evidence.

## Reporting Bugs

Open a [GitHub issue](https://github.com/blackaxgit/ssh-mcp/issues) with:

- ssh-mcp version (`uvx ssh-mcp --version`)
- Python version
- Steps to reproduce
- Expected vs. actual behavior

For security vulnerabilities, see [SECURITY.md](SECURITY.md).
