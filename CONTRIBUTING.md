# Contributing to Nerve

Thanks for your interest in contributing to Nerve! This guide will help you get started.

## Development Setup

```bash
# Clone the repo
git clone https://github.com/BreachLine/nerve.git
cd nerve

# Create a virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install in editable mode with all deps + dev tools
pip install -e ".[all,dev]"

# Verify setup
pytest
ruff check nerve/ tests/
```

## Running Tests

```bash
# All tests
pytest

# Single file
pytest tests/unit/test_config.py

# With coverage
pytest --cov=nerve
```

## Code Quality

We use [Ruff](https://docs.astral.sh/ruff/) for linting and formatting:

```bash
# Lint
ruff check nerve/ tests/

# Lint with auto-fix
ruff check --fix nerve/ tests/

# Format
ruff format nerve/ tests/
```

**Rules:** E, F, I, N, W, UP. Line length: 100. Target: Python 3.11+.

## Project Structure

See [docs/extending.md](docs/extending.md) for architecture details. The key extension points:

- **New tools** — async function in `nerve/tools/`, register in `registry.py`
- **New agents** — extend `NerveAgent` in `nerve/agents/`, wire into `orchestrator.py`
- **New techniques** — add to `TECHNIQUE_LIBRARY` in `nerve/knowledge/techniques.py`
- **New CVEs** — append to `CVE_DATABASE` in `nerve/knowledge/cve_db.py`

## Conventions

- Python 3.11+ with modern type annotations (`X | None`, not `Optional[X]`)
- Async throughout — tools use `httpx.AsyncClient`, agents use `anyio`
- Structured logging via `structlog`
- Pydantic v2 for data models
- Findings emitted in `FINDING: {json}` format by agents

## Pull Requests

1. Fork the repo and create a feature branch from `main`
2. Write tests for new functionality
3. Ensure `pytest` and `ruff check` pass
4. Keep PRs focused — one feature or fix per PR
5. Write a clear PR description explaining the *why*

## Reporting Issues

Use [GitHub Issues](https://github.com/BreachLine/nerve/issues). For security vulnerabilities, email dev@breachline.ai instead.

## License

By contributing, you agree that your contributions will be licensed under the [MIT License](LICENSE).
