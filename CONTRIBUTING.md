# Contributing to fortinet-mcp-server

Thank you for your interest in contributing! This document explains how to propose changes, report issues, and get your pull request merged smoothly.

---

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Ways to Contribute](#ways-to-contribute)
- [Getting Started](#getting-started)
- [Development Workflow](#development-workflow)
- [Code Style](#code-style)
- [Commit Convention](#commit-convention)
- [Pull Request Guidelines](#pull-request-guidelines)
- [Reporting Bugs](#reporting-bugs)
- [Requesting Features](#requesting-features)
- [Security Vulnerabilities](#security-vulnerabilities)

---

## Code of Conduct

This project follows the [Contributor Covenant Code of Conduct](CODE_OF_CONDUCT.md). By participating, you are expected to uphold this code.

---

## Ways to Contribute

| Type | How |
|------|-----|
| 🐛 Bug fix | Open an issue first, then submit a PR |
| ✨ New tool / endpoint | Discuss in an issue before writing code |
| 📝 Documentation | PRs always welcome — no issue required |
| 🔒 Security issue | See [SECURITY.md](SECURITY.md) — **do not open a public issue** |
| 🧪 Tests | More test coverage is always appreciated |

---

## Getting Started

### Prerequisites

- Python 3.11+
- [`uv`](https://github.com/astral-sh/uv) package manager
- A FortiGate device or a mock/test environment (no live device required for most contributions)

### Fork & clone

```bash
# 1. Fork on GitHub, then:
git clone https://github.com/<your-username>/fortinet-mcp-server.git
cd fortinet-mcp-server

# 2. Add the upstream remote
git remote add upstream https://github.com/paoloamato2/fortinet-mcp-server.git

# 3. Install dependencies (including dev extras)
uv sync
```

---

## Development Workflow

```bash
# Create a feature branch from master
git checkout -b feat/my-new-tool

# Make your changes, then run tests
uv run pytest

# Lint / format (if ruff is available)
uv run ruff check .
uv run ruff format .

# Commit following the convention below
git commit -m "feat(firewall): add firewall_policy_move tool"

# Push and open a PR against master
git push origin feat/my-new-tool
```

---

## Code Style

- **Formatter:** [`ruff format`](https://docs.astral.sh/ruff/) — 88-column line width, double quotes.
- **Linter:** `ruff check` with default rules.
- **Type hints:** All public functions and tool handlers should be fully typed.
- **Docstrings:** Use Google-style docstrings for module-level and function-level documentation.
- **Tool placement:** Add new tools to the appropriate module under `tools/`. If a tool does not fit any existing module, propose a new one in the issue first.

### Adding a new MCP tool

1. Choose the correct module in `tools/` (or propose a new one).
2. Define the tool function with full typing and a clear docstring — the docstring becomes the tool description shown to the LLM.
3. Register the tool in `server.py` if it requires registration outside the module (check how existing tools are registered).
4. Add at least one test in `tests/` covering the happy path and one error case.

---

## Commit Convention

This project uses [Conventional Commits](https://www.conventionalcommits.org/):

```
<type>(<scope>): <short summary>

[optional body]

[optional footer(s)]
```

| Type | Use for |
|------|---------|
| `feat` | New tool or feature |
| `fix` | Bug fix |
| `docs` | Documentation only |
| `test` | Adding or updating tests |
| `refactor` | Code change without new feature or bug fix |
| `chore` | Build, CI, dependency updates |
| `security` | Security-related fix |

Example: `feat(vpn): add ssl_vpn_user_disconnect tool`

---

## Pull Request Guidelines

- **One concern per PR** — keep PRs focused and small.
- Fill in the PR template completely.
- Ensure `uv run pytest` passes before requesting review.
- Link the related issue with `Closes #<issue-number>`.
- Do **not** include unrelated whitespace or formatting changes.
- Mark the PR as **Draft** while work is still in progress.

---

## Reporting Bugs

Open an issue using the **Bug Report** template and include:

- FortiOS firmware version
- Python version and OS
- MCP client (Claude Desktop, Cursor, etc.) and its version
- Minimal reproduction steps
- Full error message / traceback (redact any credentials)

---

## Requesting Features

Open an issue using the **Feature Request** template and describe:

- The FortiOS API endpoint(s) you want to expose
- Your use case / motivation
- Any relevant Fortinet documentation links

---

## Security Vulnerabilities

**Do not open a public issue for security bugs.** Please follow the process described in [SECURITY.md](SECURITY.md).
