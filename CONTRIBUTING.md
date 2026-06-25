# Contributing to Nova-Arsenal

Thank you for your interest in contributing to Nova-Arsenal! This document provides guidelines and instructions for contributing.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Setup](#development-setup)
- [Making Changes](#making-changes)
- [Testing](#testing)
- [Pull Requests](#pull-requests)
- [Style Guidelines](#style-guidelines)

## Code of Conduct

Please read our [Code of Conduct](CODE_OF_CONDUCT.md) before contributing. We expect all contributors to follow it.

## Getting Started

1. **Fork the repository** on GitHub
2. **Clone your fork** locally:
   ```bash
   git clone https://github.com/your-username/Nova-arsenal.git
   cd Nova-arsenal
   ```
3. **Add upstream remote**:
   ```bash
   git remote add upstream https://github.com/Informant254/Nova-arsenal.git
   ```
4. **Create a branch** for your changes:
   ```bash
   git checkout -b feature/your-feature-name
   ```

## Development Setup

### Prerequisites

- Python 3.10+
- Node.js 18+ (for web client)
- Docker and Docker Compose (for containerized development)

### Installation

```bash
# Install Python dependencies
make install

# Install web client dependencies
make install-web

# Start development services
docker compose up -d llm sandbox
```

### Environment Variables

```bash
cp config/.env.example .env
# Edit .env with your API keys
```

## Making Changes

### Branch Naming

- `feature/` - New features
- `fix/` - Bug fixes
- `docs/` - Documentation changes
- `refactor/` - Code refactoring
- `test/` - Adding tests

### Commit Messages

Use [Conventional Commits](https://www.conventionalcommits.org/):

```
feat: add new SQL injection skill
fix: resolve scope enforcement issue
docs: update API reference
test: add unit tests for nova_skills
refactor: extract LLM providers
```

## Testing

### Running Tests

```bash
# All tests
make test

# Unit tests only
make test-unit

# Integration tests only
make test-integration

# With coverage
pytest --cov=nova_arsenal --cov-report=html
```

### Writing Tests

- Place unit tests in `tests/unit/`
- Place integration tests in `tests/integration/`
- Use fixtures from `tests/conftest.py`
- Aim for 60%+ coverage on new code

## Pull Requests

### PR Title

Use the same convention as commit messages:

```
feat: add support for Gemini LLM provider
```

### PR Description

Include:

1. **Summary** - What does this PR do?
2. **Motivation** - Why is this change needed?
3. **Testing** - How was this tested?
4. **Screenshots** - If applicable, add screenshots

### PR Checklist

- [ ] Code follows style guidelines
- [ ] Tests added/updated
- [ ] Documentation updated
- [ ] No breaking changes (or clearly documented)
- [ ] All tests pass (`make quality`)

## Style Guidelines

### Python

- Follow [PEP 8](https://peps.python.org/pep-0008/)
- Use [ruff](https://github.com/astral-sh/ruff) for linting
- Type hints required for public functions
- Docstrings for all public classes and functions

```python
def analyze_vulnerability(endpoint: str, params: List[str]) -> Dict[str, Any]:
    """
    Analyze an endpoint for potential vulnerabilities.
    
    Args:
        endpoint: The target endpoint URL
        params: List of parameters to test
        
    Returns:
        Dictionary containing findings
    """
    pass
```

### TypeScript/React

- Use [ESLint](https://eslint.org/) and [Prettier](https://prettier.io/)
- Functional components with hooks
- TypeScript for all files

### Commit Hygiene

- One logical change per commit
- Keep commits focused and atomic
- Write clear commit messages

## Questions?

Open an issue or reach out on Discord.

Thank you for contributing!
