# Changelog

All notable changes to Nova-Arsenal will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Initial release of Nova-Arsenal platform
- 70+ security modules (recon, attack, analysis, reporting)
- Multi-LLM support (Ollama, OpenAI, Anthropic, Gemini)
- Web dashboard with real-time monitoring
- Docker-based deployment
- Multi-user authentication with JWT
- SQLite database for findings storage
- Kubernetes deployment manifests
- GitHub Actions CI/CD pipeline
- Security scanning (CodeQL, Trivy, TruffleHog)

### Changed
- N/A (initial release)

### Deprecated
- N/A (initial release)

### Removed
- N/A (initial release)

### Fixed
- N/A (initial release)

### Security
- Capability dropping in all containers
- Network isolation for sandbox
- Secret redaction in logs
- Tool governance and rate limiting

---

## [1.0.0] - 2026-XX-XX

### Added
- Core agent system with autonomous reasoning
- Skills library with prompt templates
- Governed tool kit with scope enforcement
- Multi-agent swarm architecture
- Web UI dashboard
- REST API with FastAPI
- WebSocket real-time updates
- Docker deployment
- Kubernetes manifests
- CI/CD pipeline
- Comprehensive documentation

---

## Versioning

We use [SemVer](https://semver.org/) for versioning. For the versions available, see the [tags on this repository](https://github.com/Informant254/Nova-arsenal/tags).

## Release Process

1. Update version in `pyproject.toml`
2. Update `CHANGELOG.md`
3. Create a git tag: `git tag v1.0.0`
4. Push: `git push origin v1.0.0`
5. CI/CD will automatically publish to PyPI, Docker Hub, and GHCR
