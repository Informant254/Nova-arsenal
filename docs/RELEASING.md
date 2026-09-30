# Releasing Nova-Arsenal

Nova-Arsenal releases are tag-driven. A release tag publishes the Python package, container images, and a GitHub Release, so tags should only be created after the release-prep PR has merged and `main` is green.

## Release prerequisites

Before creating a tag:

1. Confirm CI and Security workflows are green on `main`.
2. Confirm the version matches across:
   - `pyproject.toml`
   - `nova_arsenal.__version__`
   - `AgentConfig.version`
   - FastAPI application version
   - VS Code `package.json` and root lockfile metadata
3. Confirm `CHANGELOG.md` contains the release version and date.
4. Configure PyPI Trusted Publishing for this GitHub repository/workflow.
5. Configure repository secrets `DOCKERHUB_USERNAME` and `DOCKERHUB_TOKEN`.
6. Confirm the repository can publish packages to GHCR using `GITHUB_TOKEN`.
7. Confirm the production Compose image names match the release workflow:
   - `ghcr.io/informant254/nova-agent`
   - `ghcr.io/informant254/nova-web`
   - `ghcr.io/informant254/nova-kali`

## Creating a release

For version `2.0.0`, create and push tag `v2.0.0` from the exact `main` commit that passed CI/Security.

The release workflow first verifies that the tag exactly matches the version declared in `pyproject.toml`. It then runs Ruff, formatting, BasedPyright, the Python test suite, Python package build validation, and only after those pass does it publish artifacts.

## Published artifacts

A successful tag release publishes:

- `nova-arsenal` to PyPI through Trusted Publishing.
- `nova-agent`, `nova-web`, and `nova-kali` to GHCR.
- `nova-agent`, `nova-web`, and `nova-kali` to Docker Hub.
- A generated GitHub Release.

## Failure policy

Do not retag an existing released version to point at a different commit. Fix the problem on `main`, increment the version, update the changelog, and release a new tag.

If external publishing credentials are not configured, do not create the release tag yet. The release-prep branch and PR may be merged safely without publishing anything.