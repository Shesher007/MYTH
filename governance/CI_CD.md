# MYTH CI/CD Architecture

This document describes the design and usage of the MYTH CI/CD workflow system.

## Design Philosophy

The MYTH CI/CD system follows the **"Logic-in-Code, CI-is-a-Wrapper"** principle.
- **Orchestration Layer**: All build, test, and validation logic lives in `scripts/ci_orchestrator.py`.
- **Portability Layer**: CI configuration files (GitHub Actions YAML, GitLab CI YAML) are thin wrappers that simply invoke the `ci_orchestrator.py` script.
- **SSOT**: Versioning and branding are derived from `governance/identity.yaml` via the hydration system.

## Local Usage

Developers should run the CI pipeline locally before pushing to ensure high code quality.

```bash
# Run all pre-push checks (validate hydration + lint + test)
python scripts/ci_local.py

# Run a full pipeline (includes build stages)
python scripts/ci_local.py --full

# Run a specific stage
python scripts/ci_local.py --stage test
```

## CI Platforms

### GitHub Actions
Workflows are located in `.github/workflows/`. They are generated from `.template` files.
- `ci.yml`: Runs on every push/PR (Lint, Test).
- `build-desktop.yml`: Builds Tauri application (Tags only).
- `deploy-website.yml`: Deploys to Cloudflare Pages (Website changes).
- `release.yml`: Creates GitHub Releases with artifacts.

### GitLab CI
Configuration is in `.gitlab-ci.yml`. It mirrors the GitHub pipeline stages.
- Stages: `validate`, `lint`, `test`, `build`, `deploy`, `release`.

## Orchestrator Stages Reference

| Stage | Command | Purpose |
|-------|---------|---------|
| `validate` | `hydrate.py --check` | Ensures templates are in sync and identity is valid. |
| `lint` | `ruff check .` | Checks for code style and potential bugs. |
| `test` | `run_all.py --fast` | Executes the comprehensive test suite. |
| `build-backend` | `package_python.py` | Bundles the FastAPI backend into a sidecar. |
| `build-desktop` | `npx tauri build` | Build the desktop binary for the target triple. |
| `build-docker` | `docker build` | Creates a portable OCI container image. |
| `deploy-website` | `npm run build` | Builds the website and deploys to Cloudflare. |

To migrate to a new CI platform (e.g., CircleCI, Jenkins, Azure Pipelines):
1. Create a workspace that installs Python 3.13, Node 24, and Rust.
2. Install `uv` and run `uv sync`.
3. Call `python scripts/ci_orchestrator.py <stage>` for each step in your pipeline.

### Example: Azure Pipelines (`azure-pipelines.yml`)
```yaml
jobs:
- job: Build
  pool: { vmImage: 'ubuntu-latest' }
  steps:
  - script: curl -LsSf https://astral.sh/uv/install.sh | sh
  - script: uv sync --all-extras
  - script: uv run python scripts/ci_orchestrator.py check-env
  - script: uv run python scripts/ci_orchestrator.py validate
  - script: uv run python scripts/ci_orchestrator.py build-backend
```
