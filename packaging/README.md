# MYTH Packaging Hub

> **Dynamic, template-driven manifest generation for 30+ platforms.**

## Architecture

```
packaging/
├── meta.json              ← Single source of truth for project metadata
├── meta.schema.json       ← JSON Schema for validation & IDE support
├── README.md              ← This file
├── arch/
│   ├── PKGBUILD.template  ← Source template with {{PLACEHOLDERS}}
│   └── PKGBUILD           ← Generated output (do not edit by hand)
├── debian/
│   ├── control.template
│   └── control
└── ...                    ← 30+ platform directories
```

## How It Works

1. **`meta.json`** holds structured project metadata (name, org, maintainer, license, artifact patterns).
2. **`pyproject.toml`** is the canonical source of truth for the project **version** — the engine reads it automatically.
3. **`scripts/hydrate_manifests.py`** walks `packaging/`, finds every `*.template` file, replaces `{{KEY}}` placeholders with metadata values, and writes the hydrated output alongside the template.

## Quick Start

```bash
# Generate all manifests:
python scripts/hydrate_manifests.py

# CI/CD check (exits 1 if any manifest is out of sync):
python scripts/hydrate_manifests.py --check

# List all available placeholders:
python scripts/hydrate_manifests.py --validate
```

## Bumping a Version

1. Update `version` in `pyproject.toml`
2. Run `python scripts/hydrate_manifests.py`
3. Commit the regenerated manifests

That's it — every manifest across all 30+ platforms is updated in one command.

## Adding a New Platform

1. Create `packaging/<platform>/manifest.ext.template`
2. Use `{{KEY}}` placeholders (run `--validate` to see all available keys)
3. Run `python scripts/hydrate_manifests.py`
4. Both the `.template` and generated file will exist side-by-side

## Rules

- **Never edit generated files directly** — always edit the `.template`
- **Commit both** the `.template` and the generated output
- **Version lives in `pyproject.toml`** — do not hardcode versions in templates
