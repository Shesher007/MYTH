"""
MYTH Packaging — Manifest Hydration Engine
Reads packaging/meta.json and pyproject.toml to generate platform-specific manifests.
"""

import json
from pathlib import Path

import tomli

# Paths
PROJECT_ROOT = Path(__file__).parent.parent
PACKAGING_DIR = PROJECT_ROOT / "packaging"
META_FILE = PACKAGING_DIR / "meta.json"
PYPROJECT_FILE = PROJECT_ROOT / "pyproject.toml"


def load_metadata():
    """Load and merge metadata from meta.json and pyproject.toml."""
    # 1. Load static metadata
    with open(META_FILE, "r", encoding="utf-8") as f:
        meta = json.load(f)

    # 2. Load dynamic version from pyproject.toml
    with open(PYPROJECT_FILE, "rb") as f:
        pyproject = tomli.load(f)

    project_info = pyproject.get("project", {})
    version = project_info.get("version", "0.0.0")

    # 3. Flatten context for templating
    context = {
        "VERSION": version,
        "NAME": meta["project"]["name"],
        "NAME_LOWER": meta["project"]["name"].lower(),
        "CODENAME": meta["project"]["codename"],
        "DESCRIPTION": meta["project"]["description"],
        "SHORT_DESCRIPTION": meta["project"]["short_description"],
        "ORG": meta["organization"]["name"],
        "ORG_LOWER": meta["organization"]["org_lower"],
        "MAINTAINER_NAME": meta["maintainer"]["name"],
        "MAINTAINER_EMAIL": meta["maintainer"]["email"],
        "HOMEPAGE": meta["organization"]["homepage"],
        "REPO_URL": meta["repository"]["url"],
        "ISSUES_URL": meta["repository"]["issues"],
        "LICENSE": meta["license"]["spdx"],
        "LICENSE_URL": meta["repository"]["license_url"],
        "COPYRIGHT_YEAR": meta["license"]["copyright_year"],
        # Artifact filenames (hydrated with version)
        "ARTIFACT_DEB": meta["artifacts"]["deb"].replace("1.1.1", version),
        "ARTIFACT_RPM": meta["artifacts"]["rpm"].replace("1.1.1", version),
        "ARTIFACT_APPIMAGE": meta["artifacts"]["appimage"].replace("1.1.1", version),
        "ARTIFACT_DMG": meta["artifacts"]["dmg"].replace("1.1.1", version),
        "ARTIFACT_TARBALL": meta["artifacts"]["tarball"].replace(
            "v1.1.1", f"v{version}"
        ),
    }

    return context


def hydrate_templates():
    """Find all .template files and generate their outputs."""
    context = load_metadata()
    print(f"💧 Hydrating manifests for MYTH v{context['VERSION']}...")

    templates = list(PACKAGING_DIR.rglob("*.template"))
    if not templates:
        print("⚠️  No .template files found in packaging/ directory.")
        return

    for template_path in templates:
        output_path = template_path.with_suffix("")  # Remove .template extension
        print(f"   Processing: {template_path.name} -> {output_path.name}")

        with open(template_path, "r", encoding="utf-8") as f:
            content = f.read()

        # Replace all placeholders
        for key, value in context.items():
            placeholder = f"{{{{{key}}}}}"
            content = content.replace(placeholder, str(value))

        with open(output_path, "w", encoding="utf-8") as f:
            f.write(content)

    print(f"✅ Successfully hydrated {len(templates)} manifests.")


if __name__ == "__main__":
    try:
        hydrate_templates()
    except Exception as e:
        print(f"❌ Failed to hydrate manifests: {e}")
        exit(1)
