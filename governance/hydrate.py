#!/usr/bin/env python3
"""
MYTH Packaging Manifest Hydration Engine
==========================================
Reads structured metadata from packaging/meta.json (and version from
pyproject.toml as the canonical SSOT), flattens it into a unified
placeholder dictionary, and injects values into every *.template file
found under packaging/.

Usage:
    python scripts/hydrate_manifests.py           # Generate all manifests
    python scripts/hydrate_manifests.py --check    # CI dry-run: exit 1 if out-of-sync
    python scripts/hydrate_manifests.py --validate # Validate meta.json only (no file I/O)
"""

import argparse
import base64
import datetime
import json
import os
import re
import sys

import yaml

# MISSION CRITICAL: Force UTF-8 encoding for stdout/stderr on Windows to avoid UnicodeEncodeError with emojis
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except AttributeError:
        # Fallback for older Python versions
        import io

        sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8")
        sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8")

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
GOVERNANCE_DIR = os.path.dirname(os.path.abspath(__file__))
TEMPLATES_DIR = os.path.join(PROJECT_ROOT, "templates")

IDENTITY_PATH = os.path.join(GOVERNANCE_DIR, "identity.yaml")
IDENTITY_SCHEMA_PATH = os.path.join(GOVERNANCE_DIR, "identity.schema.json")
META_PATH = os.path.join(GOVERNANCE_DIR, "packaging.json")
PYPROJECT_PATH = os.path.join(PROJECT_ROOT, "pyproject.toml")

# Universal discovery: Walk entire project but ignore noise
EXCLUDE_DIRS = {
    ".git",
    ".venv",
    "node_modules",
    "target",
    "build",
    "__pycache__",
    ".agent",
    ".mcp_cache",
    ".myth_term_state",
    "venv",
    "env",
    "dist",
    "out",
}


# ---------------------------------------------------------------------------
# Metadata Engine
# ---------------------------------------------------------------------------
def load_metadata() -> dict:
    """Load metadata from identity.yaml (SSOT) and meta.json (Secondary)."""
    flat = {}

    # 1. Load Root Identity (Primary SSOT)
    if os.path.exists(IDENTITY_PATH):
        with open(IDENTITY_PATH, "r", encoding="utf-8") as f:
            identity = yaml.safe_load(f) or {}

        # Industry-Grade Validation
        if os.path.exists(IDENTITY_SCHEMA_PATH):
            try:
                import jsonschema

                with open(IDENTITY_SCHEMA_PATH, "r", encoding="utf-8") as sf:
                    schema = json.load(sf)
                jsonschema.validate(instance=identity, schema=schema)
                print("✅ Identity verified against schema.")
            except ImportError:
                print(
                    "⚠️  Warning: 'jsonschema' not installed. Skipping deep validation."
                )
            except Exception as e:
                print(f"❌ Identity Validation Error: {e}")
                sys.exit(1)

            # Flatten identity keys
            # --- Identity ---
            id_sect = identity.get("identity", {})
            flat["NAME"] = id_sect.get("name")
            flat["NAME_LOWER"] = id_sect.get("name", "").lower()
            flat["FULL_NAME"] = id_sect.get("full_name")
            flat["VERSION"] = id_sect.get("version")
            flat["TOOL_COUNT"] = id_sect.get("tool_count")
            flat["CODENAME"] = id_sect.get("codename")
            flat["DESCRIPTION"] = id_sect.get("description")
            flat["SHORT_DESCRIPTION"] = id_sect.get("short_description")

            # --- Organization ---
            org_sect = identity.get("organization", {})
            flat["ORG"] = org_sect.get("name")
            flat["ORG_NAME"] = flat["ORG"]
            flat["ORG_DISPLAY"] = org_sect.get("display_name")
            flat["ORG_LOWER"] = org_sect.get("org_lower")
            flat["REVERSE_DOMAIN"] = org_sect.get("reverse_domain")
            flat["HOMEPAGE"] = org_sect.get("homepage")

            # --- Author ---
            auth_sect = identity.get("author", {})
            flat["AUTHOR"] = auth_sect.get("name")
            flat["EMAIL"] = auth_sect.get("email")

            # --- Repository ---
            repo_sect = identity.get("repository", {})
            flat["REPO_URL"] = repo_sect.get("url")
            flat["ISSUES_URL"] = repo_sect.get("issues_url")
            flat["LICENSE_URL"] = repo_sect.get("license_url")

            # --- License ---
            lic_sect = identity.get("license", {})
            flat["LICENSE"] = lic_sect.get("spdx")
            flat["LICENSE_SPDX"] = lic_sect.get("spdx")
            flat["LICENSE_CUSTOM"] = lic_sect.get("custom")

            # --- Branding ---
            brand_sect = identity.get("branding", {})
            flat["BRANDING_PRIMARY"] = brand_sect.get("primary_color")
            flat["BRANDING_SECONDARY"] = brand_sect.get("secondary_color")
            flat["BRANDING_ACCENT"] = brand_sect.get("accent_color")
            flat["BRANDING_BACKGROUND"] = brand_sect.get("background_color")

            # Helper to convert Hex to RGB (e.g. #7c3aed -> 124, 58, 237)
            def hex_to_rgb(hex_color):
                if not hex_color or not hex_color.startswith("#"):
                    return ""
                hex_color = hex_color.lstrip("#")
                if len(hex_color) == 3:
                    hex_color = "".join([c * 2 for c in hex_color])  # #F00 -> #FF0000
                try:
                    return f"{int(hex_color[0:2], 16)}, {int(hex_color[2:4], 16)}, {int(hex_color[4:6], 16)}"
                except Exception:
                    return ""

            flat["BRANDING_PRIMARY_RGB"] = hex_to_rgb(flat["BRANDING_PRIMARY"])
            flat["BRANDING_SECONDARY_RGB"] = hex_to_rgb(flat["BRANDING_SECONDARY"])
            flat["BRANDING_ACCENT_RGB"] = hex_to_rgb(flat["BRANDING_ACCENT"])

            # Helper for SLUGs (e.g. cyan-400) - For now we map hex to approximate tailwind names or just use the hex
            # But the templates use {{BRANDING_ACCENT_SLUG}}
            # We will use the raw hex for now or a placeholder if needed.
            # Actually, TacticalCursor uses bg-{{BRANDING_ACCENT_SLUG}}. This implies a class name.
            # If we want custom colors, we should use style={{...}} or arbitrary values bg-[#...]
            # Updating templates to use arbitrary values might be better, but for now let's set SLUG to invalid and rely on valid RGB for others?
            # Or we can patch TacticalCursor template to use style/arbitrary.
            # For now, let's just make the RGB part work.
            # --- Ecosystem ---
            eco_sect = identity.get("ecosystem", {})
            flat["ECOSYSTEM_APPLE_BUNDLE"] = eco_sect.get("apple_bundle_id")
            flat["ECOSYSTEM_DOCKER_IMAGE"] = eco_sect.get("docker_image")
            flat["ECOSYSTEM_NPM_PACKAGE"] = eco_sect.get("npm_package")

            # --- Social ---
            soc_sect = identity.get("social", {})
            flat["SOCIAL_DISCORD"] = soc_sect.get("discord")
            flat["SOCIAL_TWITTER"] = soc_sect.get("twitter")
            flat["SOCIAL_DOCS"] = soc_sect.get("documentation")

            # --- Security ---
            sec_sect = identity.get("security", {})
            flat["SECURITY_PGP"] = sec_sect.get("pgp_fingerprint")
            flat["SECURITY_POLICY"] = sec_sect.get("policy_url")
            flat["SECURITY_CONTACT"] = sec_sect.get("contact")

            # --- Infrastructure ---
            infra_sect = identity.get("infrastructure", {})
            flat["INFRA_PORT_BACKEND"] = infra_sect.get("backend_port")
            flat["INFRA_PORT_DEV"] = infra_sect.get("dev_server_port")
            flat["PYTHON_VERSION"] = infra_sect.get("python_version")
            flat["NODE_VERSION"] = infra_sect.get("node_version")
            flat["INFRA_TIMEOUT_SHORT"] = infra_sect.get("timeout_short")
            flat["INFRA_TIMEOUT_MEDIUM"] = infra_sect.get("timeout_medium")
            flat["INFRA_TIMEOUT_LONG"] = infra_sect.get("timeout_long")

            # --- Capabilities ---
            cap_sect = identity.get("capabilities", {})
            flat["CAP_RAG_ENABLED"] = str(cap_sect.get("rag_enabled")).lower()
            flat["CAP_WEB_SEARCH"] = str(cap_sect.get("web_search_enabled")).lower()
            flat["CAP_SHELL_ACCESS"] = str(cap_sect.get("shell_access_enabled")).lower()
            flat["CAP_VPN_CONTROL"] = str(cap_sect.get("vpn_control_enabled")).lower()
            flat["CAP_VISION"] = str(cap_sect.get("vision_enabled")).lower()

            # --- Governance ---
            gov_sect = identity.get("governance", {})
            flat["GOV_LICENSE_LABEL"] = gov_sect.get("license_label")
            flat["GOV_RETENTION"] = gov_sect.get("data_retention_policy")
            flat["GOV_PII_REDACTION"] = str(gov_sect.get("pii_redaction")).lower()
            flat["GOV_AUDIT_LOGGING"] = str(gov_sect.get("audit_logging")).lower()
            flat["GOV_COMPLIANCE"] = ", ".join(gov_sect.get("compliance_standards", []))
            flat["GOV_DISCLAIMER"] = gov_sect.get("legal_disclaimer")
            flat["LICENSE_SERVER_URL"] = gov_sect.get("license_server_url")
            flat["VERIFICATION_PUB_KEY"] = gov_sect.get("verification_pub_key")
            flat["ISOLATED_PATHS"] = ",".join(gov_sect.get("isolated_paths", []))

            # --- Release ---
            rel_sect = identity.get("release", {})
            flat["COPYRIGHT_YEAR"] = rel_sect.get("copyright_year")

    # 1.5. Check for Encrypted Secrets Bundle (CI/CD Injection)
    # This allows passing the entire secrets.yaml as a Base64 string in MYTH_SECRETS_BUNDLE
    bundle_b64 = os.environ.get("MYTH_SECRETS_BUNDLE")
    if bundle_b64:
        try:
            # Clean possible whitespace/newlines from variable
            bundle_b64 = bundle_b64.strip()
            decoded = base64.b64decode(bundle_b64).decode("utf-8")
            secrets_data = yaml.safe_load(decoded)

            if secrets_data:
                print(
                    "🔒 [GOVERNANCE] Decrypted Secret Bundle found in memory. Injecting..."
                )

                # Flatten the bundle into the flat dictionary
                # We prefix with SECRET_ to allow targeted injection
                def _flatten_recursive(data, prefix="SECRET_"):
                    for k, v in data.items():
                        full_key = f"{prefix}{k.upper()}"
                        if isinstance(v, dict):
                            _flatten_recursive(v, full_key + "_")
                        elif isinstance(v, list):
                            # For lists (like keys), we just provide the first one as default if requested,
                            # but usually we want to preserve the whole structure for the final yaml.
                            # So we also store the raw values if needed.
                            flat[full_key] = str(v)
                        else:
                            flat[full_key] = str(v)

                _flatten_recursive(secrets_data)

                # Special Case: If the bundle is meant to OVERWRITE the final secrets.yaml,
                # we can flag it to the engine.
                flat["HAS_SECRETS_BUNDLE"] = "true"
                flat["RAW_SECRETS_DATA"] = decoded  # Store the full yaml string
        except Exception as e:
            print(f"❌ [GOVERNANCE] Failed to decode secrets bundle: {e}")

    # 2. Load Packaging Meta (Secondary/Specific)
    if os.path.exists(META_PATH):
        with open(META_PATH, "r", encoding="utf-8") as f:
            meta = json.load(f)

            # Merit: identity.yaml (already in flat) > meta.json
            proj = meta.get("project", {})
            for k, v in proj.items():
                uk = k.upper()
                if not flat.get(uk):
                    flat[uk] = v

            org = meta.get("organization", {})
            for k, v in org.items():
                uk = k.upper()
                if uk == "NAME":
                    if not flat.get("ORG"):
                        flat["ORG"] = v
                    if not flat.get("ORG_NAME"):
                        flat["ORG_NAME"] = v
                else:
                    if not flat.get(uk):
                        flat[uk] = v

            # Specific mappings for required keys
            repo = meta.get("repository", {})
            flat["REPO_URL"] = repo.get("url")
            flat["ISSUES_URL"] = repo.get("issues")
            flat["LICENSE_URL"] = repo.get("license_url")

            lic = meta.get("license", {})
            flat["LICENSE"] = lic.get("spdx")
            flat["LICENSE_CUSTOM"] = lic.get("custom")
            if not flat.get("COPYRIGHT_YEAR"):
                flat["COPYRIGHT_YEAR"] = lic.get("copyright_year")

            for k, v in meta.get("artifacts", {}).items():
                flat[f"ARTIFACT_{k.upper()}"] = v

            flat["ARCHITECTURES"] = " ".join(meta.get("architectures", []))

    # 3. Fallback to pyproject.toml ONLY if version is still missing
    if not flat.get("VERSION") and os.path.exists(PYPROJECT_PATH):
        version = _read_version_from_pyproject(PYPROJECT_PATH)
        if version:
            flat["VERSION"] = version

    # Final derived field overrides
    if flat.get("CODENAME"):
        flat["PROJECT_LOWER"] = flat["CODENAME"].lower()

    _compute_derived_fields(flat)
    return flat


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _read_version_from_pyproject(path: str) -> str:
    """
    Extract the version string from pyproject.toml without requiring
    any third-party TOML library (works on Python 3.10 where tomllib
    may not exist).
    """
    if not os.path.exists(path):
        return ""
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            m = re.match(r'^version\s*=\s*"([^"]+)"', line.strip())
            if m:
                return m.group(1)
    return ""


def _flatten_meta(meta: dict) -> dict[str, str]:
    """
    Flatten the structured meta.json into a single dict of
    UPPER_CASE keys → string values suitable for {{KEY}} replacement.

    Mapping:
        project.name           → PROJECT_NAME / NAME
        project.codename       → PROJECT_LOWER / CODENAME
        project.description    → DESCRIPTION
        project.short_description → SHORT_DESCRIPTION
        project.min_python     → MIN_PYTHON
        organization.name      → ORG / ORG_NAME
        organization.display_name → ORG_DISPLAY
        organization.reverse_domain → REVERSE_DOMAIN
        organization.homepage  → HOMEPAGE
        maintainer.name        → AUTHOR
        maintainer.email       → EMAIL
        repository.url         → REPO_URL
        repository.issues      → ISSUES_URL
        repository.license_url → LICENSE_URL
        license.spdx           → LICENSE
        license.custom         → LICENSE_CUSTOM
        license.copyright_year → COPYRIGHT_YEAR
        artifacts.*            → ARTIFACT_DEB, ARTIFACT_RPM, etc.
    """
    flat: dict[str, str] = {}

    # --- Project ---
    proj = meta.get("project", {})
    flat["NAME"] = proj.get("name", "")
    flat["PROJECT_NAME"] = flat["NAME"]
    flat["CODENAME"] = proj.get("codename", "")
    flat["PROJECT_LOWER"] = flat["CODENAME"]
    flat["DESCRIPTION"] = proj.get("description", "")
    flat["SHORT_DESCRIPTION"] = proj.get("short_description", "")
    flat["MIN_PYTHON"] = proj.get("min_python", "3.10")
    flat["KEYWORDS"] = ", ".join(proj.get("keywords", []))

    # --- Organization ---
    org = meta.get("organization", {})
    flat["ORG"] = org.get("name", "")
    flat["ORG_NAME"] = flat["ORG"]
    flat["ORG_DISPLAY"] = org.get("display_name", flat["ORG"])
    flat["ORG_LOWER"] = org.get(
        "org_lower", org.get("name", "").lower().replace(" ", "-")
    )
    flat["REVERSE_DOMAIN"] = org.get("reverse_domain", "")
    flat["HOMEPAGE"] = org.get("homepage", "")

    # --- Maintainer ---
    maint = meta.get("maintainer", {})
    flat["AUTHOR"] = maint.get("name", "")
    flat["EMAIL"] = maint.get("email", "")

    # --- Repository ---
    repo = meta.get("repository", {})
    flat["REPO_URL"] = repo.get("url", "")
    flat["REPO_NAME"] = (
        flat["REPO_URL"].rstrip("/").rsplit("/", 1)[-1] if flat["REPO_URL"] else ""
    )
    flat["ISSUES_URL"] = repo.get("issues", "")
    flat["LICENSE_URL"] = repo.get("license_url", "")

    # --- License ---
    lic = meta.get("license", {})
    flat["LICENSE"] = lic.get("spdx", "")
    flat["LICENSE_CUSTOM"] = lic.get("custom", "")
    flat["COPYRIGHT_YEAR"] = lic.get("copyright_year", str(datetime.date.today().year))

    # --- Artifacts ---
    for key, val in meta.get("artifacts", {}).items():
        flat[f"ARTIFACT_{key.upper()}"] = val

    # --- Architectures ---
    flat["ARCHITECTURES"] = " ".join(meta.get("architectures", []))

    return flat


def _compute_derived_fields(flat: dict[str, str]) -> None:
    """
    Compute derived/convenience fields that templates frequently need.
    These are injected after the primary flatten so they can reference
    each other.
    """
    version = flat.get("VERSION", "0.0.0")

    # Case-sensitive derivations
    for key in ["NAME", "CODENAME", "AUTHOR", "ORG", "ORG_NAME"]:
        val = flat.get(key)
        if val:
            flat[f"{key}_LOWER"] = val.lower().replace(" ", "-")
            flat[f"{key}_UPPER"] = val.upper()

    # Special case: PROJECT_LOWER is often expected to be the codename
    if flat.get("CODENAME"):
        flat["PROJECT_LOWER"] = flat["CODENAME"].lower().replace(" ", "-")
        flat["PROJECT_UPPER"] = flat["CODENAME"].upper()
        # Snake-case variant for Rust/Cargo (hyphens are illegal in lib target names)
        flat["CODENAME_SNAKE"] = (
            flat["CODENAME"].lower().replace("-", "_").replace(" ", "_")
        )

    # Organization specific derivations
    if flat.get("ORG"):
        flat["ORG_SLUG"] = flat["ORG"].lower().replace(" ", "-")
        if not flat.get("REVERSE_DOMAIN"):
            # Default to com.slug.name
            flat["REVERSE_DOMAIN"] = (
                f"com.{flat['ORG_SLUG']}.{flat.get('NAME_LOWER', 'app')}"
            )

    # Year shortcut
    flat["YEAR"] = str(datetime.date.today().year)
    if not flat.get("COPYRIGHT_YEAR"):
        flat["COPYRIGHT_YEAR"] = flat["YEAR"]

    # Maintainer line (RPM-style)
    flat["MAINTAINER_LINE"] = f"{flat.get('AUTHOR', '')} <{flat.get('EMAIL', '')}>"

    # Release and Source URLs
    if flat.get("REPO_URL"):
        repo_url = flat["REPO_URL"].rstrip("/")
        flat["RELEASE_URL"] = f"{repo_url}/releases/download/v{version}"
        flat["SOURCE_URL"] = f"{repo_url}/archive/v{version}.tar.gz"

    # Common artifact filenames (with version baked in)
    for key in list(flat.keys()):
        if key.startswith("ARTIFACT_"):
            # If the artifact string itself has {{VERSION}}, replace it NOW
            # so it's fully hydrated for templates.
            flat[key] = flat[key].replace("{{VERSION}}", version)


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------
REQUIRED_KEYS = [
    "VERSION",
    "NAME",
    "DESCRIPTION",
    "SHORT_DESCRIPTION",
    "ORG",
    "HOMEPAGE",
    "AUTHOR",
    "EMAIL",
    "REPO_URL",
    "LICENSE",
]


def _validate(flat: dict[str, str]) -> list[str]:
    """Return a list of validation errors (empty = OK)."""
    errors: list[str] = []
    for key in REQUIRED_KEYS:
        val = flat.get(key, "")
        if not val:
            errors.append(f"Missing required key: {key}")
    # Version sanity
    version = flat.get("VERSION", "")
    if version and not re.match(r"^\d+\.\d+\.\d+", version):
        errors.append(f"VERSION '{version}' does not look like semver (x.y.z)")
    return errors


# ---------------------------------------------------------------------------
# Core engine
# ---------------------------------------------------------------------------
def hydrate_manifests(
    *, check_only: bool = False, validate_only: bool = False
) -> bool:
    # ---- Load and Flatten Metadata ----
    flat = load_metadata()

    # ---- Validate ----
    errors = _validate(flat)
    if errors:
        for e in errors:
            print(f"❌ Validation: {e}")
        return False
    print("Metadata validated")

    if validate_only:
        print("\n📋 Available template placeholders:")
        for k in sorted(flat.keys()):
            val = str(flat.get(k, ""))
            print(f"   {{{{{k}}}}} = {val[:80]}{'…' if len(val) > 80 else ''}")
        return True

    # ---- Discover templates ----
    template_files: list[str] = []

    if not os.path.exists(TEMPLATES_DIR):
        print(f"ℹ️  Templates directory not found: {TEMPLATES_DIR}")
        return True

    print(f"🔍 Searching for templates in {TEMPLATES_DIR}...")
    for root, dirs, files in os.walk(TEMPLATES_DIR):
        for fname in files:
            if fname.endswith(".template"):
                template_files.append(os.path.join(root, fname))
    template_files.sort()

    if not template_files:
        print("ℹ️  No templates found to hydrate.")
        return True

    print(f"🚀 Hydrating {len(template_files)} templates...\n")

    # Add governance templates (templates/governance -> governance/)
    gov_templates = []
    GOV_TEMPLATES_DIR = os.path.join(TEMPLATES_DIR, "governance")
    if os.path.exists(GOV_TEMPLATES_DIR):
        print(f"🔍 Searching for templates in {GOV_TEMPLATES_DIR}...")
        for root, dirs, files in os.walk(GOV_TEMPLATES_DIR):
            for fname in files:
                if fname.endswith(".template"):
                    gov_templates.append(os.path.join(root, fname))

    # Revised strategy: Combine lists and use intelligent output path resolution
    all_templates = []

    # 1. Project Templates (templates/ -> PROJECT_ROOT/)
    # Exclude templates/governance since we handle it separately
    for t in template_files:
        if "templates\\governance" in t or "templates/governance" in t:
            continue
        rel = os.path.relpath(t, TEMPLATES_DIR)
        out = os.path.join(PROJECT_ROOT, rel.replace(".template", ""))
        all_templates.append((t, out))

    # 2. Governance Templates (templates/governance/ -> governance/)
    for t in gov_templates:
        rel = os.path.relpath(t, GOV_TEMPLATES_DIR)
        out = os.path.join(GOVERNANCE_DIR, rel.replace(".template", ""))
        all_templates.append((t, out))

    print(f"[INFO] Hydrating {len(all_templates)} templates...\n")

    # ---- Hydrate ----
    warnings: list[str] = []
    drifted: list[str] = []
    skipped: list[str] = []
    success = True

    for template_path, output_path in all_templates:
        # ---- Resolve Placeholders in Paths (NEW: Dynamic Path Support) ----
        # This allows templates like templates/{{CODENAME}}_utils/ to be hydrated correctly
        for k, v in flat.items():
            placeholder = f"{{{{{k}}}}}"
            if placeholder in output_path:
                output_path = output_path.replace(placeholder, str(v))

        rel_output = os.path.relpath(output_path, PROJECT_ROOT)

        with open(template_path, "r", encoding="utf-8") as f:
            content = f.read()

        file_warnings: list[str] = []

        def replace_match(match: re.Match) -> str:
            key = match.group(1).upper()
            return str(flat.get(key, ""))

        hydrated = re.sub(r"\{\{([A-Za-z0-9_]+)\}\}", replace_match, content)

        # --- Baseline Identity Refactoring (Clean Syntax Support) ---
        # If CODENAME is not 'myth', we automatically refactor baseline identifiers
        # like 'myth_utils' or 'myth_config' to match the active identity.
        # This keeps templates as valid, statically-analysable Python/JS.
        current_codename = flat.get("CODENAME", "myth").lower()
        if current_codename != "myth":
            hydrated = re.sub(
                r"\bmyth_config\b", f"{current_codename}_config", hydrated
            )
            hydrated = re.sub(r"\bmyth_utils\b", f"{current_codename}_utils", hydrated)
            # Handle remaining [MYTH] or myth_ strings in JS/Rust that might have been hit
            # as whole words but aren't explicitly templated.
            hydrated = re.sub(r"\bMYTH\b", flat.get("NAME", "MYTH"), hydrated)

        # SECURITY: If we have a RAW_SECRETS_DATA bundle and the target is secrets.yaml,
        # we bypass the template hydration and just write the bundle.
        if flat.get("HAS_SECRETS_BUNDLE") == "true" and rel_output.endswith(
            "secrets.yaml"
        ):
            hydrated = flat.get("RAW_SECRETS_DATA")
            print(
                f"[INFO] [PACKAGING] Bypassed template for {rel_output} -> Injecting raw bundle."
            )

        if file_warnings:
            warnings.extend(file_warnings)

        if check_only:
            is_isolated = False
            isolated_str = flat.get("ISOLATED_PATHS", "")
            if isolated_str:
                isolated_list = [
                    p.strip() for p in isolated_str.split(",") if p.strip()
                ]
                is_isolated = any(
                    rel_output.startswith(p)
                    or rel_output.startswith(p.replace("/", os.sep))
                    for p in isolated_list
                )

            if not os.path.exists(output_path):
                if is_isolated:
                    print(f"[INFO] ISOLATED: {rel_output} (Skipping validation)")
                    continue
                print(f"[FAIL] MISSING:  {rel_output}")
                drifted.append(rel_output)
                success = False
                continue
            with open(output_path, "r", encoding="utf-8") as f:
                current = f.read()
            if current != hydrated:
                if is_isolated:
                    print(f"[INFO] ISOLATED-DRIFT: {rel_output} (Skipping validation)")
                    continue
                print(f"[FAIL] DRIFTED:  {rel_output}")
                drifted.append(rel_output)
                success = False
            else:
                print(f"[PASS] IN SYNC:  {rel_output}")
        else:
            # SAFETY GUARDRAIL: Check for drift before overwriting
            if os.path.exists(output_path):
                with open(output_path, "r", encoding="utf-8") as f:
                    current = f.read()
                if current != hydrated:
                    print(
                        "    [SKIP] SKIPPING to prevent data loss. Please update the template or manually sync."
                    )
                    skipped.append(rel_output)
                    continue

            # Ensure parent directories exist for dynamic paths
            os.makedirs(os.path.dirname(output_path), exist_ok=True)
            with open(output_path, "w", encoding="utf-8", newline="\n") as f:
                f.write(hydrated)
            print(f"[PASS] Generated: {rel_output}")

    # ---- Summary ----
    print(f"\n{'-' * 50}")
    print("Summary")
    print(f"   Templates:  {len(template_files)}")
    print(f"   Version:    {flat['VERSION']}")
    print(f"   Warnings:   {len(warnings)}")
    if check_only and drifted:
        print(f"   Drifted:    {len(drifted)}")
    if not check_only and skipped:
        print(f"   Skipped:    {len(skipped)} (Manual changes detected)")
    print(f"{'-' * 50}")

    if warnings:
        print("\n[WARN] Warnings:")
        for w in warnings:
            print(w)

    return success


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def _run_watch():
    """Watch identity.yaml and re-run hydration on change."""
    try:
        from watchfiles import watch
    except ImportError:
        print("[FAIL] Error: 'watchfiles' package is required for --watch mode.")
        print("   Run: uv pip install watchfiles")
        sys.exit(1)

    print(f"[INFO] Watching {IDENTITY_PATH} and {TEMPLATES_DIR} for changes...")
    # Initial run
    hydrate_manifests()

    for changes in watch(IDENTITY_PATH, TEMPLATES_DIR):
        # changes is a set of (Change, path) tuples
        print("\n[WARN] Change detected. Re-hydrating...")
        hydrate_manifests()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="MYTH Packaging Manifest Hydration Engine",
        epilog="Run without arguments to generate all manifests from templates.",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="CI mode: verify manifests are in sync (no writes)",
    )
    parser.add_argument(
        "--validate",
        action="store_true",
        help="Validate meta.json and list available placeholders",
    )
    parser.add_argument(
        "--watch", action="store_true", help="Watch identity.yaml and sync in real-time"
    )
    args = parser.parse_args()

    if args.watch:
        _run_watch()
    else:
        ok = hydrate_manifests(
            check_only=args.check, validate_only=args.validate
        )
        if ok:
            print("\n[INFO] Done.")
            sys.exit(0)
        else:
            print("\n[FAIL] Failed.")
            sys.exit(1)
