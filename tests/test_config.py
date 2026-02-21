"""
test_config.py — Test configuration loading and validation.
=============================================================
Tests: ConfigurationManager, agent_manifest.yaml parsing,
       Pydantic model validation, secrets.yaml, settings.json
"""

import json
import os
import sys
import time
import traceback

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from conftest import PROJECT_ROOT, C, ResultTracker, Status, safe_import


def run(tracker: ResultTracker = None):
    if tracker is None:
        tracker = ResultTracker()

    tracker.begin_module("Configuration")
    print(C.header("CONFIGURATION & MANIFESTS"))

    # --- myth_config ---
    print(f"\n  {C.CYAN}{C.BOLD}▸ myth_config{C.RESET}")
    start = time.time()
    mod, err = safe_import("myth_config")
    elapsed = (time.time() - start) * 1000
    if mod:
        tracker.record("import myth_config", Status.PASS, elapsed)
        # Check config object
        if hasattr(mod, "config"):
            tracker.record("myth_config.config exists", Status.PASS, 0)
        else:
            tracker.record("myth_config.config missing", Status.FAIL, 0)
        if hasattr(mod, "load_dotenv"):
            tracker.record("myth_config.load_dotenv exists", Status.PASS, 0)
        else:
            tracker.record("myth_config.load_dotenv missing", Status.FAIL, 0)
    else:
        tracker.record("import myth_config", Status.FAIL, elapsed, error=err)

    # --- config_loader ---
    print(f"\n  {C.CYAN}{C.BOLD}▸ config_loader{C.RESET}")
    start = time.time()
    cl_mod, err = safe_import("config_loader")
    elapsed = (time.time() - start) * 1000
    if cl_mod:
        tracker.record("import config_loader", Status.PASS, elapsed)
    else:
        tracker.record("import config_loader", Status.FAIL, elapsed, error=err)
        tracker.end_module()
        return tracker

    # Check ConfigurationManager
    try:
        cm_cls = cl_mod.ConfigurationManager
        tracker.record("ConfigurationManager class exists", Status.PASS, 0)

        # Singleton pattern
        cm1 = cm_cls()
        cm2 = cm_cls()
        if cm1 is cm2:
            tracker.record("ConfigurationManager singleton works", Status.PASS, 0)
        else:
            tracker.record("ConfigurationManager singleton broken", Status.FAIL, 0)
    except Exception:
        tracker.record(
            "ConfigurationManager", Status.FAIL, 0, error=traceback.format_exc()
        )

    # Check Pydantic models
    pydantic_models = [
        "AgentConfig",
        "RuntimeConfig",
        "CreatorConfig",
        "IdentityConfig",
        "PromptsConfig",
        "ModelsConfig",
        "EmbeddingsConfig",
        "HyperparametersConfig",
        "ReliabilityConfig",
        "TimeoutPolicy",
        "RetryPolicy",
        "CircuitBreakerConfig",
        "CapabilitiesConfig",
        "ResourceControlConfig",
        "SessionGovernanceConfig",
        "GovernanceConfig",
        "SecurityConfig",
        "ObservabilityConfig",
        "RoleParams",
    ]
    print(f"\n  {C.CYAN}{C.BOLD}▸ Pydantic Config Models{C.RESET}")
    for model_name in pydantic_models:
        if hasattr(cl_mod, model_name):
            cls = getattr(cl_mod, model_name)
            if isinstance(cls, type):
                tracker.record(f"{model_name} class exists", Status.PASS, 0)
            else:
                tracker.record(f"{model_name} is not a class", Status.WARN, 0)
        else:
            tracker.record(f"{model_name} NOT FOUND", Status.FAIL, 0)

    # --- Load agent_manifest.yaml ---
    print(f"\n  {C.CYAN}{C.BOLD}▸ agent_manifest.yaml{C.RESET}")
    manifest_path = os.path.join(PROJECT_ROOT, "governance", "agent_manifest.yaml")
    try:
        import yaml

        start = time.time()
        with open(manifest_path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
        elapsed = (time.time() - start) * 1000
        assert isinstance(data, dict), f"Expected dict, got {type(data)}"
        tracker.record(
            f"agent_manifest.yaml parsed ({len(data)} top-level keys)",
            Status.PASS,
            elapsed,
        )

        # Validate against ConfigurationManager
        try:
            start = time.time()
            cm = cl_mod.ConfigurationManager()
            cm.load_config(manifest_path)
            elapsed = (time.time() - start) * 1000
            tracker.record(
                "ConfigurationManager.load_config() succeeded", Status.PASS, elapsed
            )

            # Verify the config object
            config = cm.config
            assert config.identity.name, "identity.name is empty"
            tracker.record(
                f"Config identity: {config.identity.name} v{config.identity.version}",
                Status.PASS,
                0,
            )
            assert config.models.router, "models.router is empty"
            tracker.record(
                f"Config router model: {config.models.router}", Status.PASS, 0
            )
        except Exception:
            tracker.record(
                "ConfigurationManager.load_config()",
                Status.FAIL,
                0,
                error=traceback.format_exc(),
            )

    except FileNotFoundError:
        tracker.record("agent_manifest.yaml NOT FOUND", Status.FAIL, 0)
    except Exception:
        tracker.record(
            "agent_manifest.yaml parse", Status.FAIL, 0, error=traceback.format_exc()
        )

    # --- secrets.yaml ---
    print(f"\n  {C.CYAN}{C.BOLD}▸ secrets.yaml{C.RESET}")
    secrets_path = os.path.join(PROJECT_ROOT, "secrets.yaml")
    try:
        import yaml

        start = time.time()
        with open(secrets_path, "r", encoding="utf-8") as f:
            secrets = yaml.safe_load(f)
        elapsed = (time.time() - start) * 1000
        assert isinstance(secrets, dict), f"Expected dict, got {type(secrets)}"
        tracker.record(
            f"secrets.yaml parsed ({len(secrets)} keys)", Status.PASS, elapsed
        )
    except FileNotFoundError:
        tracker.record("secrets.yaml NOT FOUND", Status.SKIP, 0)
    except Exception:
        tracker.record(
            "secrets.yaml parse", Status.FAIL, 0, error=traceback.format_exc()
        )

    # --- settings.json ---
    print(f"\n  {C.CYAN}{C.BOLD}▸ settings.json{C.RESET}")
    settings_path = os.path.join(PROJECT_ROOT, "settings.json")
    try:
        start = time.time()
        with open(settings_path, "r", encoding="utf-8") as f:
            settings = json.load(f)
        elapsed = (time.time() - start) * 1000
        assert isinstance(settings, dict), f"Expected dict, got {type(settings)}"
        tracker.record(
            f"settings.json parsed ({len(settings)} keys)", Status.PASS, elapsed
        )
    except FileNotFoundError:
        tracker.record("settings.json NOT FOUND", Status.SKIP, 0)
    except Exception:
        tracker.record(
            "settings.json parse", Status.FAIL, 0, error=traceback.format_exc()
        )

    tracker.end_module()

    return tracker


if __name__ == "__main__":
    t = run()
    t.print_summary()
    sys.exit(0 if t.all_passed else 1)
