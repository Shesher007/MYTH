"""
Sovereign Config Manager (Peak Industrial Grade)
==============================================
Handles structured YAML secrets with automatic API key rotation and shifting.
Replaces the legacy .env system for mission-critical operations.
"""

import logging
import os
import platform
import random
import threading
import warnings
from typing import Any, Dict, Optional, Union

import yaml

# Industry Grade: Suppress noisy third-party SyntaxWarnings (e.g., from ropper)
warnings.filterwarnings("ignore", category=SyntaxWarning)

# =============================================================================
# Logging Configuration
# =============================================================================
logger = logging.getLogger("SOVEREIGN_CONFIG")


class SovereignConfig:
    """
    Industrial-grade configuration manager with key rotation capabilities.
    """

    _instance = None
    _lock = threading.Lock()

    def __init__(self, config_path: str = "secrets.yaml"):
        self.config_path = config_path
        self.secrets: Dict[str, Any] = {}
        self._key_indices: Dict[str, int] = {}  # Provider -> Current Index
        self._failed_keys: Dict[str, set] = {}  # Provider -> Set of failing keys

        # OS Detection (Industrial Grade - High Performance)
        self.os_type = platform.system().lower()
        self.is_windows = self.os_type == "windows"
        self.is_wsl = False

        if self.os_type == "linux":
            # Direct check for WSL without platform.uname() which can be slow
            try:
                if os.path.exists("/proc/version"):
                    with open("/proc/version", "r") as f:
                        if "microsoft" in f.read().lower():
                            self.is_wsl = True
            except Exception:
                pass

        self._provider_map = {
            "shodan": "shodan",
            "censys": "censys",
            "securitytrails": "securitytrails",
            "st": "securitytrails",
            "pd": "project_discovery",
            "vt": "virustotal",
            "virustotal": "virustotal",
            "hibp": "hibp_breach",
            "hunter": "hunter_io",
            "mistral": "mistral",
            "nvidia": "nvidia",
            "google": "google_ai_studio",
            "gemini": "google_ai_studio",
            "google_ai_studio": "google_ai_studio",
            "burp": "burp_suite",
        }

        self.identity: Dict[str, Any] = {}
        self.load_identity()
        self.load()

    def load_identity(self):
        """Loads project identity from identity.yaml."""
        from myth_utils.paths import get_resource_path

        ident_path = get_resource_path("governance/identity.yaml")
        if not os.path.exists(ident_path):
            ident_path = get_resource_path("identity.yaml")

        if os.path.exists(ident_path):
            try:
                with open(ident_path, "r", encoding="utf-8") as f:
                    self.identity = yaml.safe_load(f) or {}
            except Exception as e:
                logger.error(f"❌ Failed to load identity: {e}")
        else:
            logger.warning(f"⚠️ Identity file missing: {ident_path}")

    @classmethod
    def get_instance(cls) -> "SovereignConfig":
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    import shutil

                    from myth_utils.paths import (
                        get_app_data_path,
                        get_resource_path,
                        is_frozen,
                    )

                    # Ensure models directory exists in AppData (Industrial persistence)
                    models_dir = get_app_data_path("models")
                    if not os.path.exists(models_dir):
                        os.makedirs(models_dir, exist_ok=True)
                    os.environ["MYTH_MODELS_DIR"] = models_dir

                    config_path = ""
                    appdata_secrets = get_app_data_path("secrets.yaml")
                    local_secrets = get_resource_path("secrets.yaml")

                    # Priority Logic (Industrial Grade)
                    # 1. If NOT frozen (Dev Mode), prioritize LOCAL secrets if it exists and is populated
                    if not is_frozen() and os.path.exists(local_secrets):
                        # Simple check if file has actual keys or is just the template
                        with open(local_secrets, "r", encoding="utf-8") as f:
                            content = f.read()
                            if (
                                "nvapi-" in content or "G8p3" in content
                            ):  # Heuristic for 'populated'
                                config_path = local_secrets
                                logger.info(
                                    f"🧪 [CONFIG] Dev Mode: Prioritizing local secrets at {local_secrets}"
                                )

                    # 2. AppData secrets (User persistence)
                    if not config_path and os.path.exists(appdata_secrets):
                        config_path = appdata_secrets
                        logger.info(
                            f"🔑 [CONFIG] Using persisted secrets at {appdata_secrets}"
                        )

                    # 3. Fallback to local (Prod/Frozen or first run)
                    if not config_path:
                        if os.path.exists(local_secrets):
                            config_path = local_secrets
                        else:
                            # 4. First-run — copy template to AppData
                            template_path = get_resource_path("secrets.template.yaml")
                            if os.path.exists(template_path):
                                try:
                                    shutil.copy2(template_path, appdata_secrets)
                                    logger.info(
                                        f"🔑 [INIT] Created initial secrets.yaml from template at: {appdata_secrets}"
                                    )
                                except Exception as e:
                                    logger.warning(
                                        f"⚠️ Could not copy secrets template: {e}"
                                    )
                            config_path = appdata_secrets

                    cls._instance = cls(config_path)
        return cls._instance

    def load(self):
        """Loads configuration from secrets.yaml."""
        if not os.path.exists(self.config_path):
            logger.warning(f"⚠️ Configuration file missing: {self.config_path}")
            logger.warning(
                "⚠️ Run the app once to auto-create secrets.yaml, then populate your API keys."
            )
            return

        try:
            logger.debug(f"Loading secrets from {self.config_path}")
            with open(self.config_path, "r", encoding="utf-8") as f:
                self.secrets = yaml.safe_load(f) or {}
            logger.info("✅ Industrial Secrets Loaded.")
            self._sync_to_env()
        except Exception as e:
            logger.error(f"❌ Failed to load secrets: {e}")

    def _sync_to_env(self):
        """Synchronizes YAML values to environment variables for legacy compatibility."""

        # 1. AI Providers (Primary Key only for legacy)
        providers = self.secrets.get("ai_providers", {})
        for provider, data in providers.items():
            keys = data.get("keys", [])
            if keys:
                env_key = f"{provider.upper()}_API_KEY"
                os.environ[env_key] = str(keys[0])

            if "base_url" in data:
                env_key = f"{provider.upper()}_API_BASE"
                os.environ[env_key] = str(data["base_url"])

        # 2. Recon
        recon = self.secrets.get("recon", {})
        for k, v in recon.items():
            if isinstance(v, dict):
                # Check for pairs first (Industrial Grade)
                pairs = v.get("pairs", [])
                if pairs and isinstance(pairs[0], dict):
                    for pk, pv in pairs[0].items():
                        os.environ[f"{k.upper()}_{pk.upper()}"] = str(pv)

                if "keys" in v and v["keys"]:
                    os.environ[f"{k.upper()}_API_KEY"] = str(v["keys"][0])
                for sub_k, sub_v in v.items():
                    if sub_k not in ["keys", "pairs"]:
                        os.environ[f"{k.upper()}_{sub_k.upper()}"] = str(sub_v)
            else:
                os.environ[f"{k.upper()}_API_KEY"] = str(v)

        # 3. Threat Intel
        intel = self.secrets.get("threat_intel", {})
        for k, v in intel.items():
            if isinstance(v, dict):
                pairs = v.get("pairs", [])
                if pairs and isinstance(pairs[0], dict):
                    for pk, pv in pairs[0].items():
                        os.environ[f"{k.upper()}_{pk.upper()}"] = str(pv)
                if "keys" in v and v["keys"]:
                    os.environ[f"{k.upper()}_API_KEY"] = str(v["keys"][0])
            elif not isinstance(v, dict):
                os.environ[f"{k.upper()}_API_KEY"] = str(v)

        # 4. Web Search / Services
        web = self.secrets.get("web_search", {})
        for k, v in web.items():
            if isinstance(v, dict):
                pairs = v.get("pairs", [])
                if pairs and isinstance(pairs[0], dict):
                    for pk, pv in pairs[0].items():
                        os.environ[f"{k.upper()}_{pk.upper()}"] = str(pv)

                if "keys" in v and v["keys"]:
                    os.environ[f"{k.upper()}_API_KEY"] = str(v["keys"][0])
                if "tokens" in v and v["tokens"]:
                    os.environ[f"{k.upper()}_TOKEN"] = str(v["tokens"][0])
                for sub_k, sub_v in v.items():
                    if sub_k not in ["keys", "tokens", "pairs"]:
                        os.environ[f"{k.upper()}_{sub_k.upper()}"] = str(sub_v)
            else:
                os.environ[f"{k.upper()}_API_KEY"] = str(v)

        # 5. GitHub
        gh = self.secrets.get("github", {})
        if isinstance(gh, dict):
            pairs = gh.get("pairs", [])
            if pairs and isinstance(pairs[0], dict):
                for pk, pv in pairs[0].items():
                    env_name = f"GITHUB_{pk.upper()}"
                    if pk.lower() == "token":
                        env_name = "GITHUB_PERSONAL_ACCESS_TOKEN"
                    os.environ[env_name] = str(pv)

            if "token" in gh:
                os.environ["GITHUB_PERSONAL_ACCESS_TOKEN"] = str(gh["token"])
            if "username" in gh:
                os.environ["GITHUB_USERNAME"] = str(gh["username"])

        # 6. Aether Forge
        af = self.secrets.get("aether_forge", {})
        for k, v in af.items():
            if isinstance(v, dict):
                # Dynamic Key Support for Aether Forge
                keys = v.get("keys", [])
                if keys:
                    os.environ[f"{k.upper()}_API_KEY"] = str(keys[0])

                for sub_k, sub_v in v.items():
                    if sub_k != "keys":
                        os.environ[f"{k.upper()}_{sub_k.upper()}"] = str(sub_v)
            else:
                os.environ[f"{k.upper()}_API_KEY"] = str(v)

        # 7. Environment & Paths (Industrial Grade Dynamic Resolution)
        env_data = self.secrets.get("environment", {})

        # Get defaults based on OS
        defaults = self._get_default_paths()

        # Merge YAML overrides from secrets.yaml if any
        yaml_paths = env_data.get("paths", {})
        final_paths = {**defaults, **{k.upper(): v for k, v in yaml_paths.items()}}

        # Sync to environment
        for k, v in final_paths.items():
            os.environ[k] = str(v)
            # Legacy mapping for pd_tools
            if k == "PD_TOOLS":
                os.environ["PD_TOOLS_PATH"] = str(v)

        # Special Windows Core Path
        if self.is_windows and "SystemRoot" in os.environ:
            os.environ["SYSTEM_ROOT"] = os.environ["SystemRoot"]

    def _get_default_paths(self) -> Dict[str, str]:
        """Calculates default paths dynamically based on the current OS."""
        from myth_utils.paths import get_app_data_path

        home = os.path.expanduser("~")
        paths = {}

        if self.is_windows:
            paths["GOPATH"] = os.path.join(home, "go")
            paths["GOBIN"] = os.path.join(home, "go", "bin")
            paths["PD_TOOLS"] = get_app_data_path("bin")
            paths["NUCLEI_TEMPLATES"] = get_app_data_path(
                "config/project-discovery/nuclei-templates"
            )
            paths["TEMP"] = os.environ.get("TEMP", get_app_data_path("temp"))
        else:
            # Linux / macOS / WSL
            paths["GOPATH"] = os.path.join(home, "go")
            paths["GOBIN"] = os.path.join(home, "go", "bin")
            paths["PD_TOOLS"] = get_app_data_path("bin")
            paths["NUCLEI_TEMPLATES"] = get_app_data_path(
                "config/project-discovery/nuclei-templates"
            )
            paths["TEMP"] = "/tmp"

        return paths

    def get_credentials(
        self, provider: str, rotate: bool = True
    ) -> Optional[Union[str, Dict[str, Any]]]:
        """
        Retrieves API credentials (key or pair) for a provider, respecting rotation.
        Supports single strings, 'keys' lists, 'tokens' lists, or 'pairs' lists.
        """
        # Normalize provider name
        provider_norm = self._provider_map.get(provider.lower(), provider.lower())

        for section_name in [
            "ai_providers",
            "recon",
            "threat_intel",
            "web_search",
            "github",
            "aether_forge",
        ]:
            section = self.secrets.get(section_name, {})
            # Special case for flat github section
            if section_name == "github" and provider_norm == "github":
                data = section
            elif provider_norm in section:
                data = section[provider_norm]
            else:
                continue

            items = []
            strategy = "round-robin"

            if isinstance(data, dict):
                items = data.get("pairs") or data.get("keys") or data.get("tokens")
                strategy = data.get("strategy", "round-robin").lower()

            if not items:
                # Fallback to direct value
                if not isinstance(data, dict):
                    return str(data)
                # If it's a dict but has no rotation lists, it might be a single pair
                if any(
                    k in data
                    for k in [
                        "id",
                        "secret",
                        "key",
                        "token",
                        "api_key",
                        "cse_id",
                        "email",
                        "username",
                    ]
                ):
                    return data
                return None

            with self._lock:
                # Filter out failures
                failed = self._failed_keys.get(provider, set())
                valid_items = []
                for item in items:
                    item_str = (
                        str(item)
                        if not isinstance(item, dict)
                        else str(sorted(item.items()))
                    )
                    if item_str not in failed:
                        valid_items.append(item)

                if not valid_items:
                    logger.warning(
                        f"⚠️ No known-good credentials for {provider}. Resetting failure cache."
                    )
                    self._failed_keys[provider] = set()
                    valid_items = items

                if not rotate:
                    return valid_items[0]

                if strategy == "random":
                    return random.choice(valid_items)
                elif strategy == "failover-only":
                    return valid_items[0]
                else:  # round-robin
                    idx = self._key_indices.get(provider, 0)
                    item = valid_items[idx % len(valid_items)]
                    self._key_indices[provider] = (idx + 1) % len(valid_items)
                    return item

        # Fallback to env
        env_val = os.environ.get(f"{provider.upper()}_API_KEY") or os.environ.get(
            provider.upper()
        )
        return env_val

    def get_api_key(self, provider: str, rotate: bool = True) -> Optional[str]:
        """Backward compatible method that tries to return a single key/token."""
        creds = self.get_credentials(provider, rotate)
        if isinstance(creds, dict):
            # Prioritize standard names
            for k in ["key", "api_key", "token", "secret", "password", "id"]:
                if k in creds:
                    return str(creds[k])
            # Fallback to first value
            return str(next(iter(creds.values())))
        return str(creds) if creds else None

    def invalidate_key(self, provider: str, key: Union[str, Dict[str, Any]]):
        """Marks a credential (string or part of a pair) as failing."""
        with self._lock:
            if provider not in self._failed_keys:
                self._failed_keys[provider] = set()

            # If it's a dict, use normalized string. If it's a string, it might be a sub-key.
            if isinstance(key, dict):
                self._failed_keys[provider].add(str(sorted(key.items())))
            else:
                # If a sub-key is passed, we might need to find the pair containing it
                # For simplicity, we also check if the string matches any part of existing pairs
                self._failed_keys[provider].add(str(key))

                # Check if this string belongs to a pair in rotation
                for section in [
                    "ai_providers",
                    "recon",
                    "threat_intel",
                    "web_search",
                    "github",
                ]:
                    data = self.secrets.get(section, {}).get(provider)
                    if isinstance(data, dict):
                        for list_name in ["pairs", "keys", "tokens"]:
                            items = data.get(list_name, [])
                            for item in items:
                                if isinstance(item, dict) and str(key) in [
                                    str(v) for v in item.values()
                                ]:
                                    self._failed_keys[provider].add(
                                        str(sorted(item.items()))
                                    )

            logger.error(
                f"⚠️ [CONFIG] Credentials invalidated for {provider}. Shifted to next available."
            )

    def get_all(self) -> Dict[str, Any]:
        return self.secrets

    def save(self):
        """Persists the current secrets dictionary back to the config file."""
        with self._lock:
            try:
                # Use yaml.dump with specific settings for industrial readability
                with open(self.config_path, "w", encoding="utf-8") as f:
                    yaml.dump(
                        self.secrets,
                        f,
                        default_flow_style=False,
                        sort_keys=False,
                        allow_unicode=True,
                        indent=2,
                    )
                logger.info(f"✅ [CONFIG] Secrets persisted to {self.config_path}")
                return True
            except Exception as e:
                logger.error(f"❌ [CONFIG] Failed to save secrets: {e}")
                return False

    def update_secrets(self, updates: Dict[str, Any]):
        """
        Deep-merges updates into the active secrets and persists to disk.
        Supports structured updates for known provider sections.
        """
        with self._lock:

            def _deep_update(base, up):
                for k, v in up.items():
                    if isinstance(v, dict) and k in base and isinstance(base[k], dict):
                        _deep_update(base[k], v)
                    else:
                        base[k] = v

            _deep_update(self.secrets, updates)

        # After update, trigger persistence and legacy env sync
        success = self.save()
        if success:
            self._sync_to_env()
        return success


def load_dotenv():
    """Industrial replacement for dotenv.load_dotenv()."""
    SovereignConfig.get_instance()


# Global Instance (Must be at module level for project-wide compatibility)
config = SovereignConfig.get_instance()
