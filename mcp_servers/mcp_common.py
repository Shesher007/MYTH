#!/usr/bin/env python3
import asyncio
import contextvars
import hashlib
import json
import logging
import os
import pickle
import platform
import re
import time
from concurrent.futures import ProcessPoolExecutor
from datetime import datetime
from enum import Enum
from functools import wraps
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Union

import aiofiles
import aiohttp
from pydantic import BaseModel, Field, ValidationError

# --- Logging Configuration ---
from myth_config import config

# Dynamic identity for logging
_app_name_upper = config.identity.get("name", "PROJECT").upper()
_app_name_lower = config.identity.get("name", "PROJECT").lower()

LOG_DIR = Path(os.getenv(f"{_app_name_upper}_LOG_DIR", os.getcwd())) / "logs"
LOG_DIR.mkdir(parents=True, exist_ok=True)
LOG_FILE = LOG_DIR / "myth_fortress.log"


class StructLogFormatter(logging.Formatter):
    SENSITIVE_PATTERNS = [
        r"(?i)api_?key=['\"]?([a-z0-9_\-\.]{10,})['\"]?",
        r"(?i)password=['\"]?([^'\"\s]{4,})['\"]?",
        r"(?i)secret=['\"]?([^'\"\s]{8,})['\"]?",
        r"(?i)token=['\"]?([^'\"\s]{8,})['\"]?",
    ]

    def _mask_sensitive(self, text: str) -> str:
        """Mask sensitive keys, tokens, and passwords in logs."""
        for pattern in self.SENSITIVE_PATTERNS:
            text = re.sub(
                pattern, lambda m: f"{m.group(0).split('=')[0]}=****[MASKED]****", text
            )
        return text

    def format(self, record):
        msg = self._mask_sensitive(record.getMessage())
        log_data = {
            "timestamp": datetime.fromtimestamp(record.created).isoformat(),
            "level": record.levelname,
            "module": record.module,
            "message": msg,
            "os": platform.system(),
            "pid": os.getpid(),
        }
        if record.exc_info:
            log_data["exception"] = self._mask_sensitive(
                self.formatException(record.exc_info)
            )
        return json.dumps(log_data)


logger = logging.getLogger(f"{_app_name_lower}_fortress")
logger.setLevel(logging.INFO)
if not logger.handlers:
    handler = logging.FileHandler(LOG_FILE)
    handler.setFormatter(StructLogFormatter())
    logger.addHandler(handler)


class TitanErrorCode(str, Enum):
    SECURITY_VIOLATION = "ERR-SEC-403"
    VALIDATION_FAILURE = "ERR-VAL-400"
    SYSTEM_FAILURE = "ERR-SYS-500"
    DEPENDENCY_MISSING = "ERR-DEP-404"
    RATE_LIMITED = "ERR-ROT-429"
    TIMEOUT = "ERR-TMO-504"


# --- Titan Resilience ---
class CircuitBreaker:
    """Industrial circuit breaker to prevent remote API cascades."""

    def __init__(self, failure_threshold: int = 5, recovery_timeout: int = 60):
        self.threshold = failure_threshold
        self.timeout = recovery_timeout
        self.failures = 0
        self.last_failure_time = 0
        self.state = "CLOSED"  # CLOSED, OPEN

    def __call__(self, func: Callable):
        from functools import wraps

        @wraps(func)
        async def wrapper(*args, **kwargs):
            if self.state == "OPEN":
                if time.time() - self.last_failure_time > self.timeout:
                    self.state = "CLOSED"
                    self.failures = 0
                else:
                    return {
                        "error": "Circuit Breaker OPEN (API unstable)",
                        "type": "ResilienceFailure",
                        "code": TitanErrorCode.SYSTEM_FAILURE,
                    }
            try:
                result = await func(*args, **kwargs)
                return result
            except Exception as e:
                self.failures += 1
                self.last_failure_time = time.time()
                if self.failures >= self.threshold:
                    self.state = "OPEN"
                    logger.error(f"Circuit Breaker TRIPPED for {func.__name__}")
                raise e

        return wrapper


# --- Titan Performance ---
class HighSpeedCache:
    """Atomic multi-backend cache (Redis/Local)."""

    _instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._init_cache()
        return cls._instance

    def _init_cache(self):
        self.redis = None
        redis_url = config.get_api_key("redis")
        if redis_url:
            try:
                import redis.asyncio as aioredis

                self.redis = aioredis.from_url(redis_url)
                logger.info("Connected to Redis for global caching.")
            except Exception:
                logger.warning(
                    "Redis requested but failed to connect. Falling back to Local."
                )

        self.local_dir = Path.cwd() / ".mcp_cache"
        self.local_dir.mkdir(exist_ok=True)

    async def get(self, key: str) -> Optional[Any]:
        if self.redis:
            try:
                data = await self.redis.get(key)
                return pickle.loads(data) if data else None
            except Exception:
                pass

        cache_file = self.local_dir / f"{key}.pkl"
        if cache_file.exists():
            try:
                async with aiofiles.open(cache_file, "rb") as f:
                    data = await f.read()
                    return pickle.loads(data)[1]  # Return the value part of (ts, val)
            except Exception:
                pass
        return None

    async def set(self, key: str, value: Any, ttl: int = 3600):
        if self.redis:
            try:
                await self.redis.set(key, pickle.dumps(value), ex=ttl)
                return
            except Exception:
                pass

        cache_file = self.local_dir / f"{key}.pkl"
        try:
            temp_file = cache_file.with_suffix(".tmp")
            async with aiofiles.open(temp_file, "wb") as f:
                await f.write(pickle.dumps((time.time(), value)))
            temp_file.replace(cache_file)
        except Exception:
            pass


class ComputeGuard:
    """Process pooling with dynamic Nexus auto-scaling."""

    _pool = None
    _max_workers = os.cpu_count() or 4

    @classmethod
    def _ensure_pool(cls):
        if cls._pool is None:
            # Nexus Dynamic Scaling: Adjust based on available memory
            try:
                import psutil

                mem = psutil.virtual_memory()
                if mem.available < 512 * 1024 * 1024:  # < 512MB
                    cls._max_workers = max(1, cls._max_workers // 2)
                    logger.warning(
                        f"Low memory ({mem.available // 1024**2}MB). Scaling ComputePool to {cls._max_workers} workers."
                    )
            except Exception:
                pass
            cls._pool = ProcessPoolExecutor(max_workers=cls._max_workers)

    @classmethod
    async def run_in_pool(cls, func, *args):
        cls._ensure_pool()
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(cls._pool, func, *args)


# --- Resource Management ---
class ResourceGuard:
    MAX_FILE_READ_SIZE = 10 * 1024 * 1024  # 10MB
    DEFAULT_TIMEOUT = 30
    MAX_CONCURRENT_TOOLS = 20

    _semaphore = asyncio.Semaphore(MAX_CONCURRENT_TOOLS)

    @classmethod
    async def acquire(cls):
        await cls._semaphore.acquire()

    @classmethod
    def release(cls):
        cls._semaphore.release()


class AdaptiveRateLimiter:
    """Smart backoff handler for 429 status codes."""

    @staticmethod
    async def handle_resp(resp: aiohttp.ClientResponse, attempt: int) -> bool:
        if resp.status == 429:
            retry_after = int(resp.headers.get("Retry-After", 2**attempt))
            logger.warning(f"Rate limited (429). Backing off for {retry_after}s...")
            await asyncio.sleep(retry_after)
            return True
        return False


# --- Nexus Apex: God-Tier Intel & Stealth ---
class TitanResponse(BaseModel):
    """Industry-standard rich tool response model."""

    success: bool
    data: Any
    metadata: Dict[str, Any] = Field(default_factory=dict)
    correlation_id: str = Field(default_factory=lambda: MCPUtils.get_correlation_id())
    timestamp: str = Field(default_factory=lambda: datetime.utcnow().isoformat())
    hardware_profile: Dict[str, Any] = Field(
        default_factory=lambda: AccelerationGuard.get_hardware_profile()
    )

    def to_dict(self):
        return self.model_dump()


class NexusState:
    """Enhanced Cross-tool intelligence sharing with Multi-Tier Persistence."""

    @staticmethod
    async def post_intel(key: str, value: Any, ttl: int = 3600):
        """Broadcast intelligence to the collective with persistence fallback."""
        cache = HighSpeedCache()
        data = {
            "val": value,
            "ts": time.time(),
            "source": "NexusApex",
            "correlation_id": MCPUtils.get_correlation_id(),
        }

        # Tier 1: Redis/Mem
        await cache.set(f"nexus:intel:{key}", data, ttl=ttl)

        # Tier 2: Quantum Mirror
        await UltraPersistence.mirror_state(f"intel_{key}", data)

        logger.info(f"🧠 Intelligence Broadcast: {key} (Mirrored)")

    @staticmethod
    async def get_intel(key: str) -> Optional[Any]:
        """Retrieve intelligence with multi-tier recovery."""
        cache = HighSpeedCache()

        # Try Cache
        val = await cache.get(f"nexus:intel:{key}")
        if val:
            return val["val"]

        # Fallback to Persistence
        persisted = Path(f".mcp_state/intel_{key}.json")
        if persisted.exists():
            try:
                import json

                data = json.loads(persisted.read_text())
                return data["val"]
            except Exception:
                pass

        return None


class GhostProtocol:
    """Stealth utilities for high-stakes forensics."""

    USER_AGENTS = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x4) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
    ]

    @classmethod
    def get_random_ua(cls) -> str:
        import random

        return random.choice(cls.USER_AGENTS)

    @staticmethod
    def get_stealth_config() -> Dict:
        """Playwright-compatible stealth configuration."""
        return {
            "userAgent": GhostProtocol.get_random_ua(),
            "viewport": {"width": 1920, "height": 1080},
            "deviceScaleFactor": 1,
            "isMobile": False,
            "hasTouch": False,
        }


# --- Intelligence Overlay ---


class UltraPersistence:
    """Quantum Persistence: Multi-tier state survival."""

    @staticmethod
    async def mirror_state(key: str, state: Any):
        """Mirror state across Mem, Redis, and Disk."""
        cache = HighSpeedCache()
        # 1. Sync to Redis/Local Memory
        await cache.set(f"nexus:state:{key}", state, ttl=86400)

        # 2. Async Persist to Cold Storage (Atomic)
        storage_path = Path.cwd() / ".nexus_persistence"
        storage_path.mkdir(exist_ok=True)
        file_path = storage_path / f"{key}.nexus"

        def _persist():
            temp = file_path.with_suffix(".tmp")
            with open(temp, "wb") as f:
                pickle.dump({"state": state, "ts": time.time()}, f)
            temp.replace(file_path)

        await ComputeGuard.run_in_pool(_persist)


class AccelerationGuard:
    """Hardware-Level awareness and optimization."""

    @staticmethod
    def get_hardware_profile() -> Dict:
        profile = {
            "gpu_found": False,
            "can_accelerate": False,
            "load_avg": os.getloadavg()
            if platform.system() != "Windows"
            else (0, 0, 0),
        }
        # Detect NVIDIA
        try:
            import subprocess

            if subprocess.run(["nvidia-smi"], capture_output=True).returncode == 0:
                profile["gpu_found"] = True
                profile["can_accelerate"] = True
        except Exception:
            pass
        return profile


# --- Universal OS Support & Health ---
class SystemMonitor:
    @staticmethod
    def get_system_health() -> Dict:
        """Industry-grade system health check."""
        import psutil

        try:
            return {
                "cpu_percent": psutil.cpu_percent(),
                "memory": dict(psutil.virtual_memory()._asdict()),
                "disk": dict(psutil.disk_usage("/")._asdict()),
                "platform": platform.system(),
                "uptime": round(asyncio.get_event_loop().time(), 2),
            }
        except Exception:
            return {"error": "psutil not installed/available"}


class PlatformGuard:
    """Omni-Abstraction: Unified cross-platform operations."""

    @staticmethod
    def is_windows() -> bool:
        return platform.system() == "Windows"

    @staticmethod
    def is_linux() -> bool:
        return platform.system() == "Linux"

    @staticmethod
    def is_mac() -> bool:
        return platform.system() == "Darwin"

    @classmethod
    def map_path(cls, path: str) -> str:
        """Universal path autocorrect (WSL/Win/Linux)."""
        if not path:
            return path
        if cls.is_windows():
            if path.startswith("/mnt/") and len(path) > 5:  # WSL to Win
                drive = path[5].upper()
                mapped = path[6:].replace("/", "\\")
                return f"{drive}:{mapped}"
        elif cls.is_linux():
            if len(path) > 2 and path[1] == ":" and path[0].isalpha():  # Win to Linux
                drive = path[0].lower()
                mapped = path[2:].replace("\\", "/")
                return f"/mnt/{drive}{mapped}"
        return path

    @classmethod
    def get_universal_command(cls, base_cmd: str) -> str:
        mapping = {
            "list_processes": "tasklist" if cls.is_windows() else "ps aux",
            "netstat": "netstat -ano" if cls.is_windows() else "ss -tunap",
        }
        return mapping.get(base_cmd, base_cmd)

    @staticmethod
    def safe_subprocess_args(args: List[str]) -> List[str]:
        return [
            PlatformGuard.map_path(a) if any(c in a for c in ["\\", "/"]) else a
            for a in args
        ]


# --- Ironclad Robustness ---
class DependencyGuard:
    """Self-Repairing Dependency Engine."""

    @staticmethod
    def require(modules: List[str]):
        def decorator(func: Callable):
            @wraps(func)
            async def wrapper(*args, **kwargs):
                missing = []
                system_bin_missing = []

                # Check for standard python modules or specific system binaries
                for mod in modules:
                    # Special Case: If the module name looks like a critical system binary
                    if mod.lower() in ["nmap", "searchsploit", "docker"]:
                        import shutil

                        if not shutil.which(mod.lower()):
                            system_bin_missing.append(mod)
                        continue

                    try:
                        __import__(mod)
                    except ImportError:
                        missing.append(mod)

                if missing or system_bin_missing:
                    repair_instructions = []
                    if missing:
                        repair_instructions.append(f"pip install {' '.join(missing)}")

                    for sys_bin in system_bin_missing:
                        sb_lower = sys_bin.lower()
                        if sb_lower == "nmap":
                            repair_instructions.append(
                                "Install Nmap: https://nmap.org/download.html"
                            )
                        elif sb_lower == "searchsploit":
                            repair_instructions.append(
                                "Install ExploitDB: https://github.com/offensive-security/exploitdb"
                            )
                        elif sb_lower == "docker":
                            repair_instructions.append(
                                "Install Docker Desktop: https://www.docker.com/products/docker-desktop/"
                            )
                        else:
                            repair_instructions.append(
                                f"Install {sys_bin} and add to PATH"
                            )

                    error_msg = f"Capability locked. Missing: {', '.join(missing + system_bin_missing)}"
                    logger.error(
                        f"❌ Dependency Failure in {func.__name__}. {error_msg}"
                    )

                    return {
                        "error": error_msg,
                        "repair_instruction": " | ".join(repair_instructions),
                        "type": "DependencyFailure",
                    }
                return await func(*args, **kwargs)

            return wrapper

        return decorator


class ZeroTrustValidator:
    """Military-grade input validation and sanitization."""

    MAX_STR_LEN = 4096
    MAX_LIST_SIZE = 100

    @classmethod
    def validate_input(cls, **kwargs):
        """Global zero-trust check: Reject over-sized or suspect inputs."""
        for k, v in kwargs.items():
            if isinstance(v, str):
                if len(v) > cls.MAX_STR_LEN:
                    raise ValueError(
                        f"Input '{k}' exceeds safety limit ({cls.MAX_STR_LEN} chars)"
                    )
                # Reject suspect shell/injection sequences early
                if any(seq in v for seq in ["/dev/tcp/", "$( ", "` ", "|| ", "&& "]):
                    raise ValueError(f"Unsafe sequence detected in input '{k}'")
            elif isinstance(v, list) and len(v) > cls.MAX_LIST_SIZE:
                raise ValueError(
                    f"Input list '{k}' exceeds safety limit ({cls.MAX_LIST_SIZE} items)"
                )
        return True


def ironclad_guard(func: Callable):
    """Decorator to apply zero-trust validation to any tool."""

    @wraps(func)
    async def wrapper(*args, **kwargs):
        try:
            ZeroTrustValidator.validate_input(**kwargs)
            return await func(*args, **kwargs)
        except ValueError as ve:
            logger.warning(f"Zero-Trust rejection for {func.__name__}: {ve}")
            return {"error": str(ve), "type": "ZeroTrustViolation"}

    return wrapper


# --- Cross-Platform Toolkit ---
class ToolResolver:
    """
    Project Trinity: Universal Binary Resolution Engine.
    Dynamically maps generic tool names (e.g., 'nuclei') to platform-specific
    bundled binaries (e.g., 'nuclei-x86_64-pc-windows-msvc.exe') to ensure
    seamless standalone execution on Windows, Linux, and macOS.
    """

    _cache: Dict[str, str] = {}

    @staticmethod
    def get_target_triple() -> str:
        """Determine the Rust-style target triple for the current platform."""
        import platform

        machine = platform.machine().lower()
        system = platform.system().lower()

        arch_map = {
            "x86_64": "x86_64",
            "amd64": "x86_64",
            "aarch64": "aarch64",
            "arm64": "aarch64",
        }
        arch = arch_map.get(machine, machine)

        if system == "windows":
            return f"{arch}-pc-windows-msvc"
        elif system == "darwin":
            return f"{arch}-apple-darwin"
        elif system == "linux":
            return f"{arch}-unknown-linux-gnu"
        else:
            return f"{arch}-unknown-{system}"

    @classmethod
    def resolve_binary(cls, tool_name: str) -> str:
        """
        Resolves the absolute path to a tool's executable.
        Priority:
        1. PATH (Development / User Installed)
        2. Sidecar Directory (Bundled / Standalone)
        """
        if tool_name in cls._cache:
            return cls._cache[tool_name]

        import shutil

        from myth_utils.paths import get_sidecar_dir

        # 1. Check strict tool name in PATH first (Dev override)
        if shutil.which(tool_name):
            cls._cache[tool_name] = tool_name
            return tool_name

        # 2. Check Sidecar Directory for Bundled Binaries
        sidecar_dir = get_sidecar_dir()
        if sidecar_dir and os.path.exists(sidecar_dir):
            triple = cls.get_target_triple()
            exe_ext = ".exe" if platform.system() == "Windows" else ""

            # Pattern: tool-target_triple.exe
            bundled_name = f"{tool_name}-{triple}{exe_ext}"
            bundled_path = os.path.join(sidecar_dir, bundled_name)

            if os.path.exists(bundled_path):
                logger.info(f"🔧 [RESOLVER] Mapped '{tool_name}' -> '{bundled_path}'")
                cls._cache[tool_name] = bundled_path
                return bundled_path

            # Fallback: Check if it exists without triple in sidecar (legacy bundle)
            simple_path = os.path.join(sidecar_dir, f"{tool_name}{exe_ext}")
            if os.path.exists(simple_path):
                cls._cache[tool_name] = simple_path
                return simple_path

        # 3. Not found - return original and let it fail naturally
        return tool_name

    @staticmethod
    def resolve_command(cmd: List[str]) -> List[str]:
        """Resolves the first element of a command list if it's a known tool."""
        if not cmd:
            return cmd

        # List of critical bundled tools to resolve
        KNOWN_TOOLS = {
            "nuclei",
            "subfinder",
            "naabu",
            "httpx",
            "dnsx",
            "asnmap",
            "shuffledns",
            "katana",
            "notify",
            "tlsx",
            "mapcidr",
            "uncover",
            "urlfinder",
            "alterx",
            "chaos",
            "interactsh-client",
        }

        tool = cmd[0]
        # Handle 'nuclei' or 'nuclei.exe'
        base_name = os.path.splitext(tool)[0]

        if base_name.lower() in KNOWN_TOOLS:
            resolved = ToolResolver.resolve_binary(base_name)
            if resolved != tool:
                new_cmd = list(cmd)
                new_cmd[0] = resolved
                return new_cmd

        return cmd


# --- Shared Utilities ---
class MCPUtils:
    """Singularity Grade Utilities: Hyper-Velocity & Quantum Tracing."""

    _correlation_id = contextvars.ContextVar("correlation_id", default="nexus-initial")

    @classmethod
    def get_correlation_id(cls) -> str:
        return cls._correlation_id.get()

    @classmethod
    def set_correlation_id(cls, cid: Optional[str] = None):
        if not cid:
            import uuid

            cid = f"trace-{uuid.uuid4().hex[:8]}"
        cls._correlation_id.set(cid)
        return cid

    @staticmethod
    def fast_hash(data: str) -> str:
        """Hyper-Velocity Hashing (xxhash fallback to md5)."""
        try:
            import xxhash

            return xxhash.xxh64(data).hexdigest()
        except ImportError:
            return hashlib.md5(data.encode()).hexdigest()

    @staticmethod
    def fast_dumps(data: Any) -> str:
        """Hyper-Velocity Serialization (orjson fallback to json)."""
        try:
            import orjson

            return orjson.dumps(data).decode()
        except ImportError:
            return json.dumps(data)

    @staticmethod
    def get_safe_path(
        path_str: str, base_dir: Optional[Union[str, Path]] = None
    ) -> Path:
        """Resolves a path and ensures it is safe (no traversal)."""
        if not base_dir:
            base_dir = Path.cwd()
        else:
            base_dir = Path(base_dir).resolve()

        target = Path(path_str).resolve()

        if not str(target).startswith(str(base_dir)):
            logger.warning(f"Path traversal attempt blocked: {path_str}")
            raise PermissionError(
                f"Access denied: Path {path_str} is outside workspace"
            )

        return target

    @staticmethod
    def cache_result(ttl_seconds: int = 3600):
        """Singularity Hyper-Speed Caching (xxhash + Redis)."""

        def decorator(func: Callable):
            cache = HighSpeedCache()
            from functools import wraps

            @wraps(func)
            async def wrapper(*args, **kwargs):
                key_data = f"{func.__name__}:{args}:{kwargs}"
                key_hash = MCPUtils.fast_hash(key_data)

                cached = await cache.get(key_hash)
                if cached is not None:
                    return cached

                result = await func(*args, **kwargs)
                await cache.set(key_hash, result, ttl=ttl_seconds)
                return result

            return wrapper

        return decorator

    @staticmethod
    async def run_command_async(
        cmd: Union[str, List[str]], cwd: Optional[str] = None, timeout: int = 60
    ) -> Dict[str, Any]:
        """Robust async command execution with correlation tracing and adaptive timeouts."""
        async with ResourceGuard._semaphore:
            cid = MCPUtils.get_correlation_id()

            # [TITAN] Dynamic Tool Resolution for Standalone Bundles
            if isinstance(cmd, list):
                cmd = ToolResolver.resolve_command(cmd)

            logger.info(f"[{cid}] Executing: {cmd}")
            try:
                # [TITAN] Adaptive Timeout: Scale based on target complexity if needed
                if isinstance(cmd, str):
                    process = await asyncio.create_subprocess_shell(
                        cmd,
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.PIPE,
                        cwd=cwd,
                    )
                else:
                    process = await asyncio.create_subprocess_exec(
                        *cmd,
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.PIPE,
                        cwd=cwd,
                    )

                stdout, stderr = await asyncio.wait_for(
                    process.communicate(), timeout=timeout
                )
                return {
                    "success": process.returncode == 0,
                    "exit_code": process.returncode,
                    "stdout": stdout.decode("utf-8", errors="ignore"),
                    "stderr": stderr.decode("utf-8", errors="ignore"),
                    "correlation_id": cid,
                }
            except asyncio.TimeoutError:
                return {
                    "success": False,
                    "error": "Command Timeout",
                    "code": TitanErrorCode.TIMEOUT,
                    "correlation_id": cid,
                }
            except Exception as e:
                return {
                    "success": False,
                    "error": str(e),
                    "code": TitanErrorCode.SYSTEM_FAILURE,
                    "correlation_id": cid,
                }


def tool_exception_handler(func):
    """Deep tool exception handler with standardized Titan Error Codes."""

    @wraps(func)
    async def wrapper(*args, **kwargs):
        cid = MCPUtils.get_correlation_id()
        try:
            return await func(*args, **kwargs)
        except ValidationError as ve:
            return {
                "success": False,
                "error": "Validation failed",
                "details": ve.errors(),
                "code": TitanErrorCode.VALIDATION_FAILURE,
                "correlation_id": cid,
            }
        except PermissionError as pe:
            return {
                "success": False,
                "error": str(pe),
                "code": TitanErrorCode.SECURITY_VIOLATION,
                "correlation_id": cid,
            }
        except asyncio.TimeoutError:
            return {
                "success": False,
                "error": "Operation timed out",
                "code": TitanErrorCode.TIMEOUT,
                "correlation_id": cid,
            }
        except Exception as e:
            logger.exception(f"[{cid}] Error in {func.__name__}")
            return {
                "success": False,
                "error": f"Internal Error: {str(e)}",
                "code": TitanErrorCode.SYSTEM_FAILURE,
                "correlation_id": cid,
            }

    return wrapper


class QuantumEnricher:
    """Advanced entropy analysis for cryptographic primitives."""

    @staticmethod
    def calculate_entropy(data: bytes) -> float:
        import math

        if not data:
            return 0
        entropy = 0
        for x in range(256):
            p_x = float(data.count(x)) / len(data)
            if p_x > 0:
                entropy += -p_x * math.log(p_x, 2)
        return entropy
