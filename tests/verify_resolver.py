import logging
import os
import sys
from pathlib import Path

# Add project root to path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.append(str(PROJECT_ROOT))

# Setup logging
logging.basicConfig(level=logging.INFO)

try:
    from mcp_servers.mcp_common import ToolResolver
except ImportError as e:
    print(f"❌ ImportError: {e}")
    sys.exit(1)


def test_resolver():
    print("🧪 Testing ToolResolver...")

    # 1. Test Triple
    triple = ToolResolver.get_target_triple()
    print(f"   ℹ️  Target Triple: {triple}")

    # 2. Test Nuclei Resolution
    tool_name = "nuclei"
    resolved = ToolResolver.resolve_binary(tool_name)
    print(f"   🔍 Resolved '{tool_name}' -> '{resolved}'")

    # Verify it matches expectation (on Windows)
    if os.name == "nt":
        expected_suffix = "pc-windows-msvc.exe"
        if expected_suffix in resolved and os.path.exists(resolved):
            print("   ✅ SUCCESS: Resolved to platform-specific binary.")
        elif resolved == tool_name:
            # It might return generic name if not found in sidecar, check PATH
            import shutil

            if shutil.which(tool_name):
                print("   ⚠️  WARNING: Resolved to user PATH (Sidecar missing?).")
            else:
                print("   ❌ FAILED: Resolved to generic name but not in PATH.")
        else:
            print(f"   ❌ FAILED: Unexpected resolution: {resolved}")
    else:
        print("   ℹ️  Non-Windows platform test.")

    # 3. Debug Sidecar
    from myth_utils.paths import get_sidecar_dir

    sidecar = get_sidecar_dir()
    print(f"\n   📂 Sidecar Dir: {sidecar}")
    if sidecar and os.path.exists(sidecar):
        print("   ✅ Sidecar directory exists.")
        # Check manually
        suffix = "pc-windows-msvc.exe" if os.name == "nt" else "unknown"
        expected = os.path.join(sidecar, f"nuclei-x86_64-{suffix}")
        if os.path.exists(expected):
            print(f"   ✅ Bundled binary found at: {expected}")
        else:
            print(f"   ❌ Bundled binary NOT found at: {expected}")
    # 4. Test Forced Sidecar Resolution (Simulate Fresh Install)
    print("\n🧪 Testing Forced Sidecar Resolution (Mocking fresh install)...")
    import shutil

    original_which = shutil.which
    try:
        # Mock specific tool to return None
        def mock_which(cmd, mode=os.F_OK | os.X_OK, path=None):
            if cmd == "nuclei":
                return None
            return original_which(cmd, mode, path)

        shutil.which = mock_which
        ToolResolver._cache.clear()  # Clear cache to force re-resolve

        forced_resolved = ToolResolver.resolve_binary("nuclei")
        print(f"   🔍 Forced Resolution: '{forced_resolved}'")

        if "pc-windows-msvc" in forced_resolved:
            print(
                "   ✅ SUCCESS: Correctly resolved to bundled binary when missing from PATH."
            )
        else:
            print(
                f"   ❌ FAILED: Did not resolve to bundled binary. Got: {forced_resolved}"
            )

    finally:
        shutil.which = original_which
