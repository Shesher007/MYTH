import os
import sys

# Add current dir to sys.path
sys.path.append(os.getcwd())

from myth_utils.paths import get_resource_path


def test_paths():
    assets = [
        "governance/agent_manifest.yaml",
        "governance/identity.yaml",
        "resources/nvidia_nim_models.txt",
        "resources/mistral_models.txt",
    ]

    all_ok = True
    for asset in assets:
        p = get_resource_path(asset)
        exists = os.path.exists(p)
        print(f"Checking {asset} -> {p} (Exists: {exists})")
        if not exists:
            all_ok = False

    if all_ok:
        print("\n✅ RESOLUTION PROPERLY IMPLEMENTED")
    else:
        print("\n❌ RESOLUTION FAILED")
        sys.exit(1)


if __name__ == "__main__":
    test_paths()
