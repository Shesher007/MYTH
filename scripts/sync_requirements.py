import os
import re


def normalize_name(name):
    return name.lower().replace("_", "-").replace(".", "-")


def parse_requirements(path):
    packages = {}
    lines = []
    if not os.path.exists(path):
        return packages, lines

    with open(path, "r", encoding="utf-8") as f:
        file_content = f.read()

    for line in file_content.splitlines():
        lines.append(line)
        line = line.strip()
        if not line or line.startswith("#"):
            continue

        # Regex to capture package name
        # Handles: package==1.0, package>=1.0, package, package[extra]
        match = re.match(r"^([a-zA-Z0-9\-\_\.]+)", line)
        if match:
            name = normalize_name(match.group(1))
            packages[name] = line

    return packages, lines


def main():
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    desktop_req_path = os.path.join(root, "requirements-desktop.txt")
    source_req_path = os.path.join(root, "requirements.txt")

    print(f"Reading {desktop_req_path}...")
    desktop_pkgs, desktop_lines = parse_requirements(desktop_req_path)

    print(f"Reading {source_req_path}...")
    source_pkgs, _ = parse_requirements(source_req_path)

    # Blocklist of build/dev tools to NOT copy automatically
    blocklist = {
        "pip",
        "setuptools",
        "wheel",
        "build",
        "twine",
        "black",
        "mypy",
        "flake8",
        "pytest",
        "pylint",
        "tox",
        "virtualenv",
        "uv",
    }

    print("\nAnalyzing differences...")

    to_add = []
    for name, line in source_pkgs.items():
        if name in blocklist:
            continue
        if name not in desktop_pkgs:
            to_add.append(line)

    if not to_add:
        print("No new packages to add.")
        return

    print(f"Found {len(to_add)} new packages.")

    with open(desktop_req_path, "a", encoding="utf-8") as f:
        f.write("\n\n# --- Imported from requirements.txt ---\n")
        for line in sorted(to_add):
            f.write(line + "\n")
            print(f" + Adding: {line}")

    print(f"\n✅ Successfully added {len(to_add)} packages to requirements-desktop.txt")


if __name__ == "__main__":
    main()
