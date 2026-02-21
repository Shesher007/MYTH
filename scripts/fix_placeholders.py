import os

# The placeholder I used across all 33 manifests
OLD_REPO = "myth-tools/MYTH"


def fix_placeholders():
    print(f"🔍 Searching for placeholders: {OLD_REPO}")

    # Ask for the real repository URL path
    new_repo = input(
        f"Enter your real GitHub path (e.g. 'myuser/my-repo') or press Enter to keep DEFAULT [{OLD_REPO}]: "
    ).strip()

    if not new_repo:
        new_repo = OLD_REPO
        print("Using default placeholder.")

    packaging_dir = os.path.join(os.getcwd(), "packaging")
    count = 0

    for root, dirs, files in os.walk(packaging_dir):
        for file in files:
            file_path = os.path.join(root, file)
            try:
                with open(file_path, "r", encoding="utf-8") as f:
                    content = f.read()

                if OLD_REPO in content:
                    new_content = content.replace(OLD_REPO, new_repo)
                    with open(file_path, "w", encoding="utf-8") as f:
                        f.write(new_content)
                    print(f"✅ Updated: {file}")
                    count += 1
            except Exception:
                # Skip binary files or permission issues
                continue

    print(f"\n✨ Finished! Updated {count} files.")
    print(f"🔗 All manifests now point to: https://github.com/{new_repo}")


if __name__ == "__main__":
    fix_placeholders()
