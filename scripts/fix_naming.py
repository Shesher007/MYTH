import os

# The tauri.conf.json has "productName": "MYTH"
# Tauri produces files like MYTH_1.1.0_x64-setup.exe
OLD_NAME = "myth"
NEW_NAME = "MYTH"


def fix_naming_case():
    print(f"🔄 Standardizing manifest naming: {OLD_NAME} -> {NEW_NAME}")
    packaging_dir = os.path.join(os.getcwd(), "packaging")
    count = 0

    for root, dirs, files in os.walk(packaging_dir):
        for file in files:
            file_path = os.path.join(root, file)
            try:
                with open(file_path, "r", encoding="utf-8") as f:
                    content = f.read()

                # We want to catch things like: myth_1.1.0_x64.deb -> MYTH_1.1.0_x64.deb
                # but NOT things like myth-tools.github.io

                new_content = content.replace("myth_1.1.0", "MYTH_1.1.0")
                new_content = new_content.replace("/myth_v", "/MYTH_v")
                new_content = new_content.replace(
                    "/myth-", "/MYTH-"
                )  # For some formats

                if content != new_content:
                    with open(file_path, "w", encoding="utf-8") as f:
                        f.write(new_content)
                    print(f"✅ Case Fixed: {file_path}")
                    count += 1
            except Exception:
                continue

    print(f"\n✨ Naming audit complete. Fixed {count} manifest references.")


if __name__ == "__main__":
    fix_naming_case()
