import os

# New Brand Mapping
replacements = {
    "myth-tools/MYTH": "myth-tools/MYTH",
    "myth-tools.github.io": "myth-tools.github.io",
    "com.myth-tools.myth": "com.myth-tools.myth",
    "MYTH Tools": "MYTH Tools",
}


def clean_sweep():
    print("🧹 Starting global brand sweep...")
    root_dirs = ["packaging", "ui/src-tauri", "ui/src", "scripts"]
    count = 0

    for d in root_dirs:
        target_dir = os.path.join(os.getcwd(), d)
        if not os.path.exists(target_dir):
            continue

        for root, dirs, files in os.walk(target_dir):
            for file in files:
                # Skip binaries and non-text files
                if file.endswith((".png", ".ico", ".icns", ".exe", ".dll")):
                    continue

                file_path = os.path.join(root, file)
                try:
                    with open(file_path, "r", encoding="utf-8") as f:
                        content = f.read()

                    changed = False
                    for old, new in replacements.items():
                        if old in content:
                            content = content.replace(old, new)
                            changed = True

                    if changed:
                        with open(file_path, "w", encoding="utf-8") as f:
                            f.write(content)
                        print(f"✅ Cleaned: {file_path}")
                        count += 1
                except Exception:
                    continue

    print(f"\n✨ Global sweep complete. Cleaned {count} files.")


if __name__ == "__main__":
    clean_sweep()
