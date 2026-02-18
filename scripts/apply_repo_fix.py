import os

OLD_REPO = "myth-tools/MYTH"
NEW_REPO = "myth-tools/MYTH"

def update_all():
    print(f"🚀 Updating project from {OLD_REPO} to {NEW_REPO}...")
    
    # Files to check (manifests + source code)
    root_dirs = ['packaging', 'ui/src-tauri', 'scripts']
    count = 0

    for d in root_dirs:
        target_dir = os.path.join(os.getcwd(), d)
        if not os.path.exists(target_dir):
            continue
            
        for root, dirs, files in os.walk(target_dir):
            for file in files:
                file_path = os.path.join(root, file)
                try:
                    with open(file_path, 'r', encoding='utf-8') as f:
                        content = f.read()
                    
                    if OLD_REPO in content:
                        new_content = content.replace(OLD_REPO, NEW_REPO)
                        with open(file_path, 'w', encoding='utf-8') as f:
                            f.write(new_content)
                        print(f"✅ Updated: {file_path}")
                        count += 1
                except:
                    continue

    print(f"\n✨ Successfully updated {count} files to use myth-tools/MYTH.")

if __name__ == "__main__":
    update_all()
