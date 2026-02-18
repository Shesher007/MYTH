import os
import re

from pathlib import Path

TEMPLATES_DIR = Path(__file__).parent.parent / "templates" / "packaging"

def mass_templatize():
    for root, dirs, files in os.walk(TEMPLATES_DIR):
        for fname in files:
            if fname.endswith(".template"):
                fpath = os.path.join(root, fname)
                with open(fpath, "r", encoding="utf-8") as f:
                    content = f.read()

                # Rule 1: MYTH -> {{NAME}} (Except if it looks like a variable or part of a common path)
                # Use word boundaries
                content = re.sub(r"\bMYTH\b", "{{NAME}}", content)
                
                # Rule 2: myth -> {{NAME_LOWER}}
                # Avoid replacing things inside dependencies like libwebkit2gtk-4.0-37 or python3-myth if it was there
                # But looking at current files, myth usually refers to the package name.
                content = re.sub(r"\bmyth\b", "{{NAME_LOWER}}", content)

                # Rule 3: com.myth-tools.myth -> {{REVERSE_DOMAIN}}
                content = content.replace("com.myth-tools.myth", "{{REVERSE_DOMAIN}}")
                
                # Rule 4: Shesher Hasan -> {{AUTHOR}}
                content = content.replace("Shesher Hasan", "{{AUTHOR}}")

                # Rule 5: Multi-Yield Tactical Hub -> {{FULL_NAME}}
                content = content.replace("Multi-Yield Tactical Hub", "{{FULL_NAME}}")

                with open(fpath, "w", encoding="utf-8") as f:
                    f.write(content)
                print(f"✅ Templatized: {fpath}")

if __name__ == "__main__":
    mass_templatize()
