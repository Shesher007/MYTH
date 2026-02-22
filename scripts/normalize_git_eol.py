import os


def normalize_eol(file_path, target="lf"):
    if not os.path.exists(file_path):
        print(f"File not found: {file_path}")
        return

    with open(file_path, "rb") as f:
        content = f.read()

    # Standardize all to LF first
    content = content.replace(b"\r\n", b"\n").replace(b"\r", b"\n")

    if target == "crlf":
        content = content.replace(b"\n", b"\r\n")

    with open(file_path, "wb") as f:
        f.write(content)
    print(f"Normalized {file_path} to {target.upper()}")


# Target Files
files_lf = [
    "tests/lint_results.xml",
    "tests/results.xml",
    "tests/test_errors.txt",
    "tests/validate_results.xml",
    "tools/.internal_tool_cache.json",
]

files_crlf = [
    "packaging/chocolatey/tools/chocolateyInstall.ps1",
    "scripts/package_portable_win.ps1",
]

for f in files_lf:
    normalize_eol(f, "lf")

for f in files_crlf:
    normalize_eol(f, "crlf")
