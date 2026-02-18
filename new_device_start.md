## How to setup

### install dependencies
- 1. install python 3.13.11
- 2. install go (go1.25.5 windows/amd64)
- 3. install Node.js (v24.12.0) and npm (11.8.0)
- 4. install rust
- 5. python install_titan_dependencies.py
- 6. pip install uv
- 7. uv venv --python 3.13.11
- 8. .\.venv\Scripts\activate (Actavating the uv venv)
- 9. uv pip install -r .\requirements.txt --find-links https://download.pytorch.org/whl/cpu
- 10. Do what is said in the "TTS_INSTALL_GUIDE.md" file to install the "TTS" model
- 11. playwright install chromium

### How to run

- 1. python run_desktop.py


#### Remove all __pycache__ directories
Get-ChildItem -Path . -Filter "__pycache__" -Directory -Recurse | Remove-Item -Recurse -Force