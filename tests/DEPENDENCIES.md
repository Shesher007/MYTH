# MYTH Project — Complete Dependency & Technology Audit
> Auto-generated from source code analysis (NOT from requirements.txt/pyproject.toml)
> Scanned: **188** Python files, **23** JS/JSX files

## Runtime Versions

| Runtime | Version |
|---------|---------|
| Python | 3.13.11 |
| uv | uv 0.9.18 (0cee76417 2025-12-16) |
| Node.js | v24.12.0 |
| npm | 11.8.0 |
| OS | win32 (nt) |

## Programming Languages & File Types

| Language | Files | Total Size |
|----------|------:|------------|
| Python | 188 | 1.9 MB |
| Other (.log) | 31 | 32.8 KB |
| JavaScript (JSX/React) | 18 | 235.7 KB |
| JSON | 8 | 769.7 KB |
| Markdown | 6 | 24.8 KB |
| Plain Text | 6 | 42.0 KB |
| JavaScript | 5 | 41.9 KB |
| YAML | 2 | 40.0 KB |
| HTML | 2 | 2.2 KB |
| Other (.png) | 2 | 5.4 MB |
| CSS | 2 | 47.9 KB |
| No Extension | 1 | 0.3 KB |
| TOML | 1 | 2.3 KB |
| Lock File | 1 | 564.7 KB |
| Other (.zip) | 1 | 0.0 KB |
| Other (.production) | 1 | 0.1 KB |
| Other (.bz2) | 1 | 0.1 KB |
| Other (.bak) | 1 | 0.1 KB |
| Other (.db) | 1 | 12.0 KB |
| Cloud Models (Gemini/NIM) | 0+ | ~0 MB (Streaming) |
| Other (.bin) | 1 | 26.9 MB |

## Python Third-Party Dependencies (from source imports)

**79** unique third-party packages imported across 188 Python files.

| # | Import Name | Status | Used In (files) | Sample Locations |
|--:|-------------|--------|----------------:|------------------|
| 1 | `langchain_core` | ✅ 1.2.9 (venv) | 125 | api.py, backend.py, mcp_servers\mcp_client.py |
| 2 | `httpx` | ✅ 0.28.1 (venv) | 31 | api.py, mcp_servers\mcp_client.py, mcp_servers\remote_servers\external_apis.py |
| 3 | `pydantic` | ✅ 2.12.5 (venv) | 27 | api.py, config_loader.py, mcp_servers\custom_servers\burp_server.py |
| 4 | `fastmcp` | ✅ 2.14.1 (venv) | 25 | mcp_servers\custom_servers\burp_server.py, mcp_servers\custom_servers\exploit_hub_server.py, mcp_servers\custom_servers\nuclei_server.py |
| 5 | `aiohttp` | ✅ 3.13.2 (venv) | 17 | mcp_servers\custom_servers\burp_server.py, mcp_servers\local_servers\fetch_server.py, mcp_servers\mcp_common.py |
| 6 | `psutil` | ✅ 7.1.3 (venv) | 15 | api.py, mcp_servers\custom_servers\security_tools.py, mcp_servers\local_servers\system_tools.py |
| 7 | `lief` | ✅ 0.17.3 (venv) | 9 | tools\reverse_engineering\binary_analyzer.py, tools\reverse_engineering\firmware_audit.py, tools\reverse_engineering\hardening_audit.py |
| 8 | `capstone` | ✅ 5.0.7 (venv) | 7 | tools\reverse_engineering\binary_analyzer.py, tools\reverse_engineering\decompilation_context.py, tools\reverse_engineering\diffing_engine.py |
| 9 | `yaml` | ✅ 6.0.3 (venv) | 7 | config_loader.py, myth_config.py, testing\test_config.py |
| 10 | `aiofiles` | ✅ 24.1.0 (venv) | 5 | mcp_servers\local_servers\filesystem_tools.py, mcp_servers\mcp_common.py, rag_system\file_uploader.py |
| 11 | `langchain_nvidia_ai_endpoints` | ✅ 1.0.0 (venv) | 5 | backend.py, myth_llm.py, rag_system\image_processor.py |
| 12 | `pwn` | ✅ 4.15.0 (venv) | 4 | tools\vr\exploit_automation.py, tools\vr\gadget_discovery.py, tools\vr\heap_exploitation.py |
| 13 | `PIL` | ✅ 11.3.0 (venv) | 3 | rag_system\document_processor.py, rag_system\image_processor.py, tools\utilities\file_generator.py |
| 14 | `bs4` | ✅ 4.14.3 (venv) | 3 | tools\intelligence\search.py, tools\recon\content_discovery.py, tools\recon\supply_chain_recon.py |
| 15 | `dns` | ✅ 2.8.0 (venv) | 3 | mcp_servers\remote_servers\external_apis.py, tools\recon\network.py, tools\recon\passive.py |
| 16 | `duckduckgo_search` | ⚠️ Not Installed | 3 | tools\intelligence\ai.py, tools\intelligence\search.py, tools\intelligence\social.py |
| 17 | `langchain_mistralai` | ✅ 1.1.1 (venv) | 3 | backend.py, myth_llm.py, rag_system\audio_processor.py |
| 18 | `requests` | ✅ 2.32.5 (venv) | 3 | tools\intelligence\search.py, tools\recon\active.py, tools\recon\discovery.py |
| 19 | `scapy` | ✅ 2.6.1 (venv) | 3 | tools\recon\infrastructure_services.py, tools\recon\internal_network.py, tools\recon\network.py |
| 20 | `tenacity` | ✅ 9.1.2 (venv) | 3 | rag_system\image_processor.py, rag_system\rag_chain.py, rag_system\vector_store.py |
| 21 | `cryptography` | ✅ 46.0.3 (venv) | 2 | tools\exploitation\identity_exploitation.py, tools\utilities\file_generator.py |
| 22 | `fastapi` | ✅ 0.128.0 (venv) | 2 | api.py, rag_system\file_uploader.py |
| 23 | `langchain` | ✅ 1.2.0 (venv) | 2 | rag_system\document_processor.py, tools\recon\pd_all_subdomains.py |
| 24 | `langchain_community` | ✅ 0.4.1 (venv) | 2 | rag_system\rag_chain.py, tools\intelligence\search.py |
| 25 | `numpy` | ✅ 2.2.6 (venv) | 2 | rag_system\vibevoice_processor.py, tools\utilities\file_generator.py |
| 26 | `orjson` | ✅ 3.11.5 (venv) | 2 | mcp_servers\mcp_common.py, tools\utilities\file_generator.py |
| 27 | `playwright` | ✅ 1.57.0 (venv) | 2 | mcp_servers\local_servers\browser_tools.py, tools\intelligence\browser.py |
| 28 | `redis` | ✅ 7.1.0 (venv) | 2 | mcp_servers\local_servers\db_tools.py, mcp_servers\mcp_common.py |
| 29 | `toml` | ✅ 0.10.2 (venv) | 2 | tools\utilities\file_generator.py, tools\utilities\utils.py |
| 30 | `whois` | ✅ 1.20240129.2 (venv) | 2 | tools\recon\advanced_osint.py, tools\recon\passive.py |
| 31 | `audioop_lts` | ✅ 0.2.2 (venv) | 1 | tools\utilities\file_generator.py |
| 32 | `azure` | ⚠️ Not Installed | 1 | tools\cloud\automation.py |
| 33 | `boto3` | ✅ 1.42.11 (venv) | 1 | tools\cloud\automation.py |
| 34 | `botocore` | ✅ 1.42.11 (venv) | 1 | tools\cloud\automation.py |
| 35 | `cvss` | ⚠️ Not Installed | 1 | mcp_servers\custom_servers\report_gen_server.py |
| 36 | `docker` | ✅ 7.1.0 (venv) | 1 | mcp_servers\local_servers\docker_tools.py |
| 37 | `exifread` | ✅ 3.5.1 (venv) | 1 | rag_system\document_processor.py |
| 38 | `faker` | ✅ 40.1.0 (venv) | 1 | tools\utilities\file_generator.py |
| 39 | `google` | ⚠️ Not Installed | 1 | tools\cloud\automation.py |
| 40 | `imagehash` | ✅ 4.3.2 (venv) | 1 | rag_system\document_processor.py |
| 41 | `google-generativeai` | ✅ Cloud | 1 | rag_system\vibevoice_processor.py |
| 42 | `kubernetes` | ✅ 34.1.0 (venv) | 1 | tools\cloud\automation.py |
| 43 | `langchain_google_community` | ✅ 3.0.2 (venv) | 1 | tools\intelligence\search.py |
| 44 | `langchain_mcp_adapters` | ✅ 0.2.1 (venv) | 1 | mcp_servers\mcp_client.py |
| 45 | `langchain_qdrant` | ✅ 1.1.0 (venv) | 1 | rag_system\vector_store.py |
| 46 | `langchain_text_splitters` | ✅ 1.1.0 (venv) | 1 | rag_system\document_processor.py |
| 47 | `langgraph` | ✅ 1.0.5 (venv) | 1 | backend.py |
| 48 | `magic` | ✅ 0.4.27 (venv) | 1 | rag_system\universal_processor.py |
| 49 | `markdownify` | ✅ 1.2.2 (venv) | 1 | mcp_servers\local_servers\browser_tools.py |
| 50 | `mcp` | ✅ 1.24.0 (venv) | 1 | mcp_servers\mcp_client.py |
| 51 | `motor` | ✅ 3.7.1 (venv) | 1 | mcp_servers\local_servers\db_tools.py |
| 52 | `msgpack` | ✅ 1.1.2 (venv) | 1 | tools\utilities\file_generator.py |
| 53 | `nest_asyncio` | ✅ 1.6.0 (venv) | 1 | rag_system\vibevoice_processor.py |
| 54 | `olefile` | ✅ 0.47 (venv) | 1 | tools\utilities\file_generator.py |
| 55 | `google-generativeai` | ✅ Cloud | 1 | rag_system\vibevoice_processor.py |
| 56 | `openpyxl` | ✅ 3.1.5 (venv) | 1 | tools\utilities\file_generator.py |
| 57 | `pandas` | ✅ 2.3.3 (venv) | 1 | rag_system\document_processor.py |
| 58 | `playwright_stealth` | ✅ 2.0.1 (venv) | 1 | mcp_servers\local_servers\browser_tools.py |
| 59 | `py7zr` | ✅ 1.1.0 (venv) | 1 | rag_system\archive_extractor.py |
| 60 | `pypdf` | ✅ 6.5.0 (venv) | 1 | rag_system\document_processor.py |
| 61 | `pywintypes` | ⚠️ Not Installed | 1 | tools\utilities\file_generator.py |
| 62 | `qdrant_client` | ✅ 1.16.2 (venv) | 1 | rag_system\vector_store.py |
| 63 | `qrcode` | ✅ 8.2 (venv) | 1 | tools\utilities\file_generator.py |
| 64 | `rarfile` | ✅ 4.2 (venv) | 1 | rag_system\archive_extractor.py |
| 65 | `ropper` | ✅ 1.13.13 (venv) | 1 | tools\vr\gadget_discovery.py |
| 66 | `soundfile` | ✅ 0.13.1 (venv) | 1 | rag_system\vibevoice_processor.py |
| 67 | `speedtest` | ⚠️ Not Installed | 1 | asset_inventory\wifi_speed_tester.py |
| 68 | `sqlalchemy` | ✅ 2.0.46 (venv) | 1 | mcp_servers\local_servers\db_tools.py |
| 69 | `sse_starlette` | ✅ 3.0.4 (venv) | 1 | api.py |
| 70 | `starlette` | ✅ 0.50.0 (venv) | 1 | api.py |
| 71 | `streamlit` | ⚠️ Not Installed | 1 | tools\recon\discovery.py |
| 72 | `tldextract` | ✅ 5.3.0 (venv) | 1 | api.py |
| 73 | `ujson` | ✅ 5.11.0 (venv) | 1 | tools\utilities\file_generator.py |
| 74 | `unstructured` | ✅ 0.18.26 (venv) | 1 | rag_system\document_processor.py |
| 75 | `uvicorn` | ✅ 0.38.0 (venv) | 1 | api.py |
| 76 | `win32con` | ✅ 311 (venv) | 1 | tools\utilities\file_generator.py |
| 77 | `win32file` | ✅ 311 (venv) | 1 | tools\utilities\file_generator.py |
| 78 | `xmltodict` | ⚠️ Not Installed | 1 | tools\utilities\utils.py |
| 79 | `xxhash` | ✅ 3.6.0 (venv) | 1 | mcp_servers\mcp_common.py |

### Installation Command
To install all discovered dependencies, run:
```bash
uv pip install aiofiles aiohttp audioop-lts azure beautifulsoup4 boto3 botocore capstone cryptography cvss dnspython docker duckduckgo-search exifread faker fastapi fastmcp google google-generativeai httpx imagehash kubernetes langchain langchain-community langchain-core langchain-google-community langchain-mcp-adapters langchain-mistralai langchain-nvidia-ai-endpoints langchain-qdrant langchain-text-splitters langgraph lief markdownify mcp motor msgpack nest-asyncio numpy olefile openpyxl orjson pandas pillow playwright playwright-stealth psutil pwntools py7zr pydantic pypdf python-magic pywin32 pywintypes pyyaml qdrant-client qrcode rarfile redis requests ropper scapy speedtest sqlalchemy sse-starlette starlette streamlit tenacity tldextract toml ujson unstructured uvicorn whois xmltodict xxhash
```

## Python Standard Library Modules Used

**76** stdlib modules referenced.

`os` (148), `asyncio` (140), `json` (129), `datetime` (112), `typing` (80), `re` (61), `sys` (46), `pathlib` (43), `platform` (35), `time` (29), `hashlib` (25), `logging` (24), `socket` (22), `random` (20), `shutil` (19), `subprocess` (18), `base64` (17), `traceback` (13), `math` (12), `tempfile` (12), `collections` (10), `struct` (9), `concurrent` (8), `ctypes` (8), `urllib` (8), `importlib` (5), `mimetypes` (5), `string` (5), `uuid` (5), `ipaddress` (4), `ssl` (4), `threading` (4), `atexit` (3), `binascii` (3), `csv` (3), `enum` (3), `io` (3), `sqlite3` (3), `xml` (3), `zipfile` (3), `bz2` (2), `dataclasses` (2), `functools` (2), `gzip` (2), `html` (2), `lzma` (2), `pickle` (2), `shlex` (2), `signal` (2), `tarfile` (2), `winreg` (2), `zlib` (2), `argparse` (1), `ast` (1), `audioop` (1), `calendar` (1), `colorsys` (1), `configparser` (1), `contextlib` (1), `contextvars` (1), `copy` (1), `decimal` (1), `email` (1), `fnmatch` (1), `fractions` (1), `hmac` (1), `itertools` (1), `pkgutil` (1), `queue` (1), `secrets` (1), `select` (1), `stat` (1), `textwrap` (1), `tkinter` (1), `wave` (1), `webbrowser` (1)

## Internal Project Modules

**10** internal packages/modules.

- `myth_config` — imported in 138 files
- `tools` — imported in 109 files
- `mcp_common` — imported in 25 files
- `config_loader` — imported in 12 files
- `testing` — imported in 9 files
- `rag_system` — imported in 4 files
- `mcp_servers` — imported in 3 files
- `myth_llm` — imported in 3 files
- `backend` — imported in 2 files
- `myth_utils` — imported in 2 files

## Node.js / npm Dependencies (from source imports)

**17** unique packages imported across 23 JS/JSX files.

| Package | Used In (files) | Sample Locations |
|---------|----------------:|------------------|
| `react` | 21 | ui\src\App.jsx, ui\src\components\ChatWindow.jsx, ui\src\components\CommandPalette.jsx |
| `lucide-react` | 13 | ui\src\App.jsx, ui\src\components\ChatWindow.jsx, ui\src\components\CommandPalette.jsx |
| `framer-motion` | 11 | ui\src\App.jsx, ui\src\components\ChatWindow.jsx, ui\src\components\CommandPalette.jsx |
| `react-markdown` | 2 | ui\src\components\ChatWindow.jsx, ui\src\components\NeuralCore.jsx |
| `remark-gfm` | 2 | ui\src\components\ChatWindow.jsx, ui\src\components\NeuralCore.jsx |
| `@eslint/js` | 1 | ui\eslint.config.js |
| `globals` | 1 | ui\eslint.config.js |
| `eslint` | 1 | ui\eslint.config.js |
| `eslint-plugin-react-hooks` | 1 | ui\eslint.config.js |
| `eslint-plugin-react-refresh` | 1 | ui\eslint.config.js |
| `vite` | 1 | ui\vite.config.js |
| `@tailwindcss/vite` | 1 | ui\vite.config.js |
| `@vitejs/plugin-react` | 1 | ui\vite.config.js |
| `react-dom` | 1 | ui\src\main.jsx |
| `axios` | 1 | ui\src\hooks\useAgent.js |

## System Binaries & External Tools

**32** external programs/tools invoked via subprocess or os.system.

| Binary/Tool | Referenced In |
|-------------|---------------|
| `/bin/bash` | tools\exploitation\polyglot_payloads.py |
| `/bin/sh` | tools\utilities\file_generator.py |
| `alterx` | tools\recon\pd_all_subdomains.py |
| `curl` | tools\utilities\shell.py |
| `dig` | tools\recon\pd_all_subdomains.py |
| `ffprobe` | rag_system\universal_processor.py |
| `ffuf` | tools\utilities\shell.py |
| `git` | tools\utilities\shell.py |
| `go` | tools\recon\discovery.py |
| `id` | tools\utilities\file_generator.py |
| `iptables` | tools\exploitation\host_exploitation.py, tools\exploitation\infrastructure_exploitation.py |
| `iwlist` | tools\exploitation\host_exploitation.py |
| `kubectl` | tools\cloud\k8s_advanced.py |
| `nm` | tools\ctf\binary_expert.py |
| `nmap` | tools\utilities\shell.py |
| `nmcli` | tools\exploitation\host_exploitation.py |
| `node` | testing\audit_dependencies.py |
| `npm` | testing\audit_dependencies.py |
| `npx.cmd` | mcp_servers\mcp_client.py |
| `nslookup` | tools\recon\pd_all_subdomains.py |
| `nvidia-smi` | mcp_servers\mcp_common.py |
| `objdump` | tools\ctf\binary_expert.py |
| `powershell` | tools\utilities\shell.py |
| `pwsh` | tools\utilities\shell.py |
| `readelf` | tools\ctf\binary_expert.py |
| `sharphound` | tools\utilities\integrations.py |
| `snmpwalk` | tools\recon\infrastructure_services.py |
| `sqlmap` | tools\utilities\shell.py |
| `sysctl` | tools\exploitation\host_exploitation.py, tools\exploitation\infrastructure_exploitation.py |
| `tshark` | tools\ctf\network_forensics.py |
| `uv` | testing\audit_dependencies.py |
| `wsl` | tools\utilities\shell.py |

## External APIs & Services Referenced

**52** unique external domains found in source code.

| Domain | Referenced In (files) |
|--------|---------------------:|
| `crt.sh` | 6 |
| `github.com` | 5 |
| `ip-api.com` | 4 |
| `attacker.com` | 4 |
| `metadata.google.internal` | 4 |
| `gitlab.com` | 3 |
| `shodan.io` | 3 |
| `hackertarget.com` | 3 |
| `cisa.gov` | 2 |
| `pwnedpasswords.com` | 2 |
| `virustotal.com` | 2 |
| `interact.sh` | 2 |
| `vulnerable.target.com` | 2 |
| `web.archive.org` | 2 |
| `html.duckduckgo.com` | 2 |
| `first.org` | 2 |
| `registry.npmjs.org` | 2 |
| `evil.com` | 2 |
| `raw.githubusercontent.com` | 1 |
| `security-portal.company-it.com` | 1 |
| `google.com` | 1 |
| `nodejs.org` | 1 |
| `go.dev` | 1 |
| `openrouter.ai` | 1 |
| `search.censys.io` | 1 |
| `cve.circl.lu` | 1 |
| `haveibeenpwned.com` | 1 |
| `hunter.io` | 1 |
| `services.nvd.nist.gov` | 1 |
| `securitytrails.com` | 1 |
| `exfil-node.com` | 1 |
| `login-update.com` | 1 |
| `management.azure.com` | 1 |
| `login.microsoftonline.com` | 1 |
| `twitter.com` | 1 |
| `soundcloud.com` | 1 |
| `vimeo.com` | 1 |
| `reddit.com` | 1 |
| `medium.com` | 1 |
| `instagram.com` | 1 |
| `otx.alienvault.com` | 1 |
| `dns.projectdiscovery.io` | 1 |
| `apple.com` | 1 |
| `malicious.com` | 1 |
| `cve.mitre.org` | 1 |
| `rebind-service.com` | 1 |
| `idp.com` | 1 |
| `client.attacker.com` | 1 |
| `tidelift.com` | 1 |
| `eslint.org` | 1 |
| `opencollective.com` | 1 |
| `vite.dev` | 1 |
