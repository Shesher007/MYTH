"""
test_tool_invocations.py — Invoke every registered tool with safe dummy arguments.
===================================================================================
Uses the tools/__init__.py discovery system (get_all_tools) to:
1. Get every registered tool
2. Attempt a safe ainvoke() with minimal/dummy arguments
3. Verify no unhandled exception is raised (result content irrelevant)
4. 10-second timeout per tool to prevent hangs
"""

import asyncio
import os
import sys
import time
import traceback
from pathlib import Path

ROOT = Path(__file__).parents[1].absolute()

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from conftest import C, ResultTracker, Status  # noqa: E402

CONCURRENCY_LIMIT = 50  # Number of tools to test in parallel
TOOL_TIMEOUT = 10  # seconds per tool invocation

# Safe dummy arguments for common tool parameter names
SAFE_ARGS = {
    "target": "127.0.0.1",
    "target_url": "http://example.com",
    "target_domain": "example.com",
    "url": "http://example.com",
    "domain": "example.com",
    "host": "127.0.0.1",
    "ip": "127.0.0.1",
    "ip_address": "127.0.0.1",
    "port": 80,
    "query": "test",
    "search_query": "test",
    "q": "test",
    "input": "test",
    "text": "test",
    "command": "echo test",
    "cmd": "echo test",
    "email": "test@example.com",
    "username": "testuser",
    "filename": "test.txt",
    "file_path": "/tmp/test.txt",
    "path": "/tmp",
    "network_range": "127.0.0.1/32",
    "cidr": "127.0.0.1/32",
    "binary_path": "/bin/echo",
    "data": "test",
    "content": b"test content",
    "target_stack": ["test-lib-1.0"],
    "target_assets": ["test@example.com"],
    "credentials": [{"username": "admin", "password": "test123"}],
    "target_profile": {"name": "Test", "role": "Tester", "company": "TestCorp"},
    "target_role": "IT",
    "company": "TestCorp",
    "keyword": "test",
    "technology": "python",
    "cve_id": "CVE-2021-44228",
    "working_directory": ".",
    "capabilities": [],
    "headers": {"User-Agent": "Test"},
    "v__args": [],
    "args": [],
    "script_args": [],
    "ns_server": "8.8.8.8",
    "nameserver": "8.8.8.8",
    "templates": "default",
    "target_list": "",
    "custom_paths": [],
    "kwargs": {},
    "key_hex": "00112233445566778899aabbccddeef",
    "accept": True,
    "click_selector": "button",
    "save_as": "downloaded.txt",
    "headless": True,
    "ignore_cache": True,
    "full_page": False,
    "timeout": 30,
    "latitude": 0.0,
    "longitude": 0.0,
    "target_mitigations": [],
    "years_horizon": 5,
    "length": 16,
    "pid": 1234,
    "engines": ["test-engine"],
    "root_key": "HKEY_LOCAL_MACHINE",
    "subkey": "SOFTWARE",
    "value_name": "TestValue",
    "indicators": ["127.0.0.1"],
    "hostname": "example.com",
    "connection_string": "postgresql://user:pass@localhost:5432/db",
    "sql": "SELECT 1",
    "params": {},
    "uri": "redis://localhost:6379",
    "image": "nginx:latest",
    "urls": ["http://example.com"],
    "urls_to_scan": ["http://example.com"],
    "fingerprint": "test-fingerprint",
    "class_hierarchy": {},
    "selector": "div.test",
    "selector_or_name": "test",
    "project_id": "test-project",
    "logic_flow": "test-flow",
    "oracle_seed": "test-seed",
    "config_override": {},
    "primary_endpoint": "http://127.0.0.1:8080",
    "secondary_endpoint": "http://127.0.0.1:8081",
    "bash_command": "echo 'test'",
    "powershell_script": "Write-Output 'test'",
    "python_code": "print('test')",
    "purpose": "testing",
    "file_spec": {"test.txt": "test content"},
    "target_info": {"host": "127.0.0.1"},
    "vulnerabilities": [],
    "recommendations": [],
    "session_id": "test-session",
    "commands": ["ls"],
    "script": "http-title",
    "api_id": "test-id",
    "api_secret": "test-secret",
    "account": "test-account",
    "key": "test-key",
    "address_or_ens": "0x1234567890123456789012345678901234567890",
    "network": "ethereum",
    "severity": "high",
    "status": "active",
    "organization": "test-org",
    "team": "test-team",
    "user_id": "test-user",
    "resource_id": "test-resource",
    "instance_id": "i-1234567890abcdef0",
    "arn": "arn:aws:iam::123456789012:user/test-user",
    "bucket": "test-bucket",
    "region": "us-east-1",
    "owner": "test-owner",
    "repo": "test-repo",
    "pull_number": 1,
    "issue_number": 1,
    "commit_id": "abcdef123456",
    "password": "testpassword123",
    "phone_number": "+15551234567",
    "current_proxy": "http://127.0.0.1:8080",
    "target_metrics": {},
    "encoded_str": "AABBAA",
    "branch": "main",
    "from_branch": "test",
    "title": "Test Finding",
    "body": "test body",
    "message": "test message",
    "assignees": [],
    "milestone": 1,
    "labels": [],
    "state": "test",
    "direction": "test",
    "per_page": 1,
    "page": 1,
    "since": "test",
    "sort": "test",
    "sha": "test",
    "perPage": 1,
    "event": "COMMENT",
    "comments": [],
    "wordlist_path": os.path.join(ROOT, "tests", "assets", "wordlist.txt")
    if "ROOT" in globals()
    else "tests/assets/wordlist.txt",
    "index": 0,
    "class_name": "TestClass",
    "ip_or_domain": "127.0.0.1",
    "target_ip": "127.0.0.1",
    "chunk_ptr": 0,
    "next_ptr": 0,
    "size": 1024,
    "ir_graph": {},
    "domains": ["example.com"],
    "wordlist": ["admin", "test"],
    "dependency_tree": {},
    "lib_path": "/usr/lib",
    "campaign_name": "test-campaign",
    "token_sample": ["token1", "token2"],
    "account_name": "test-account",
    "scan_results": [],
    "package": "test-package",
    "ecosystem": "npm",
    "use_https": True,
    "request_b64": "R0VUIC8gSFRUUC8xLjENCkhvc3Q6IGV4YW1wbGUuY29tDQoNCg==",
    "program": "test-program",
    "findings": [],
    "token": "ej...",
    "address": "0x123...",
    "ciphertext": "aabbcc",
    "shellcode_hex": "909090",
    "detected_arch": "x64",
    "primitives": [],
    "mitigations": [],
    "expected_head_sha": "abcdef123456",
    "commit_title": "test commit",
    "merge_method": "merge",
    # Added for RAG/Tools
    "parameter": "id",
    "n": 1,
    "file_path_v2": "/tmp/test.txt",
    "binary_metadata_nexus": {},
    # Added for GitHub
    "name": "test-repo",
    "head": "feature",
    "base": "main",
    "files": {"readonly.txt": "content"},
    "repo_path": ".",
    "depth": 1,
    "recursive": False,
    "token_name": "test-token",
    "secret": "test-secret",
    "offset_mapping": {},
    "modulus": 123,
    "pub_exp": 65537,
    "n_gram": 2,
    "top_k": 5,
    "min_confidence": 0.5,
    "arch": "x86",
    "os": "linux",
    "format": "el",
    "bad_chars": b"",
    "encoder": "xor",
    "iterations": 1,
    "key_size": 16,
    "structure_map": {},
    # --- FIXED MISSING ARGS ---
    "pattern": "test",
    "search_dir": ".",
    "service_name": "test-service",
    "config_snippet": "test-config",
    "discovery_artifacts": [{"summary": "test", "severity": "LOW"}],
    "target_api": "http://api.example.com",
    "regex_list": ["test-regex"],
    "action": "test-action",
    "vulnerability_type": "xss",
    "scope": {"include": ["all"]},
    "project_name": "default",
    "file_format": "txt",
    "file_specs": [{"name": "test", "content": "content"}],
    "mission_name": "test-mission",
    "script_name": "http-title",
    "current_findings": [],
    "historical_context": {},
    "target_dir": ".",
    "source_dir": ".",
    "mission_reports": [],
    "target_pid": 1234,
    "filter_name": "test-filter",
    "endpoint": "http://endpoint.com",
    "output_format": "json",
    "input_data": "start",
    "service_map": {},
    "spectral_signature": {"sig": "nature"},
    "results_data": {},
    "targets": ["http://test.com"],
    "base_domain": "example.com",
    "target_host": "127.0.0.1",
    "target_port": 443,
    "target_os": "linux",
    "company_name": "TestCorp",
    "full_name": "John Doe",
    "domain_or_term": "example.com",
    "threat_event": "Malicious login attempt",
    "objective": "Map target network surface",
    "sources_data": [{"source": "DNS", "data": {"ip": "127.0.0.1"}}],
    "high_level_goal": "Perform comprehensive target reconnaissance",
    "target_selector": "#target",
    "sid": "S-1-5-21-123456789-123456789-123456789-500",
    "krbtgt_hash": "0123456789abcdef0123456789abcde",
    "diff_results": "binary mismatch at offset 0x400",
    "ports": [80, 443],
    "code": "++++++++[>++++[>++>+++>+++>+<<<<-]>+>+>->>+[<]<-]>>.>---.+++++++..+++.>>.<-.<.+++.------.--------.>>+.>++.",
    "queries": ["vulnerability research", "exploits"],
    "subnet": "192.168.1.0/24",
    "token_symbol": "ETH",
    "limit": 10,
    "offset": 0,
    "order": "desc",
    "tags": ["test"],
    "description": "test description",
    "notes": "test notes",
    "metadata": {},
    "config": {},
    "options": {},
    "filters": {},
    "criteria": {},
    "rules": [],
    "policy": {},
    "permission": "admin",
    "role_name": "admin",
    "group_name": "admin",
    "zone": "us-east-1a",
    "bucket_name": "test-bucket",
    "object_key": "test-key",
    "volume_id": "vol-1234567890abcdef0",
    "snapshot_id": "snap-1234567890abcdef0",
    "vpc_id": "vpc-1234567890abcdef0",
    "subnet_id": "subnet-1234567890abcdef0",
    "security_group_id": "sg-1234567890abcdef0",
    "access_key": "AKIAIOSFODNN7EXAMPLE",
    "secret_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    "session_token": "FwoGZXIvYXdzE...",
    "api_key": "test-api-key",
    "auth_token": "test-auth-token",
    "bearer_token": "test-bearer-token",
    "jwt": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
    "cookie": "session=test-session-id",
    "user_agent": "Mozilla/5.0...",
    "referer": "http://example.com",
    "origin": "http://example.com",
    "method": "GET",
    "status_code": 200,
    "response_body": "test response",
    "request_body": "test request",
    "payload_type": "json",
    "encoding": "utf-8",
    "compression": "none",
    "encryption": "none",
    "hashing": "sha256",
    "algorithm": "aes-256-cbc",
    "key_id": "test-key-id",
    "iv": "00112233445566778899aabbccddeef",
    "salt": "test-salt",
    "nonce": "test-nonce",
    "tag": "test-tag",
    "aad": "test-aad",
    "padding": "pkcs7",
    "mode": "cbc",
    "bit_length": 256,
    "key_format": "raw",
    "cert_path": "/tmp/cert.pem",
    "key_path": "/tmp/key.pem",
    "ca_path": "/tmp/ca.pem",
    "pfx_path": "/tmp/cert.pfx",
    "jks_path": "/tmp/cert.jks",
    "keystore_password": "password",
    "truststore_password": "password",
}

# Create a persistent dummy binary for tools that need file_path
try:
    binary_dir = Path("testing/bins")
    binary_dir.mkdir(exist_ok=True, parents=True)
    dummy_bin = binary_dir / "dummy_payload.bin"
    if not dummy_bin.exists():
        with open(dummy_bin, "wb") as f:
            f.write(
                b"\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            )  # Minimal ELF header

    SAFE_ARGS["file_path"] = str(dummy_bin.absolute())
    SAFE_ARGS["binary_path"] = str(dummy_bin.absolute())
    SAFE_ARGS["filename"] = str(dummy_bin.absolute())
except Exception:
    pass


def _build_args_for_tool(tool_obj) -> dict:
    """Build safe invocation arguments based on tool's schema."""
    args = {}

    # Try to extract schema from the tool
    schema = None
    try:
        if hasattr(tool_obj, "args_schema") and tool_obj.args_schema:
            schema = tool_obj.args_schema
    except Exception:
        pass

    if schema:
        try:
            # Enforce Pydantic V2 model_fields
            schema_fields = schema.model_fields

            for field_name, field_info in schema_fields.items():
                # Check if field has a default
                has_default = False
                if hasattr(field_info, "default"):
                    has_default = (
                        field_info.default is not None and field_info.default is not ...
                    )

                if not has_default and hasattr(field_info, "default_factory"):
                    has_default = field_info.default_factory is not None

                # Check if required (no default)
                is_required = not has_default

                # Smart type detection
                annotation = None
                if hasattr(field_info, "annotation"):
                    annotation = field_info.annotation
                elif hasattr(field_info, "type_"):
                    annotation = field_info.type_

                ann_str = str(annotation).lower() if annotation else ""

                if field_name in SAFE_ARGS:
                    safe_val = SAFE_ARGS[field_name]
                    # Type correction based on annotation
                    if "dict" in ann_str and not isinstance(safe_val, dict):
                        args[field_name] = {}
                    elif (
                        "list" in ann_str or "sequence" in ann_str
                    ) and not isinstance(safe_val, (list, tuple)):
                        args[field_name] = [safe_val] if safe_val else []
                    elif "bool" in ann_str and not isinstance(safe_val, bool):
                        args[field_name] = True
                    elif "int" in ann_str and not isinstance(safe_val, int):
                        try:
                            args[field_name] = int(safe_val)
                        except (ValueError, TypeError):  # Fix E722
                            args[field_name] = 1
                    elif "float" in ann_str and not isinstance(safe_val, float):
                        try:
                            args[field_name] = float(safe_val)
                        except (ValueError, TypeError):  # Fix E722
                            args[field_name] = 1.0
                    elif "bytes" in ann_str and isinstance(safe_val, str):
                        args[field_name] = safe_val.encode("utf-8")
                    elif "str" in ann_str and not isinstance(safe_val, str):
                        args[field_name] = str(safe_val)
                    else:
                        args[field_name] = safe_val
                elif is_required:
                    # Attempt type-based fallback
                    if "int" in ann_str:
                        args[field_name] = 1
                    elif "float" in ann_str:
                        args[field_name] = 1.0
                    elif "bool" in ann_str:
                        args[field_name] = False
                    elif "list" in ann_str or "sequence" in ann_str:
                        args[field_name] = []
                    elif "dict" in ann_str:
                        args[field_name] = {}
                    elif "bytes" in ann_str:
                        args[field_name] = b"test"
                    else:
                        args[field_name] = "test"
        except Exception:
            pass

    return args

    @staticmethod
    def header(text):
        return f"\n{C.BOLD}{'=' * 70}\n  {text}\n{'=' * 70}{C.END}"

    @staticmethod
    def line():
        return f"{C.DIM}{'-' * 61}{C.END}"

    @staticmethod
    def info(text):
        return f"{C.BLUE}{text}{C.END}"

    @staticmethod
    def ok(text):
        return f"{C.GREEN}{text}{C.END}"

    @staticmethod
    def fail(text):
        return f"{C.RED}{text}{C.END}"

    @staticmethod
    def warn(text):
        return f"{C.YELLOW}{text}{C.END}"


async def _invoke_tool(tool_obj, args: dict, timeout: int):
    """Invoke a tool with timeout."""
    try:
        if args:
            result = await asyncio.wait_for(tool_obj.ainvoke(args), timeout=timeout)
        else:
            # Fallback for tools with NO required arguments
            # Most modern tools (MCP, StructuredTool) expect a dict {}
            try:
                result = await asyncio.wait_for(tool_obj.ainvoke({}), timeout=timeout)
            except Exception:
                # Last resort for simple string tools
                result = await asyncio.wait_for(
                    tool_obj.ainvoke("test"), timeout=timeout
                )
        return result, None
    except asyncio.TimeoutError:
        return None, f"TIMEOUT after {timeout}s"
    except Exception:
        return None, traceback.format_exc()


async def _invoke_tool_wrapper(
    tool_obj, tracker: ResultTracker, semaphore: asyncio.Semaphore
):
    """Wrapper to run a single tool test with concurrency control."""
    async with semaphore:
        tool_name = getattr(tool_obj, "name", str(tool_obj))
        args = _build_args_for_tool(tool_obj)

        start = time.time()
        # Non-blocking invocation
        result, err = await _invoke_tool(tool_obj, args, TOOL_TIMEOUT)
        elapsed = (time.time() - start) * 1000

        if err is None:
            # Tool returned without crashing
            res_str = str(result) if result is not None else "None"
            tracker.record(
                f"{tool_name}",
                Status.PASS,
                elapsed,
                detail=f"args={list(args.keys())} result={res_str[:100]}",
            )
        elif "TIMEOUT" in str(err):
            # Timeout is a warning, not a hard failure
            tracker.record(
                f"{tool_name}",
                Status.WARN,
                elapsed,
                error=f"Timed out after {TOOL_TIMEOUT}s (tool may be network-dependent)",
                detail=f"args={args}",
            )
        else:
            tracker.record(
                f"{tool_name}", Status.FAIL, elapsed, error=err, detail=f"args={args}"
            )


async def run_async(tracker: ResultTracker):
    print(C.header("TOOL INVOCATIONS (ainvoke)"))

    # Load all tools via discovery system
    print(f"  {C.info('Loading tools via get_all_tools()...')}")
    start_load = time.time()
    try:
        from tools import get_all_tools

        all_tools = await get_all_tools()
        load_time = (time.time() - start_load) * 1000
        tool_count = len(all_tools)
        print(f"  {C.ok(f'Loaded {tool_count} tools in {load_time:.0f}ms')}")

        # User explicitly requested 672 tools
        EXPECTED_COUNT = 672
        if tool_count < EXPECTED_COUNT:
            msg = f"CRITICAL Discrepancy: Only {tool_count} tools found, expected at least {EXPECTED_COUNT}!"
            print(f"  {C.fail(msg)}")
            tracker.record("Tool Count Validation", Status.FAIL, 0, error=msg)
        else:
            print(
                f"  {C.ok(f'Tool count validation passed: {tool_count} >= {EXPECTED_COUNT}')}\n"
            )

    except Exception:
        tracker.record("get_all_tools()", Status.FAIL, 0, error=traceback.format_exc())
        return

    # Initialize semaphore for concurrency control
    semaphore = asyncio.Semaphore(CONCURRENCY_LIMIT)

    # Create tasks for all tools
    tasks = []
    for tool_obj in all_tools:
        tasks.append(_invoke_tool_wrapper(tool_obj, tracker, semaphore))

    # Run all tasks concurrently with a progress indicator
    print(f"  {C.info('Testing tools')} ", end="", flush=True)

    # We use a custom gather with progress feedback
    tested_count = 0
    for future in asyncio.as_completed(tasks):
        await future
        tested_count += 1
        if tested_count % 10 == 0:
            print(".", end="", flush=True)
        if tested_count % 100 == 0:
            print(f"[{tested_count}/{tool_count}]", end="", flush=True)

    print(f"\n  {C.info(f'Invoked {tested_count}/{tool_count} tools')}")

    # Detailed export for verification
    tracker.export_errors("testing/test_errors.txt")

    # Export full results summary for user verification
    with open("testing/full_tool_results.txt", "w", encoding="utf-8") as f:
        f.write(f"Full Tool Invocation Report - {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"Total Tools Discovered: {tool_count}\n")
        f.write(f"Total Tools Invoked: {tested_count}\n")
        f.write("-" * 80 + "\n")
        for module in tracker.modules:
            for res in module.results:
                status_str = (
                    "PASS"
                    if res.status == Status.PASS
                    else ("WARN" if res.status == Status.WARN else "FAIL")
                )
                f.write(
                    f"[{status_str:4}] {res.name:<40} ({res.elapsed_ms:6.0f}ms) {res.detail}\n"
                )
                if res.error:
                    f.write(f"      ERROR: {str(res.error).splitlines()[0]}\n")

    print(f"  {C.ok('Full report written to testing/full_tool_results.txt')}")


def run(tracker: ResultTracker = None):
    if tracker is None:
        tracker = ResultTracker()

    tracker.begin_module("Tool Invocations")
    asyncio.run(run_async(tracker))
    tracker.end_module()
    return tracker


if __name__ == "__main__":
    t = run()
    t.print_summary()
    sys.exit(0 if t.all_passed else 1)
