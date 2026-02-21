import os
import re


def fix_file(filepath):
    try:
        content = open(filepath, "r", encoding="utf-8", errors="ignore").read()
        original_content = content

        # 1. Fix E722 (Bare except)
        # Match "except:" followed by newline, or "except: " followed by code
        # We replace "except:" with "except Exception:"
        content = re.sub(r"(\n\s*)except:(\s*\n)", r"\1except Exception:\2", content)
        content = re.sub(r"(\n\s*)except:(\s+)", r"\1except Exception:\2", content)

        # 2. Fix E701 (Multiple statements on one line)
        # Focus on "except Exception: code" -> "except Exception:\n    code"
        # and "if cond: break/continue/pass" -> "if cond:\n    break/continue/pass"
        # We use a cautious approach for E701 to not break indentation

        lines = content.splitlines()
        new_lines = []
        for line in lines:
            # Match "except Exception: pass/break/continue"
            match_except = re.match(
                r"^(\s*)except ([\w\s,()\*]+):(\s+)(pass|break|continue|return.*|print.*|os\..*|sys\..*|shutil\..*)$",
                line,
            )
            if match_except:
                indent = match_except.group(1)
                exc = match_except.group(2)
                code = match_except.group(4)
                new_lines.append(f"{indent}except {exc}:")
                new_lines.append(f"{indent}    {code}")
                continue

            # Match "if cond: break/continue/pass"
            match_if = re.match(r"^(\s*)if (.+):(\s+)(break|continue|pass)$", line)
            if match_if:
                indent = match_if.group(1)
                cond = match_if.group(2)
                code = match_if.group(4)
                new_lines.append(f"{indent}if {cond}:")
                new_lines.append(f"{indent}    {code}")
                continue

            new_lines.append(line)

        content = "\n".join(new_lines)

        # 3. Fix F541 (f-string without placeholders)
        # Search for f'...' or f"..." without {
        def fix_fstring(match):
            s = match.group(0)
            if "{" not in s:
                return s[1:]  # Remove 'f'
            return s

        content = re.sub(r"f'[^'\\n]*'", fix_fstring, content)
        content = re.sub(r'f"[^"\\n]*"', fix_fstring, content)

        if content != original_content:
            with open(filepath, "w", encoding="utf-8", newline="") as f:
                f.write(content)
            return True
        return False
    except Exception as e:
        print(f"Error fixing {filepath}: {e}")
        return False


# List of files from error report (extracted previously)
files_to_fix = [
    "rag_system/document_processor.py",
    "run_tauri.py",
    "scripts/sync_requirements.py",
    "tests/audit_dependencies.py",
    "tests/run_all.py",
    "tests/test_mcp_client.py",
    "tests/test_tool_invocations.py",
    "tests/verify_resolver.py",
    "tools/__init__.py",
    "tools/cache_manager.py",
    "tools/cloud/iac_cicd.py",
    "tools/cloud/k8s_advanced.py",
    "tools/ctf/binary_expert.py",
    "tools/ctf/crypto_master.py",
    "tools/ctf/entropy_analyzer.py",
    "tools/ctf/esoteric_ciphers.py",
    "tools/ctf/forensics.py",
    "tools/ctf/network_forensics.py",
    "tools/ctf/web_ctf_master.py",
    "tools/ctf/web_esoteric.py",
    "tools/evasion/anti_analysis.py",
    "tools/evasion/edr_aware_payloads.py",
    "tools/evasion/execution_mastery.py",
    "tools/evasion/host_audit_advanced.py",
    "tools/evasion/maldev_advanced.py",
    "tools/evasion/payload_engineering.py",
    "tools/evasion/techniques.py",
    "tools/evasion/unhooking.py",
    "tools/exploitation/api_prober.py",
    "tools/exploitation/clr_engineering.py",
    "tools/exploitation/evasion_generators.py",
    "tools/exploitation/host_exploitation.py",
    "tools/exploitation/identity_exploitation.py",
    "tools/exploitation/infrastructure_exploitation.py",
    "tools/exploitation/polyglot_payloads.py",
    "tools/exploitation/process_injection.py",
    "tools/exploitation/situational_awareness.py",
    "tools/exploitation/syscall_factory.py",
    "tools/exploitation/web/protocols.py",
    "tools/intelligence/ai.py",
    "tools/intelligence/browser.py",
    "tools/intelligence/identity_audit.py",
    "tools/intelligence/osint.py",
    "tools/intelligence/research_engine.py",
    "tools/intelligence/search.py",
    "tools/intelligence/social.py",
    "tools/recon/active.py",
    "tools/recon/advanced_osint.py",
    "tools/recon/asm_engine.py",
    "tools/recon/cloud_discovery.py",
    "tools/recon/content_discovery.py",
    "tools/recon/discovery.py",
    "tools/recon/industrial_iot.py",
    "tools/recon/infrastructure_services.py",
    "tools/recon/internal_network.py",
    "tools/recon/network.py",
    "tools/recon/passive.py",
    "tools/recon/pd_all_subdomains.py",
    "tools/recon/spectral_fingerprint.py",
    "tools/recon/supply_chain_recon.py",
    "tools/reverse_engineering/binary_analyzer.py",
    "tools/reverse_engineering/decompilation_context.py",
    "tools/reverse_engineering/diffing_engine.py",
    "tools/reverse_engineering/dynamic_helper.py",
    "tools/reverse_engineering/firmware_advanced.py",
    "tools/reverse_engineering/firmware_audit.py",
    "tools/reverse_engineering/nexus_orchestrator.py",
    "tools/reverse_engineering/symbol_resolver.py",
    "tools/reverse_engineering/vuln_context_elite.py",
    "tools/reverse_engineering/vulnerability_research.py",
    "tools/utilities/file_generator.py",
    "tools/utilities/files.py",
    "tools/utilities/integrations.py",
    "tools/utilities/report.py",
    "tools/utilities/shell.py",
    "tools/utilities/utils.py",
    "tools/vr/exploit_automation.py",
    "tools/vr/gadget_discovery.py",
    "tools/vr/heap_exploitation.py",
    "tools/vr/kernel_exploitation.py",
    "tools/web/advanced_ssrf.py",
    "tools/web/auth_logic.py",
    "tools/web/distributed_grid.py",
    "tools/web/modern_api.py",
    "tools/web/ssti_prober.py",
    "ui/src-tauri/binaries/nmap/ndiff.py",
]

modified_count = 0
for f in files_to_fix:
    f_path = f.replace("\\", "/")
    if os.path.exists(f_path):
        if fix_file(f_path):
            modified_count += 1

print(f"Summary: Fixed {modified_count} files.")
