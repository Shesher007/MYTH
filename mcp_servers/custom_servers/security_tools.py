#!/usr/bin/env python3
from fastmcp import FastMCP
from myth_config import load_dotenv
load_dotenv()
import json
import os
import hashlib
import base64
from typing import Dict, List, Optional
import subprocess
import tempfile
import platform
import time
from mcp_common import MCPUtils, SystemMonitor, tool_exception_handler, logger, ironclad_guard, QuantumEnricher

# Create MCP server
mcp = FastMCP("Security Tools Server")

@mcp.tool()
@tool_exception_handler
@ironclad_guard
async def analyze_binary_entropy(file_path: str) -> Dict:
    """Deep binary analysis: Shannon entropy and potential packed/encrypted segment detection."""
    safe_path = MCPUtils.get_safe_path(file_path)
    async with aiofiles.open(safe_path, 'rb') as f:
        data = await f.read()
    
    # Analyze in 1KB chunks to find high-entropy blocks
    chunk_size = 1024
    segments = []
    for i in range(0, len(data), chunk_size):
        chunk = data[i:i+chunk_size]
        entropy = QuantumEnricher.calculate_entropy(chunk)
        if entropy > 7.5: # Suspect encrypted/compressed
            segments.append({"offset": hex(i), "entropy": entropy, "status": "SUSPECT"})
            
    return {
        "file": safe_path.name,
        "total_entropy": QuantumEnricher.calculate_entropy(data),
        "suspicious_segments": segments[:10]
    }

@mcp.tool()
@tool_exception_handler
async def get_system_health() -> Dict:
    """Industry-grade system resource and health report."""
    return SystemMonitor.get_system_health()

# File analysis tools
@mcp.tool()
def analyze_file_hash(file_path: str, recursive: bool = False) -> Dict:
    """Generates unique MD5, SHA1, and SHA256 fingerprints. If 'recursive' is True and path is a directory, it calculates a cumulative hash of all files."""
    if not os.path.exists(file_path):
        return {"error": "Path not found", "path": file_path}
    
    def get_hash(path):
        with open(path, 'rb') as hf:
            cnt = hf.read()
            return {
                "path": path,
                "size": len(cnt),
                "md5": hashlib.md5(cnt).hexdigest(),
                "sha1": hashlib.sha1(cnt).hexdigest(),
                "sha256": hashlib.sha256(cnt).hexdigest()
            }

    try:
        if os.path.isfile(file_path):
            return get_hash(file_path)
            
        if recursive and os.path.isdir(file_path):
            res_list = []
            combined = hashlib.sha256()
            for root, _, files in os.walk(file_path):
                for name in sorted(files):
                    p = os.path.join(root, name)
                    h = get_hash(p)
                    res_list.append(h)
                    combined.update(h['sha256'].encode())
            
            return {
                "directory_path": file_path,
                "file_count": len(res_list),
                "directory_integrity_hash": combined.hexdigest(),
                "files": res_list[:10]
            }
        
        return {"error": "Path is a directory. Set recursive=True to analyze."}
    except Exception as e:
        return {"error": str(e)}

@mcp.tool()
def extract_strings(file_path: str, min_length: int = 4) -> Dict:
    """Extracts human-readable strings and identifies suspicious patterns (IPs, URLs, API keys) from binary or text files."""
    if not os.path.exists(file_path):
        return {"error": "File not found"}
        
    try:
        import re
        with open(file_path, 'rb') as sf:
            content = sf.read()
            
        # Standard string extraction
        strings = re.findall(rb'[ -~]{' + str(min_length).encode() + rb',}', content)
        decoded_strings = [s.decode('utf-8', errors='ignore') for s in strings]
        
        # Pattern identification
        patterns = {
            "ipv4": list(set(re.findall(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', "\n".join(decoded_strings)))),
            "urls": list(set(re.findall(r'https?://[^\s<>"]+|www\.[^\s<>"]+', "\n".join(decoded_strings)))),
            "api_keys": list(set(re.findall(r'(?:api|secret|key|token)[_-]?[a-zA-Z0-9]{16,}', "\n".join(decoded_strings), re.I)))
        }
        
        return {
            "file_path": file_path,
            "total_strings": len(decoded_strings),
            "findings": patterns,
            "sample_strings": decoded_strings[:50]
        }
    except Exception as e:
        return {"error": str(e)}

@mcp.tool()
def decode_base64(encoded_string: str) -> Dict:
    """Decode a base64 encoded string."""
    try:
        # Add padding if needed
        missing_padding = len(encoded_string) % 4
        if missing_padding:
            encoded_string += '=' * (4 - missing_padding)
        
        decoded_bytes = base64.b64decode(encoded_string)
        decoded_str = decoded_bytes.decode('utf-8', errors='ignore')
        
        return {
            "original": encoded_string,
            "decoded": decoded_str,
            "byte_length": len(decoded_bytes)
        }
    except Exception as e:
        return {"error": str(e)}

@mcp.tool()
def encode_base64(string_to_encode: str) -> Dict:
    """Encode a string to base64."""
    try:
        encoded_bytes = base64.b64encode(string_to_encode.encode('utf-8'))
        encoded_str = encoded_bytes.decode('utf-8')
        
        return {
            "original": string_to_encode,
            "encoded": encoded_str,
            "byte_length": len(encoded_bytes)
        }
    except Exception as e:
        return {"error": str(e)}

# Network tools for Windows
@mcp.tool()
def check_open_ports(host: str = "127.0.0.1", ports: str = "80,443,22,21,25,3389,8000,8080") -> Dict:
    """High-performance parallel port scanner. Scans specified ports on a target host."""
    import socket
    from concurrent.futures import ThreadPoolExecutor
    
    target_ports = [int(p.strip()) for p in ports.split(',') if p.strip().isdigit()]
    open_ports = []
    
    def scan_port(p):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2.0) # Extended from 0.5 to 2.0s
        res = s.connect_ex((host, p))
        s.close()
        return p if res == 0 else None

    try:
        with ThreadPoolExecutor(max_workers=20) as executor:
            scanned = list(executor.map(scan_port, target_ports))
            open_ports = [sp for sp in scanned if sp is not None]
            
        return {
            "host": host,
            "open_ports": open_ports,
            "closed_count": len(target_ports) - len(open_ports),
            "total_scanned": len(target_ports),
            "timestamp": time.strftime('%Y-%m-%d %H:%M:%S')
        }
    except Exception as e:
        return {"error": str(e)}

@mcp.tool()
def process_list(filter_name: str = None) -> Dict:
    """Get list of running processes with performance metrics and optional filtering."""
    import psutil
    processes = []
    try:
        for proc in psutil.process_iter(['pid', 'name', 'username', 'cpu_percent', 'memory_info']):
            try:
                pinfo = proc.info
                if filter_name and filter_name.lower() not in (pinfo['name'] or "").lower():
                    continue
                    
                processes.append({
                    "pid": pinfo['pid'],
                    "name": pinfo['name'],
                    "user": pinfo['username'],
                    "cpu": f"{pinfo['cpu_percent']}%",
                    "memory": f"{pinfo['memory_info'].rss / 1024 / 1024:.2f} MB" if pinfo['memory_info'] else "N/A"
                })
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        
        # Sort by memory usage
        processes.sort(key=lambda x: float(x['memory'].split()[0]) if 'N/A' not in x['memory'] else 0, reverse=True)
        
        return {
            "total_processes": len(processes),
            "processes": processes[:50]
        }
    except Exception as e:
        return {"error": str(e)}

# Security analysis tools
@mcp.tool()
def analyze_password_strength(password: str) -> Dict:
    """Performs a deep logic check on passwords, calculating entropy and identifying weaknesses (e.g., lack of special characters or insufficient length)."""
    score = 0
    feedback = []
    
    # Length check
    if len(password) >= 12:
        score += 2
    elif len(password) >= 8:
        score += 1
    else:
        feedback.append("Password is too short (minimum 8 characters recommended)")
    
    # Character variety
    import re
    
    if re.search(r'[A-Z]', password):
        score += 1
    else:
        feedback.append("Add uppercase letters")
    
    if re.search(r'[a-z]', password):
        score += 1
    else:
        feedback.append("Add lowercase letters")
    
    if re.search(r'\d', password):
        score += 1
    else:
        feedback.append("Add numbers")
    
    if re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        score += 1
    else:
        feedback.append("Add special characters")
    
    # Common patterns check
    common_patterns = ['123', 'password', 'admin', 'qwerty', 'letmein']
    if any(pattern in password.lower() for pattern in common_patterns):
        score -= 1
        feedback.append("Avoid common password patterns")
    
    # Strength rating
    if score >= 5:
        strength = "Strong"
    elif score >= 3:
        strength = "Moderate"
    else:
        strength = "Weak"
    
    return {
        "password_length": len(password),
        "score": score,
        "strength": strength,
        "recommendations": feedback,
        "entropy_estimate": len(set(password)) * len(password)  # Simplified entropy
    }

@mcp.tool()
def generate_password(
    length: int = 16, 
    include_special: bool = True,
    # Accept alternative parameter names
    use_special: Optional[bool] = None,
    use_special_chars: Optional[bool] = None,
    special: Optional[bool] = None
) -> Dict:
    """Produces high-entropy, random strings."""
    import random
    import string
    
    # Handle different parameter names for 'special'
    if use_special is not None:
        include_special = use_special
    elif use_special_chars is not None:
        include_special = use_special_chars
    elif special is not None:
        include_special = special
    
    characters = string.ascii_letters + string.digits
    if include_special:
        characters += string.punctuation
    
    password = ''.join(random.choice(characters) for _ in range(length))
    
    return {
        "password": password,
        "length": length,
        "include_special": include_special,
        "note": f"Generated {length}-character password with special chars: {include_special}"
    }

# File metadata analysis
@mcp.tool()
def get_file_metadata(file_path: str) -> Dict:
    """Extracts OS-level forensic data, including exact byte size, creation timestamps, and the last time a file was accessed or modified."""
    if not os.path.exists(file_path):
        return {"error": "File not found", "file_path": file_path}
    
    try:
        stat_info = os.stat(file_path)
        
        metadata = {
            "file_path": file_path,
            "size_bytes": stat_info.st_size,
            "size_human": f"{stat_info.st_size / 1024:.2f} KB",
            "created": stat_info.st_ctime,
            "created_iso": time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(stat_info.st_ctime)),
            "modified": stat_info.st_mtime,
            "modified_iso": time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(stat_info.st_mtime)),
            "accessed": stat_info.st_atime,
            "accessed_iso": time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(stat_info.st_atime)),
            "is_file": os.path.isfile(file_path),
            "is_dir": os.path.isdir(file_path),
            "extension": os.path.splitext(file_path)[1],
            "filename": os.path.basename(file_path)
        }
        
        return metadata
    except Exception as e:
        return {"error": str(e)}

if __name__ == "__main__":
    import os
    # We force the port from the environment variable set in mcp_client.py
    # If not found, it defaults to 8001
    port = int(os.getenv("FASTMCP_PORT", 8001))
    # 'sse' transport is required for the client to connect via URL
    mcp.run(transport="sse", port=port, show_banner=False)
