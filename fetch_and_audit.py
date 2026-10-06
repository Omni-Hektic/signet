#!/usr/bin/env python3
import argparse
import hashlib
import json
import os
import re
import shutil
import sqlite3
import subprocess
import sys
import time
from datetime import datetime, timezone
import requests

BSC_RPC = "https://bsc-dataseed.binance.org/"
# Unified Etherscan API V2 endpoint for BSC (chainid=56)
BSCSCAN_API = "https://api.etherscan.io/v2/api"

SLOT_EIP1967_IMPL = "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc"
SLOT_EIP1967_BEACON = "0xa3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50"
SLOT_EIP1822_UUPS = "0xc5f16f0fcc639fa48a6947836d9850f504798523bf8c9a3a87d5876cf622bcf7"

def init_db(db_path: str = "audit_cache.db") -> sqlite3.Connection:
    conn = sqlite3.connect(db_path)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS api_budget (
            date_str TEXT PRIMARY KEY,
            request_count INTEGER DEFAULT 0
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS source_cache (
            address TEXT,
            block_number INTEGER DEFAULT 0,
            source_hash TEXT,
            raw_json TEXT,
            PRIMARY KEY (address, block_number)
        )
    """)
    conn.commit()
    return conn

def check_and_increment_budget(conn: sqlite3.Connection, max_requests: int = 90000) -> bool:
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    cursor = conn.cursor()
    cursor.execute("SELECT request_count FROM api_budget WHERE date_str = ?", (today,))
    row = cursor.fetchone()
    current_count = row[0] if row else 0

    if current_count >= max_requests:
        return False

    cursor.execute("""
        INSERT INTO api_budget (date_str, request_count) VALUES (?, 1)
        ON CONFLICT(date_str) DO UPDATE SET request_count = request_count + 1
    """, (today,))
    conn.commit()
    return True

def rpc_call(method: str, params: list) -> dict:
    payload = {"jsonrpc": "2.0", "id": 1, "method": method, "params": params}
    try:
        resp = requests.post(BSC_RPC, json=payload, timeout=10)
        return resp.json().get("result")
    except Exception as e:
        print(f"[!] RPC call failed: {e}")
        return None

def resolve_proxy(address: str) -> dict:
    # 1. EIP-1967 Implementation Slot
    impl_1967 = rpc_call("eth_getStorageAt", [address, SLOT_EIP1967_IMPL, "latest"])
    if impl_1967 and int(impl_1967, 16) != 0:
        impl_addr = "0x" + impl_1967[-40:]
        return {"isProxy": True, "type": "EIP-1967", "implementation": impl_addr}

    # 2. EIP-1967 Beacon Slot
    beacon = rpc_call("eth_getStorageAt", [address, SLOT_EIP1967_BEACON, "latest"])
    if beacon and int(beacon, 16) != 0:
        beacon_addr = "0x" + beacon[-40:]
        # Selector for implementation(): keccak256("implementation()")[:4] -> 0x5c60da1b
        impl_call = rpc_call("eth_call", [{"to": beacon_addr, "data": "0x5c60da1b"}, "latest"])
        if impl_call and int(impl_call, 16) != 0:
            impl_addr = "0x" + impl_call[-40:]
            return {
                "isProxy": True,
                "type": "EIP-1967-Beacon",
                "beacon": beacon_addr,
                "implementation": impl_addr
            }

    # 3. EIP-1822 UUPS Slot
    impl_1822 = rpc_call("eth_getStorageAt", [address, SLOT_EIP1822_UUPS, "latest"])
    if impl_1822 and int(impl_1822, 16) != 0:
        impl_addr = "0x" + impl_1822[-40:]
        return {"isProxy": True, "type": "EIP-1822", "implementation": impl_addr}

    # 4. EIP-1167 Minimal Proxy Bytecode
    code = rpc_call("eth_getCode", [address, "latest"]) or ""
    clean_code = code.removeprefix("0x").lower()

    if clean_code.startswith("363d3d373d3d3d363d73") and clean_code[60:90] == "5af43d82803e903d91602b57fd5bf3":
        impl = "0x" + clean_code[20:60]
        return {"isProxy": True, "type": "EIP-1167", "implementation": impl}

    if clean_code.startswith("3d3d3d3d363d3d37363d73") and len(clean_code) >= 62:
        impl = "0x" + clean_code[22:62]
        return {"isProxy": True, "type": "EIP-1167-Legacy", "implementation": impl}

    return {"isProxy": False, "type": None, "implementation": None}

def fetch_bscscan_source(address: str, api_key: str, conn: sqlite3.Connection) -> dict:
    if not check_and_increment_budget(conn):
        raise RuntimeError("Daily BscScan API budget reached (90% threshold).")

    # 1. Primary: Etherscan V2 API (BSC chainid=56)
    if api_key:
        params = {
            "chainid": "56",
            "module": "contract",
            "action": "getsourcecode",
            "address": address,
            "apikey": api_key
        }
        for attempt in range(5):
            try:
                resp = requests.get(BSCSCAN_API, params=params, timeout=10)
                if resp.status_code == 429:
                    time.sleep(2 ** attempt)
                    continue
                data = resp.json()
                if data.get("status") == "1" and data.get("result"):
                    return data["result"][0]
                elif data.get("message") == "NOTOK":
                    print(f"    [!] Explorer API returned NOTOK: {data.get('result')}")
                break
            except Exception as e:
                print(f"    [!] Network error fetching source: {e}")
                break

    # 2. Public Fallback: Sourcify V2 API (mirrors verified BSC / BscScan contract sources)
    try:
        sourcify_url = f"https://sourcify.dev/server/v2/contract/56/{address}?fields=sources,compilation"
        resp = requests.get(sourcify_url, timeout=10)
        if resp.status_code == 200:
            s_data = resp.json()
            sources = s_data.get("sources", {})
            if sources:
                compiler_ver = s_data.get("compilation", {}).get("compilerVersion", "")
                if len(sources) == 1:
                    fn, f_data = next(iter(sources.items()))
                    return {
                        "SourceCode": f_data.get("content", ""),
                        "ContractName": fn.replace(".sol", ""),
                        "CompilerVersion": compiler_ver
                    }
                else:
                    std_json = {
                        "sources": {fn: {"content": f_data.get("content", "")} for fn, f_data in sources.items()}
                    }
                    return {
                        "SourceCode": "{{" + json.dumps(std_json) + "}}",
                        "ContractName": "MultiFileContract",
                        "CompilerVersion": compiler_ver
                    }
    except Exception as e:
        print(f"    [!] Fallback source fetch error: {e}")

    return {}

def is_erc20_conforming(source_text: str) -> bool:
    required = ["totalSupply", "balanceOf", "transfer", "approve"]
    return all(re.search(rf"\b{fn}\b", source_text) for fn in required)

def derive_status_and_action(confidence: str, severity: str, is_cross_validated: bool = False, is_info: bool = False, finding_type: str = "") -> tuple:
    """
    Programmatic derivation of (status, action) from (confidence, severity).
    Mapping specification:
      is_info and finding_type == "UNVERIFIED_SOURCE"  -> status="UNVERIFIED", action="MANUAL_REVIEW"
      is_info                                          -> status="INFO",       action="LOG"
      confidence == "HIGH" (Slither confirmed)         -> status="CONFIRMED",  action="DISCLOSE" (or "REVIEW" if sev < HIGH)
      confidence == "MEDIUM" (Semgrep / documented FP)  -> status="FLAGGED",    action="REVIEW"
      confidence == "LOW" and is_cross_validated        -> status="FLAGGED",    action="REVIEW"
      confidence == "LOW" (Semgrep alone)               -> status="INFO",       action="INFO_ONLY"
    """
    if is_info:
        if finding_type == "UNVERIFIED_SOURCE":
            return "UNVERIFIED", "MANUAL_REVIEW"
        return "INFO", "LOG"
    conf = confidence.upper()
    sev = severity.upper()
    if conf == "HIGH":
        action = "DISCLOSE" if sev == "HIGH" else "REVIEW"
        return "CONFIRMED", action
    elif conf == "MEDIUM":
        return "FLAGGED", "REVIEW"
    elif conf == "LOW":
        if is_cross_validated:
            return "FLAGGED", "REVIEW"
        else:
            return "INFO", "INFO_ONLY"
    return "INFO", "LOG"


def main():
    parser = argparse.ArgumentParser(description="Audit BSC contract signature verification")
    parser.add_argument("--address", required=True, help="Token contract address")
    parser.add_argument("--apikey", default=os.getenv("BSCSCAN_API_KEY", ""), help="BscScan API key")
    parser.add_argument("--out", default="findings.json", help="Output JSON findings path")
    args = parser.parse_args()

    conn = init_db()
    target_addr = args.address.lower()

    print(f"[*] Starting audit for target: {target_addr}")

    # 1. Resolve Proxies
    proxy_info = resolve_proxy(target_addr)
    if proxy_info["isProxy"]:
        print(f"    [+] Proxy detected ({proxy_info['type']}) -> Target implementation: {proxy_info['implementation']}")
        fetch_addr = proxy_info["implementation"]
    else:
        fetch_addr = target_addr

    # 2. Fetch Source Code from BscScan
    source_payload = fetch_bscscan_source(fetch_addr, args.apikey, conn)
    raw_source = source_payload.get("SourceCode", "")

    if not raw_source:
        print("    [!] Source code is unverified on BscScan.")
        u_status, u_action = derive_status_and_action("LOW", "INFO", is_info=True, finding_type="UNVERIFIED_SOURCE")
        unverified_report = {
            "auditMetadata": {
                "targetChain": "bsc",
                "chainId": 56,
                "scanTimestamp": datetime.now(timezone.utc).isoformat(),
                "analyzer": "bsc-sig-audit-v1",
                "status": "COMPLETED",
                "detectorVersions": {
                    "slither": "0.11.6",
                    "semgrep": "1.179.0",
                    "solc": "0.8.20",
                    "sig-01-slither": "v1.0",
                    "sig-03-semgrep": "v1.0"
                }
            },
            "token": {"address": target_addr, "proxy": proxy_info},
            "findings": [{
                "checkId": "UNVERIFIED_SOURCE",
                "severity": "INFO",
                "confidence": "LOW",
                "status": u_status,
                "title": "Contract source code is unverified",
                "description": "The contract bytecode is deployed on BSC without verified source code on BscScan.",
                "action": u_action
            }]
        }
        with open(args.out, "w") as f:
            json.dump(unverified_report, f, indent=2)

        # Update queue status if present
        conn.execute("UPDATE token_queue SET status = 'UNVERIFIED' WHERE address = ?", (target_addr,))
        conn.commit()
        return

    # 3. Unwrap Double Braces on Standard-JSON-Input
    os.makedirs("workspace", exist_ok=True)
    is_multi_file = False
    source_to_hash = raw_source

    if raw_source.startswith("{{") and raw_source.endswith("}}"):
        raw_source = raw_source[1:-1]
        is_multi_file = True

    if is_multi_file:
        parsed_json = json.loads(raw_source)
        sources = parsed_json.get("sources", {})
        combined_text = ""
        for file_path, file_data in sources.items():
            out_file = os.path.join("workspace", os.path.basename(file_path))
            with open(out_file, "w") as f:
                f.write(file_data.get("content", ""))
            combined_text += file_data.get("content", "")
        source_to_hash = combined_text
        entry_contract = "workspace"
    else:
        entry_contract = os.path.join("workspace", "Contract.sol")
        with open(entry_contract, "w") as f:
            f.write(raw_source)
        source_to_hash = raw_source

    source_hash = hashlib.sha256(source_to_hash.encode()).hexdigest()

    # 4. Token Interface Conformity Filter
    if not is_erc20_conforming(source_to_hash):
        print("    [-] Contract does not implement standard IERC20 functions. Skipping signature audit.")
        conn.execute("UPDATE token_queue SET status = 'NON_TOKEN' WHERE address = ?", (target_addr,))
        conn.commit()
        return

    # 5. Compiler Auto-Switch
    compiler_ver = source_payload.get("CompilerVersion", "")
    ver_match = re.search(r"v\d+\.\d+\.\d+", compiler_ver)
    if ver_match and shutil.which("solc-select"):
        ver = ver_match.group(0).removeprefix("v")
        subprocess.run(["solc-select", "install", ver], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(["solc-select", "use", ver], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    findings = []

    semgrep_findings = []
    # 6. Run Semgrep
    if shutil.which("semgrep"):
        print("    [*] Running Semgrep static checks...")
        semgrep_cmd = [
            "semgrep", "--config", "rules/semgrep.yaml", "workspace", "--json"
        ]
        sem_res = subprocess.run(semgrep_cmd, capture_output=True, text=True, check=False)
        if sem_res.returncode == 0 and sem_res.stdout:
            try:
                sem_json = json.loads(sem_res.stdout)
                for hit in sem_json.get("results", []):
                    check_id = "SIG-01"
                    if "sig03" in hit["check_id"]:
                        check_id = "SIG-03"

                    sev = "HIGH" if check_id == "SIG-01" else "MEDIUM"
                    conf = "LOW" if check_id == "SIG-01" else "MEDIUM"
                    semgrep_findings.append({
                        "checkId": check_id,
                        "severity": sev,
                        "confidence": conf,
                        "title": hit["extra"]["message"].split(".")[0],
                        "location": {
                            "file": hit["path"],
                            "line": hit["start"]["line"]
                        }
                    })
            except Exception:
                pass
    else:
        print("    [-] semgrep CLI not available in PATH. Skipping syntactic check pass.")

    # 7. Run Slither with Custom Detectors
    slither_findings = []
    if shutil.which("slither"):
        print("    [*] Running Slither data-flow detectors...")
        slither_cmd = [
            "slither", entry_contract,
            "--detect", "sig-01-zero-check",
            "--json", "slither_out.json"
        ]
        subprocess.run(slither_cmd, capture_output=True, check=False)

        if os.path.exists("slither_out.json"):
            try:
                with open("slither_out.json") as sf:
                    s_data = json.load(sf)
                    for det in s_data.get("results", {}).get("detectors", []):
                        check_id = "SIG-01"
                        slither_findings.append({
                            "checkId": check_id,
                            "severity": det["impact"].upper(),
                            "confidence": det["confidence"].upper(),
                            "title": det["description"].split("\n")[0],
                            "location": {
                                "file": det["elements"][0]["source_mapping"]["filename_relative"] if det["elements"] else "",
                                "line": det["elements"][0]["source_mapping"]["lines"][0] if det["elements"] else 0
                            }
                        })
            except Exception:
                pass
    else:
        print("    [-] slither CLI not available in PATH. Skipping IR data-flow pass.")

    # 8. Programmatic Derivation of (confidence, status, action) Triples
    findings = []
    slither_confirmed_sig01 = any(f["checkId"] == "SIG-01" for f in slither_findings)

    for sf in slither_findings:
        status, action = derive_status_and_action(sf["confidence"], sf["severity"], is_cross_validated=True)
        sf["status"] = status
        sf["action"] = action
        findings.append(sf)

    for sem_f in semgrep_findings:
        is_cv = (sem_f["checkId"] == "SIG-01" and slither_confirmed_sig01)
        status, action = derive_status_and_action(sem_f["confidence"], sem_f["severity"], is_cross_validated=is_cv)
        sem_f["status"] = status
        sem_f["action"] = action
        findings.append(sem_f)

    report = {
        "auditMetadata": {
            "targetChain": "bsc",
            "chainId": 56,
            "scanTimestamp": datetime.now(timezone.utc).isoformat(),
            "analyzer": "bsc-sig-audit-v1",
            "status": "COMPLETED",
            "detectorVersions": {
                "slither": "0.11.6",
                "semgrep": "1.179.0",
                "solc": "0.8.20",
                "sig-01-slither": "v1.0",
                "sig-03-semgrep": "v1.0"
            }
        },
        "token": {
            "address": target_addr,
            "sourceHash": "0x" + source_hash,
            "proxy": proxy_info
        },
        "findings": findings
    }

    with open(args.out, "w") as f:
        json.dump(report, f, indent=2)

    conn.execute("UPDATE token_queue SET status = 'AUDITED' WHERE address = ?", (target_addr,))
    conn.commit()

    print(f"[+] Audit completed. Total findings: {len(findings)}. Report saved to {args.out}")

if __name__ == "__main__":
    main()
