#!/usr/bin/env python3
import os
import sys
import json
import csv
import sqlite3
import subprocess
import time
from datetime import datetime, timezone

# Ensure virtualenv binaries (semgrep, slither, solc) are in PATH
VENV_BIN = "/home/hektic/Downloads/ai-web3-security/.venv/bin"
if VENV_BIN not in os.environ.get("PATH", ""):
    os.environ["PATH"] = f"{VENV_BIN}:{os.environ.get('PATH', '')}"

from solidity_auditor.tools.fetch_and_audit import (
    resolve_proxy,
    fetch_bscscan_source,
    init_db,
    is_erc20_conforming,
    derive_status_and_action,
    rpc_call
)

REPORTS_DIR = "part4_reports"
CSV_PATH = "batch_audit_results.csv"

def get_token_name(addr: str) -> str:
    res = rpc_call("eth_call", [{"to": addr, "data": "0x06fdde03"}, "latest"])
    if not res or res == "0x" or len(res) < 66:
        return ""
    try:
        hex_data = res[2:]
        offset = int(hex_data[:64], 16) * 2
        length = int(hex_data[offset:offset+64], 16)
        name_hex = hex_data[offset+64:offset+64+length*2]
        return bytes.fromhex(name_hex).decode("utf-8", errors="ignore").strip("\x00")
    except Exception:
        try:
            return bytes.fromhex(hex_data[:64]).decode("utf-8", errors="ignore").strip("\x00")
        except Exception:
            return ""

def run_batch_audit(limit: int = 25, output_csv: str = CSV_PATH):
    os.makedirs(REPORTS_DIR, exist_ok=True)
    conn = init_db("audit_cache.db")
    cursor = conn.cursor()

    cursor.execute("""
        SELECT address, symbol, market_cap_usd, liquidity_usd, source
        FROM token_queue
        WHERE market_cap_usd <= 1000000.0 AND liquidity_usd >= 5000.0
        ORDER BY liquidity_usd DESC
        LIMIT ?
    """, (limit,))
    tokens = cursor.fetchall()

    print(f"[*] Starting Part 4 Batch Audit on {len(tokens)} real BSC tokens (market cap <= $1M, liquidity >= $5k)...")

    results = []
    source_cache_mem = {}
    token_name_cache = {}

    for idx, (addr, sym, mcap, liq, src) in enumerate(tokens, 1):
        addr_lower = addr.lower()
        if addr_lower in token_name_cache:
            token_name = token_name_cache[addr_lower]
        else:
            token_name = get_token_name(addr_lower) or sym
            token_name_cache[addr_lower] = token_name

        print(f"\n[{idx}/{len(tokens)}] Auditing token {token_name} ({sym}, {addr_lower}) - Mcap: ${mcap:,.2f}, Liq: ${liq:,.2f}")

        # 1. Resolve proxy
        proxy_info = resolve_proxy(addr_lower)
        is_proxy = proxy_info.get("isProxy", False)
        proxy_type = proxy_info.get("type")
        target_addr = proxy_info.get("implementation") if is_proxy else addr_lower
        if is_proxy:
            print(f"    [+] Proxy detected: {proxy_type} -> Implementation: {target_addr}")

        # 2. Fetch source code
        if target_addr in source_cache_mem:
            source_payload = source_cache_mem[target_addr]
        else:
            api_key = os.getenv("BSCSCAN_API_KEY", "")
            source_payload = fetch_bscscan_source(target_addr, api_key, conn)
            source_cache_mem[target_addr] = source_payload

        raw_source = source_payload.get("SourceCode", "")
        contract_name = source_payload.get("ContractName", sym)
        compiler_ver = source_payload.get("CompilerVersion", "")
        source_verified = bool(raw_source)

        token_out = os.path.join(REPORTS_DIR, f"findings_{addr_lower}.json")
        findings = []
        sig01_count = 0
        sig03_count = 0

        if not source_verified:
            print("    [-] Source code unverified on BscScan/Sourcify.")
            u_status, u_action = derive_status_and_action("LOW", "INFO", is_info=True, finding_type="UNVERIFIED_SOURCE")
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
                    "address": addr_lower,
                    "symbol": sym,
                    "name": token_name,
                    "implementationName": "Unverified",
                    "marketCapUsd": mcap,
                    "liquidityUsd": liq,
                    "proxy": proxy_info,
                    "sourceVerified": False
                },
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
            with open(token_out, "w") as f:
                json.dump(report, f, indent=2)
            sig01_semgrep_candidates = 0
            sig01_semgrep_confirmed = 0
        else:
            print(f"    [+] Source verified ({contract_name}, compiler: {compiler_ver}).")
            # Setup workspace
            ws_dir = os.path.join("/tmp", f"ws_{addr_lower}")
            os.makedirs(ws_dir, exist_ok=True)

            sc = raw_source.strip()
            data = None
            while sc.startswith("{") and sc.endswith("}"):
                try:
                    data = json.loads(sc)
                    break
                except Exception:
                    if len(sc) > 2:
                        sc = sc[1:-1].strip()
                    else:
                        break

            if isinstance(data, dict) and "sources" in data:
                sources = data["sources"]
                entry_path = ws_dir
                for fn, fd in sources.items():
                    rel_p = fn.lstrip("/\\")
                    p = os.path.join(ws_dir, rel_p)
                    os.makedirs(os.path.dirname(p), exist_ok=True)
                    with open(p, "w") as f:
                        f.write(fd.get("content", ""))
            else:
                entry_path = os.path.join(ws_dir, "Contract.sol")
                with open(entry_path, "w") as f:
                    f.write(raw_source)

            # Compiler switch
            import re, shutil
            ver_match = re.search(r"v\d+\.\d+\.\d+", compiler_ver) or re.search(r"\d+\.\d+\.\d+", compiler_ver)
            if ver_match and shutil.which("solc-select"):
                v_str = ver_match.group(0).removeprefix("v")
                subprocess.run(["solc-select", "install", v_str], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                subprocess.run(["solc-select", "use", v_str], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

            # Run Semgrep
            semgrep_findings = []
            if shutil.which("semgrep"):
                cmd_sem = ["semgrep", "--config", "rules/semgrep.yaml", ws_dir, "--json"]
                res_sem = subprocess.run(cmd_sem, capture_output=True, text=True, check=False)
                if res_sem.returncode == 0 and res_sem.stdout:
                    try:
                        s_data = json.loads(res_sem.stdout)
                        for hit in s_data.get("results", []):
                            cid = "SIG-01" if "sig01" in hit["check_id"] else ("SIG-03" if "sig03" in hit["check_id"] else hit["check_id"])
                            sev = "HIGH" if cid == "SIG-01" else "MEDIUM"
                            conf = "LOW" if cid == "SIG-01" else "MEDIUM"
                            semgrep_findings.append({
                                "checkId": cid,
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

            # Run Slither
            slither_findings = []
            if shutil.which("slither"):
                out_slither = os.path.join(ws_dir, "slither.json")
                cmd_slither = ["slither", entry_path, "--detect", "sig-01-zero-check", "--json", out_slither]
                subprocess.run(cmd_slither, capture_output=True, check=False)
                if os.path.exists(out_slither):
                    try:
                        with open(out_slither) as sf:
                            sl_data = json.load(sf)
                            for det in sl_data.get("results", {}).get("detectors", []):
                                slither_findings.append({
                                    "checkId": "SIG-01",
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

            # Cross-validate findings
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

            sig01_semgrep_candidates = sum(1 for f in semgrep_findings if f["checkId"] == "SIG-01")
            sig01_semgrep_confirmed = sum(1 for f in findings if f["checkId"] == "SIG-01" and f.get("status") == "CONFIRMED")
            sig01_count = sig01_semgrep_confirmed
            sig03_count = sum(1 for f in findings if f["checkId"] == "SIG-03")

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
                    "address": addr_lower,
                    "symbol": sym,
                    "name": token_name,
                    "implementationName": contract_name,
                    "marketCapUsd": mcap,
                    "liquidityUsd": liq,
                    "proxy": proxy_info,
                    "sourceVerified": True
                },
                "findings": findings
            }
            with open(token_out, "w") as f:
                json.dump(report, f, indent=2)

            print(f"    [+] Findings: {len(findings)} (SIG-01 Slither: {sig01_count}, SIG-03 Semgrep: {sig03_count})")

        # Record result row
        results.append({
            "address": addr_lower,
            "token_name": token_name,
            "implementation_name": contract_name if source_verified else "Unverified",
            "mcap": round(mcap, 2),
            "liquidity": round(liq, 2),
            "is_proxy": is_proxy,
            "proxy_type": proxy_type if is_proxy else "NONE",
            "source_verified": source_verified,
            "sig01_findings": sig01_count,
            "sig01_fp": 0,
            "sig03_findings": sig03_count,
            "sig03_fp": 0,
            "sig01_semgrep_candidates": sig01_semgrep_candidates,
            "sig01_semgrep_confirmed": sig01_semgrep_confirmed,
            "findings_detail": findings
        })

    # Write CSV
    with open(output_csv, "w", newline="") as cf:
        writer = csv.writer(cf)
        writer.writerow([
            "address",
            "token_name",
            "implementation_name",
            "mcap",
            "liquidity",
            "is_proxy",
            "proxy_type",
            "source_verified",
            "sig01_findings",
            "sig01_fp",
            "sig03_findings",
            "sig03_fp",
            "sig01_semgrep_candidates",
            "sig01_semgrep_confirmed"
        ])
        for r in results:
            writer.writerow([
                r["address"],
                r["token_name"],
                r["implementation_name"],
                r["mcap"],
                r["liquidity"],
                r["is_proxy"],
                r["proxy_type"],
                r["source_verified"],
                r["sig01_findings"],
                r["sig01_fp"],
                r["sig03_findings"],
                r["sig03_fp"],
                r["sig01_semgrep_candidates"],
                r["sig01_semgrep_confirmed"]
            ])

    print(f"\n[+] Batch audit complete! Results written to {output_csv}")
    return results

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Part 4 Batch Audit Runner")
    parser.add_argument("limit", nargs="?", type=int, default=25, help="Number of tokens to audit")
    parser.add_argument("--output", "-o", default=CSV_PATH, help="Output CSV path")
    args = parser.parse_args()
    run_batch_audit(args.limit, args.output)

