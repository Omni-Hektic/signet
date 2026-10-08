#!/usr/bin/env python3
"""
validate_250_pools.py: Phase 1 Stress-Test Runner for Signet
Ingests and audits 250 real BSC token pools to empirically measure:
1. Vulnerability hit rate (validating/falsifying the Stream 1 bounty thesis).
2. Proxy de-aliasing rate across larger sample sizes.
3. Compute and cache performance benchmarks.
"""

import os
import sys
import time
import requests
import sqlite3
from datetime import datetime, timezone

from discover_tokens import init_queue_db, HEADERS
from batch_audit_part4 import run_batch_audit

DEXSCREENER_SEARCH = "https://api.dexscreener.com/latest/dex/search?q={}"
GECKOTERMINAL_POOLS = "https://api.geckoterminal.com/api/v2/networks/bsc/pools?page={}"

MAX_MCAP_USD = 5_000_000.0
MIN_LIQUIDITY_USD = 20_000.0

SEARCH_TERMS = [
    "bsc", "WBNB", "pancakeswap", "cake", "usdt", "pepe", "cat", "doge", 
    "inu", "ai", "trump", "sol", "floki", "safe", "moon", "yield", "dao"
]

def ingest_250_pools(conn: sqlite3.Connection, target_count: int = 250) -> int:
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM token_queue WHERE liquidity_usd >= ? AND market_cap_usd <= ?", (MIN_LIQUIDITY_USD, MAX_MCAP_USD))
    existing = cursor.fetchone()[0]
    if existing >= target_count:
        print(f"[*] Queue already contains {existing} eligible pools (>= {target_count}). Proceeding.")
        return existing

    print(f"[*] Queue currently has {existing} pools. Ingesting from DexScreener & GeckoTerminal up to {target_count}...")
    inserted = 0

    # 1. DexScreener Multi-Query
    for q in SEARCH_TERMS:
        try:
            url = DEXSCREENER_SEARCH.format(q)
            resp = requests.get(url, headers=HEADERS, timeout=10)
            if resp.status_code == 200:
                pairs = resp.json().get("pairs", [])
                for p in pairs:
                    if p.get("chainId") != "bsc":
                        continue
                    fdv = float(p.get("fdv") or p.get("marketCap") or 0.0)
                    liq = float(p.get("liquidity", {}).get("usd") or 0.0)
                    addr = p.get("baseToken", {}).get("address", "").lower()
                    sym = p.get("baseToken", {}).get("symbol", "")

                    if 0 < fdv <= MAX_MCAP_USD and liq >= MIN_LIQUIDITY_USD and addr:
                        cursor.execute("""
                            INSERT INTO token_queue (address, symbol, market_cap_usd, liquidity_usd, source, discovered_at)
                            VALUES (?, ?, ?, ?, 'dexscreener', ?)
                            ON CONFLICT(address) DO UPDATE SET
                                market_cap_usd = excluded.market_cap_usd,
                                liquidity_usd = excluded.liquidity_usd
                        """, (addr, sym, fdv, liq, datetime.now(timezone.utc).isoformat()))
                        inserted += 1
            conn.commit()
            time.sleep(0.4)
            cursor.execute("SELECT COUNT(*) FROM token_queue WHERE liquidity_usd >= ? AND market_cap_usd <= ?", (MIN_LIQUIDITY_USD, MAX_MCAP_USD))
            current = cursor.fetchone()[0]
            if current >= target_count:
                print(f"[+] Reached {current} target pools from DexScreener.")
                return current
        except Exception as e:
            print(f"[!] DexScreener query error ({q}): {e}")

    # 2. GeckoTerminal Multi-Page Fallback
    headers = dict(HEADERS)
    headers["Accept"] = "application/json;version=20230302"
    for page in range(1, 10):
        try:
            url = GECKOTERMINAL_POOLS.format(page)
            resp = requests.get(url, headers=headers, timeout=10)
            if resp.status_code == 200:
                pools = resp.json().get("data", [])
                for pool in pools:
                    attrs = pool.get("attributes", {})
                    fdv = float(attrs.get("fdv_usd") or 0.0)
                    liq = float(attrs.get("reserve_in_usd") or 0.0)
                    name = attrs.get("name", "")
                    sym = name.split("/")[0].strip() if "/" in name else "UNKNOWN"
                    rel = pool.get("relationships", {})
                    base_data = rel.get("base_token", {}).get("data", {})
                    raw_id = base_data.get("id", "")
                    addr = raw_id.split("_")[-1].lower() if "_" in raw_id else ""

                    if 0 < fdv <= MAX_MCAP_USD and liq >= MIN_LIQUIDITY_USD and addr.startswith("0x"):
                        cursor.execute("""
                            INSERT INTO token_queue (address, symbol, market_cap_usd, liquidity_usd, source, discovered_at)
                            VALUES (?, ?, ?, ?, 'geckoterminal', ?)
                            ON CONFLICT(address) DO UPDATE SET
                                market_cap_usd = excluded.market_cap_usd,
                                liquidity_usd = excluded.liquidity_usd
                        """, (addr, sym, fdv, liq, datetime.now(timezone.utc).isoformat()))
                        inserted += 1
            conn.commit()
            time.sleep(0.5)
        except Exception as e:
            print(f"[!] GeckoTerminal page {page} error: {e}")

    cursor.execute("SELECT COUNT(*) FROM token_queue WHERE liquidity_usd >= ? AND market_cap_usd <= ?", (MIN_LIQUIDITY_USD, MAX_MCAP_USD))
    final_count = cursor.fetchone()[0]
    print(f"[+] Ingestion complete. Total eligible pools in queue: {final_count}")
    return final_count

def main():
    target = int(sys.argv[1]) if len(sys.argv) > 1 else 250
    out_csv = sys.argv[2] if len(sys.argv) > 2 else "batch_audit_results_250.csv"

    print(f"=== Signet Phase 1 Stress-Test: {target} BSC Pools ===")
    conn = init_queue_db("audit_cache.db")
    total_eligible = ingest_250_pools(conn, target)

    actual_run_count = min(total_eligible, target)
    print(f"\n[*] Launching batch audit on {actual_run_count} pools. Output file: {out_csv}")
    
    start_time = time.time()
    results = run_batch_audit(actual_run_count, out_csv)
    elapsed = time.time() - start_time

    # Compute Stress-Test Metrics
    total = len(results)
    verified = sum(1 for r in results if r.get("source_verified"))
    proxies = sum(1 for r in results if r.get("is_proxy"))
    sig01_hits = sum(r.get("sig01_findings", 0) for r in results)
    sig03_hits = sum(r.get("sig03_findings", 0) for r in results)
    semgrep_cand = sum(r.get("sig01_semgrep_candidates", 0) for r in results)

    print("\n" + "="*60)
    print("           SIGNET 250-POOL STRESS-TEST RESULTS")
    print("="*60)
    print(f"Total Pools Audited:          {total}")
    print(f"Verified Sources:             {verified} ({verified/total*100:.1f}%)" if total else 0)
    print(f"Proxies Resolved:             {proxies} ({proxies/total*100:.1f}%)" if total else 0)
    print(f"Semgrep SIG-01 Candidates:    {semgrep_cand}")
    print(f"Slither SIG-01 Confirmed:     {sig01_hits}")
    print(f"Semgrep SIG-03 Confirmed:     {sig03_hits}")
    print(f"Total Elapsed Time:           {elapsed:.1f}s ({elapsed/max(total, 1):.2f}s per pool)")
    print("="*60)

    # Evaluation against Stream 1 Kill Criteria
    if sig01_hits > 0 or sig03_hits > 0:
        print(f"\n[+] SUCCESS: Found {sig01_hits + sig03_hits} potentially exploitable findings!")
        print("    -> Proceed to Step 2: Triage PoC for Immunefi / Coordinated Disclosure.")
    else:
        print("\n[-] TRIGGER KILL CRITERIA 1: 0 exploitable findings detected across sample.")
        print("    -> Recommendation: Demote Stream 1 bounties. Pivot 100% of Week 1 to Stream 2 FastAPI SaaS.")

if __name__ == "__main__":
    main()
