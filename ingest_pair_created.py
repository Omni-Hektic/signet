#!/usr/bin/env python3
"""
ingest_pair_created.py: Real-Time On-Chain Token Discovery for Signet

Listens to new pair deployments on PancakeSwap V2 Factory (0xcA143Ce32Fe78f1f7019d7d551a6402fC5350c73).
Unlike REST keyword searches (which cap out at ~30 pairs and introduce high latency),
this worker directly polls the on-chain allPairsLength() state counter or listens to events.

Workflow:
1. Poll allPairsLength() on PancakeSwap Factory via eth_call (zero block-range restrictions).
2. For newly incremented indices, fetch pair address via allPairs(index).
3. Read token0 and token1 contracts from the pair.
4. Filter out canonical quote tokens (WBNB, USDT, USDC, BUSD, BTCB, ETH).
5. Enqueue new token into audit_cache.db and immediately dispatch cold audit into Redis cache.
"""

import os
import sys
import time
import sqlite3
import argparse
from datetime import datetime, timezone
from typing import Optional, List, Tuple

# Ensure package imports
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

from solidity_auditor.tools.fetch_and_audit import rpc_call, init_db
from api.cache import cache_manager
from api.scanner import execute_cold_audit

PANCAKESWAP_V2_FACTORY = "0xcA143Ce32Fe78f1f7019d7d551a6402fC5350c73"

# Common base/quote tokens on BSC to exclude from being treated as the new token
CANONICAL_QUOTE_TOKENS = {
    "0xbb4cdb9cbd36b01bd1cbaebf2de08d9173bc095c": "WBNB",
    "0x55d398326f99059ff775485246999027b3197955": "USDT",
    "0x8ac76a51cc950d9822d68b83fe1ad97b32cd580d": "USDC",
    "0xe9e7cea3dedca5984780bafc599bd69add087d56": "BUSD",
    "0x7130d2a12b9bcbfae4f2634d864a1ee1ce3ead9c": "BTCB",
    "0x2170ed0880ac9a755fd29b2688956bd959f933f8": "ETH",
    "0x0e09fabb73bd3ade0a17ecc321fd13a19e81ce82": "CAKE"
}

# BSC Reorg Confirmation Buffer (15 blocks ~45 seconds)
CONFIRMATION_DEPTH_BLOCKS = 15

def get_total_pairs(block_tag: str = "latest") -> int:
    """Calls allPairsLength() on PancakeSwap Factory at a specific block height."""
    # selector for allPairsLength(): 0x574f2ba3
    res = rpc_call("eth_call", [{"to": PANCAKESWAP_V2_FACTORY, "data": "0x574f2ba3"}, block_tag])
    if not res or res == "0x":
        return 0
    return int(res, 16)

def get_pair_at_index(index: int, block_tag: str = "latest") -> Optional[str]:
    """Calls allPairs(uint256) on PancakeSwap Factory at a specific block height."""
    # selector for allPairs(uint256): 0x1e3dd18b
    selector = "0x1e3dd18b"
    arg = hex(index)[2:].zfill(64)
    res = rpc_call("eth_call", [{"to": PANCAKESWAP_V2_FACTORY, "data": selector + arg}, block_tag])
    if not res or len(res) < 42:
        return None
    return "0x" + res[-40:].lower()

def get_pair_tokens(pair_addr: str, block_tag: str = "latest") -> Tuple[Optional[str], Optional[str]]:
    """Fetches token0 and token1 from the UniswapV2Pair contract."""
    # token0(): 0x0dfe1681, token1(): 0xd21220a7
    t0_res = rpc_call("eth_call", [{"to": pair_addr, "data": "0x0dfe1681"}, block_tag])
    t1_res = rpc_call("eth_call", [{"to": pair_addr, "data": "0xd21220a7"}, block_tag])
    
    t0 = ("0x" + t0_res[-40:].lower()) if t0_res and len(t0_res) >= 42 else None
    t1 = ("0x" + t1_res[-40:].lower()) if t1_res and len(t1_res) >= 42 else None
    return t0, t1

MIN_TIER2_LIQUIDITY_USD = 25000.0  # Cold audit gating threshold (tuned to enforce < 10% trigger rate)

def get_pair_reserves(pair_addr: str, block_tag: str = "latest") -> Tuple[int, int]:
    """Calls getReserves() on UniswapV2Pair contract."""
    # getReserves(): 0x0902f1ac
    res = rpc_call("eth_call", [{"to": pair_addr, "data": "0x0902f1ac"}, block_tag])
    if not res or len(res) < 130:
        return 0, 0
    try:
        r0 = int(res[2:66], 16)
        r1 = int(res[66:130], 16)
        return r0, r1
    except Exception:
        return 0, 0

def estimate_liquidity_usd(token0: str, token1: str, r0: int, r1: int) -> float:
    """Estimates pool liquidity in USD assuming BNB ~$600."""
    WBNB = "0xbb4cdb9cbd36b01bd1cbaebf2de08d9173bc095c"
    USDT = "0x55d398326f99059ff775485246999027b3197955"
    USDC = "0x8ac76a51cc950d9822d68b83fe1ad97b32cd580d"

    if token0 == WBNB:
        return (r0 / 1e18) * 600.0 * 2.0
    elif token1 == WBNB:
        return (r1 / 1e18) * 600.0 * 2.0
    elif token0 in (USDT, USDC):
        return (r0 / 1e18) * 2.0
    elif token1 in (USDT, USDC):
        return (r1 / 1e18) * 2.0
    return 0.0

def init_ingest_state(conn: sqlite3.Connection) -> int:
    """Ensures state and tracking tables exist and retrieves last processed pair index."""
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS ingest_state (
            key TEXT PRIMARY KEY,
            value INTEGER
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS discovered_pairs (
            pair_address TEXT PRIMARY KEY,
            pair_index INTEGER,
            token0 TEXT,
            token1 TEXT,
            target_token TEXT,
            quote_symbol TEXT,
            is_canonical INTEGER DEFAULT 1,
            confirmation_block INTEGER,
            discovered_at TEXT
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS ingest_telemetry (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            pairs_discovered INTEGER,
            canonical_ratio REAL,
            tier2_evaluated INTEGER,
            tier2_triggered INTEGER,
            tier2_trigger_rate REAL,
            hourly_discovery_rate REAL
        )
    """)
    # Ensure all columns exist for existing databases
    cols = [r[1] for r in cursor.execute("PRAGMA table_info(discovered_pairs)").fetchall()]
    if "quote_symbol" not in cols:
        cursor.execute("ALTER TABLE discovered_pairs ADD COLUMN quote_symbol TEXT")
    if "is_canonical" not in cols:
        cursor.execute("ALTER TABLE discovered_pairs ADD COLUMN is_canonical INTEGER DEFAULT 1")
    if "confirmation_block" not in cols:
        cursor.execute("ALTER TABLE discovered_pairs ADD COLUMN confirmation_block INTEGER")
    
    # Enable WAL mode and feed index optimizations
    cursor.execute("PRAGMA journal_mode = WAL;")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_discovered_pairs_feed ON discovered_pairs (is_canonical, pair_index DESC);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_discovered_pairs_idx ON discovered_pairs (pair_index DESC);")

    # Initialize Tier 2 telemetry counters
    cursor.execute("INSERT OR IGNORE INTO ingest_state (key, value) VALUES ('tier2_evaluated', 0)")
    cursor.execute("INSERT OR IGNORE INTO ingest_state (key, value) VALUES ('tier2_triggered', 0)")
    conn.commit()

    cursor.execute("SELECT value FROM ingest_state WHERE key = 'last_pancake_pair_index'")
    row = cursor.fetchone()
    if row:
        return row[0]
    
    # Initialize to (total_pairs - 10) on first boot
    total = get_total_pairs()
    start_index = max(0, total - 10)
    cursor.execute("INSERT OR REPLACE INTO ingest_state (key, value) VALUES ('last_pancake_pair_index', ?)", (start_index,))
    conn.commit()
    return start_index

def update_ingest_state(conn: sqlite3.Connection, last_index: int):
    cursor = conn.cursor()
    cursor.execute("INSERT OR REPLACE INTO ingest_state (key, value) VALUES ('last_pancake_pair_index', ?)", (last_index,))
    conn.commit()

def log_hourly_telemetry(conn: sqlite3.Connection):
    """Calculates and logs hourly telemetry for pairs velocity, canonical ratio, and Tier 2 trigger rate."""
    cursor = conn.cursor()
    
    # 1. Total and canonical pairs
    cursor.execute("SELECT COUNT(*) FROM discovered_pairs")
    total_pairs = cursor.fetchone()[0]
    
    cursor.execute("SELECT COUNT(*) FROM discovered_pairs WHERE is_canonical = 1")
    canonical_pairs = cursor.fetchone()[0]
    canonical_pct = (canonical_pairs / total_pairs * 100.0) if total_pairs > 0 else 0.0
    
    # 2. Tier 2 metrics
    cursor.execute("SELECT value FROM ingest_state WHERE key = 'tier2_evaluated'")
    row_ev = cursor.fetchone()
    tier2_eval = row_ev[0] if row_ev else 0
    
    cursor.execute("SELECT value FROM ingest_state WHERE key = 'tier2_triggered'")
    row_trig = cursor.fetchone()
    tier2_trig = row_trig[0] if row_trig else 0
    
    trigger_rate = (tier2_trig / tier2_eval * 100.0) if tier2_eval > 0 else 0.0
    
    # 3. Discovery velocity
    cursor.execute("SELECT MIN(discovered_at), MAX(discovered_at) FROM discovered_pairs")
    min_t, max_t = cursor.fetchone()
    pairs_per_hour = 0.0
    if min_t and max_t and total_pairs > 1:
        t0 = datetime.fromisoformat(min_t)
        t1 = datetime.fromisoformat(max_t)
        elapsed_hours = max((t1 - t0).total_seconds() / 3600.0, 0.01)
        pairs_per_hour = total_pairs / elapsed_hours
    
    now_iso = datetime.now(timezone.utc).isoformat()
    cursor.execute("""
        INSERT INTO ingest_telemetry (timestamp, pairs_discovered, canonical_ratio, tier2_evaluated, tier2_triggered, tier2_trigger_rate, hourly_discovery_rate)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (now_iso, total_pairs, canonical_pct, tier2_eval, tier2_trig, trigger_rate, pairs_per_hour))
    conn.commit()
    
    print("\n" + "="*70)
    print(f"📊 [SIGNET HOURLY TELEMETRY] {now_iso}")
    print(f"   • Total Discovered Pairs : {total_pairs} (Canonical: {canonical_pairs} / {canonical_pct:.1f}%)")
    print(f"   • Ingestion Velocity     : {pairs_per_hour:.1f} pairs/hour (~{pairs_per_hour * 24:,.0f} pairs/day)")
    print(f"   • Tier 2 Evaluated       : {tier2_eval} canonical pairs")
    print(f"   • Tier 2 Triggered       : {tier2_trig} pools (>= ${MIN_TIER2_LIQUIDITY_USD:,.0f} liq)")
    print(f"   • Tier 2 Trigger Rate    : {trigger_rate:.2f}%")
    if trigger_rate > 10.0:
        print(f"   ⚠️ [ALERT] Trigger rate {trigger_rate:.2f}% EXCEEDS 10.0% COGS safety threshold! Tighten gating.")
    else:
        print(f"   ✅ [COGS SAFE] Trigger rate {trigger_rate:.2f}% is safely below 10.0% budget cap.")
    print("="*70 + "\n")

def process_new_pairs(conn: sqlite3.Connection, auto_audit: bool = True) -> Tuple[int, int]:
    """Polls for newly created pairs on PancakeSwap confirmed by 15 blocks."""
    last_index = init_ingest_state(conn)

    # 1. Enforce 15-Block Safe Confirmation Depth
    latest_hex = rpc_call("eth_blockNumber", [])
    if not latest_hex:
        return 0, 0
    latest_block = int(latest_hex, 16)
    safe_block_num = max(0, latest_block - CONFIRMATION_DEPTH_BLOCKS)
    safe_block_tag = hex(safe_block_num)

    safe_total_pairs = get_total_pairs(block_tag=safe_block_tag)

    if safe_total_pairs <= last_index:
        return 0, 0

    new_pairs_count = safe_total_pairs - last_index
    print(f"[*] Found {new_pairs_count} confirmed new pairs on PancakeSwap (index {last_index} to {safe_total_pairs - 1}, confirmed at block #{safe_block_num} [-{CONFIRMATION_DEPTH_BLOCKS} blocks]).")

    processed = 0
    duplicates = 0
    cursor = conn.cursor()

    for idx in range(last_index, safe_total_pairs):
        pair_addr = get_pair_at_index(idx, block_tag=safe_block_tag)
        if not pair_addr:
            continue

        # Check for reorg / existing pair de-duplication
        cursor.execute("SELECT pair_address FROM discovered_pairs WHERE pair_address = ?", (pair_addr,))
        if cursor.fetchone():
            duplicates += 1
            update_ingest_state(conn, idx + 1)
            continue

        token0, token1 = get_pair_tokens(pair_addr, block_tag=safe_block_tag)
        if not token0 or not token1:
            continue

        # Identify target token and quote asset
        target_token = None
        quote_symbol = "UNKNOWN"
        is_canonical = 0

        if token0 in CANONICAL_QUOTE_TOKENS and token1 not in CANONICAL_QUOTE_TOKENS:
            target_token = token1
            quote_symbol = CANONICAL_QUOTE_TOKENS[token0]
            is_canonical = 1
        elif token1 in CANONICAL_QUOTE_TOKENS and token0 not in CANONICAL_QUOTE_TOKENS:
            target_token = token0
            quote_symbol = CANONICAL_QUOTE_TOKENS[token1]
            is_canonical = 1
        elif token0 not in CANONICAL_QUOTE_TOKENS:
            target_token = token0
            quote_symbol = "TOKEN"
            is_canonical = 0

        # Record in discovered_pairs with confirmation block
        cursor.execute("""
            INSERT INTO discovered_pairs (pair_address, pair_index, token0, token1, target_token, quote_symbol, is_canonical, confirmation_block, discovered_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(pair_address) DO NOTHING
        """, (pair_addr, idx, token0, token1, target_token or "UNKNOWN", quote_symbol, is_canonical, safe_block_num, datetime.now(timezone.utc).isoformat()))
        conn.commit()

        if target_token:
            print(f"\n[+] [Pair #{idx}] New Token Discovered: {target_token} (Pair: {pair_addr}, Quote: {quote_symbol})")
            
            # Check pool reserves for Tier 2 gating
            r0, r1 = get_pair_reserves(pair_addr, block_tag=safe_block_tag)
            liq_usd = estimate_liquidity_usd(token0, token1, r0, r1)

            # Update Tier 2 metrics in ingest_state
            if is_canonical == 1:
                cursor.execute("UPDATE ingest_state SET value = value + 1 WHERE key = 'tier2_evaluated'")
                conn.commit()

            # Enqueue into token_queue with estimated liquidity
            cursor.execute("""
                INSERT INTO token_queue (address, symbol, market_cap_usd, liquidity_usd, source, discovered_at, status)
                VALUES (?, 'UNKNOWN', 0.0, ?, 'pancakeswap_factory', ?, 'QUEUED')
                ON CONFLICT(address) DO UPDATE SET liquidity_usd = excluded.liquidity_usd
            """, (target_token, liq_usd, datetime.now(timezone.utc).isoformat()))
            conn.commit()

            # Check Tier 2 qualification (canonical AND liquidity >= $5,000)
            meets_tier2_criteria = (is_canonical == 1) and (liq_usd >= MIN_TIER2_LIQUIDITY_USD)
            if meets_tier2_criteria:
                cursor.execute("UPDATE ingest_state SET value = value + 1 WHERE key = 'tier2_triggered'")
                conn.commit()

            # Tier 2 Gated Audit Execution
            if meets_tier2_criteria and auto_audit and target_token not in cache_manager:
                print(f"    [*] Tier 2 Gating PASSED (${liq_usd:,.2f} >= ${MIN_TIER2_LIQUIDITY_USD:,.2f}). Auto-auditing {target_token}...")
                try:
                    report, dur, cost = execute_cold_audit(target_token, conn)
                    cache_manager.set(target_token, report)
                    print(f"    [+] Audit completed in {dur:.2f}s (Slither CPU: {cost.get('slither_cpu_seconds')}s). Stored in warm cache!")
                except Exception as e:
                    print(f"    [!] Audit error for {target_token}: {e}")
            elif not meets_tier2_criteria:
                print(f"    [-] Tier 2 Gating SKIPPED (Est. Liq: ${liq_usd:,.2f} < ${MIN_TIER2_LIQUIDITY_USD:,.2f} or non-canonical). COGS preserved.")

            processed += 1
        
        # Save progress
        update_ingest_state(conn, idx + 1)
        time.sleep(0.2)

    return processed, duplicates

def main():
    parser = argparse.ArgumentParser(description="Signet PancakeSwap PairCreated Ingestion Worker")
    parser.add_argument("--daemon", action="store_true", help="Run continuously as background daemon")
    parser.add_argument("--interval", type=int, default=5, help="Polling interval in seconds")
    parser.add_argument("--no-audit", action="store_true", help="Enqueue only, do not run immediate audit")
    args = parser.parse_args()

    conn = init_db("audit_cache.db")
    print("=== Signet PancakeSwap Factory Ingestion Worker ===")
    print(f"Factory Address: {PANCAKESWAP_V2_FACTORY}")
    
    # Ensure tables and state exist
    init_ingest_state(conn)

    # Run initial telemetry snapshot on boot
    try:
        log_hourly_telemetry(conn)
    except Exception as e:
        print(f"[!] Initial telemetry error: {e}")

    last_telemetry_time = time.time()

    if args.daemon:
        print(f"[*] Starting continuous daemon mode (polling every {args.interval}s)...")
        while True:
            try:
                proc, dupes = process_new_pairs(conn, auto_audit=not args.no_audit)
                if proc > 0:
                    print(f"[+] Swept {proc} tokens (skipped {dupes} duplicates).")
            except Exception as e:
                print(f"[!] Ingestion loop error: {e}")
            
            # Hourly telemetry logging
            if time.time() - last_telemetry_time >= 3600:
                try:
                    log_hourly_telemetry(conn)
                except Exception as e:
                    print(f"[!] Hourly telemetry error: {e}")
                last_telemetry_time = time.time()

            time.sleep(args.interval)
    else:
        print("[*] Running single polling sweep...")
        processed, dupes = process_new_pairs(conn, auto_audit=not args.no_audit)
        print(f"[+] Ingestion sweep finished. Processed {processed} new tokens (skipped {dupes} duplicates).")

if __name__ == "__main__":
    main()
