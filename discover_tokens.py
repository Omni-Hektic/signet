#!/usr/bin/env python3
import requests
import sqlite3
import time
from datetime import datetime, timezone

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Defensive-Audit-Research; Linux x86_64)",
    "Accept": "application/json"
}

DEXSCREENER_SEARCH = "https://api.dexscreener.com/latest/dex/search?q={}"
GECKOTERMINAL_POOLS = "https://api.geckoterminal.com/api/v2/networks/bsc/pools?page={}"

MAX_MCAP_USD = 1_000_000.0
MIN_LIQUIDITY_USD = 5_000.0

def init_queue_db(db_path: str = "audit_cache.db") -> sqlite3.Connection:
    conn = sqlite3.connect(db_path)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS token_queue (
            address TEXT PRIMARY KEY,
            symbol TEXT,
            market_cap_usd REAL,
            liquidity_usd REAL,
            source TEXT,
            discovered_at TEXT,
            status TEXT DEFAULT 'PENDING'
        )
    """)
    conn.commit()
    return conn

def fetch_dexscreener_tokens(conn: sqlite3.Connection):
    print("[*] Ingesting from DexScreener...")
    search_queries = ["bsc", "WBNB", "pancakeswap", "cake"]
    inserted = 0

    for q in search_queries:
        try:
            url = DEXSCREENER_SEARCH.format(q)
            resp = requests.get(url, headers=HEADERS, timeout=10)
            if resp.status_code != 200:
                continue
            data = resp.json()
            pairs = data.get("pairs", [])
            for p in pairs:
                if p.get("chainId") != "bsc":
                    continue
                fdv = float(p.get("fdv") or p.get("marketCap") or 0.0)
                liq = float(p.get("liquidity", {}).get("usd") or 0.0)
                token_addr = p.get("baseToken", {}).get("address", "").lower()
                symbol = p.get("baseToken", {}).get("symbol", "")

                if 0 < fdv <= MAX_MCAP_USD and liq >= MIN_LIQUIDITY_USD and token_addr:
                    cursor = conn.cursor()
                    cursor.execute("""
                        INSERT INTO token_queue (address, symbol, market_cap_usd, liquidity_usd, source, discovered_at)
                        VALUES (?, ?, ?, ?, 'dexscreener', ?)
                        ON CONFLICT(address) DO UPDATE SET
                            market_cap_usd = excluded.market_cap_usd,
                            liquidity_usd = excluded.liquidity_usd
                    """, (token_addr, symbol, fdv, liq, datetime.now(timezone.utc).isoformat()))
                    inserted += 1
            conn.commit()
            time.sleep(0.5)
        except Exception as e:
            print(f"[!] DexScreener fetch error ({q}): {e}")

    print(f"[+] DexScreener processed. Candidates added/updated: {inserted}")

def fetch_geckoterminal_tokens(conn: sqlite3.Connection):
    print("[*] Ingesting from GeckoTerminal...")
    headers = dict(HEADERS)
    headers["Accept"] = "application/json;version=20230302"
    inserted = 0

    for page in range(1, 4):
        try:
            url = GECKOTERMINAL_POOLS.format(page)
            resp = requests.get(url, headers=headers, timeout=10)
            if resp.status_code != 200:
                break
            data = resp.json()
            pools = data.get("data", [])
            if not pools:
                break

            for pool in pools:
                attrs = pool.get("attributes", {})
                fdv = float(attrs.get("fdv_usd") or 0.0)
                liq = float(attrs.get("reserve_in_usd") or 0.0)
                pool_name = attrs.get("name", "")

                rel = pool.get("relationships", {}).get("base_token", {}).get("data", {})
                token_id = rel.get("id", "")
                if token_id.startswith("bsc_"):
                    token_addr = token_id.replace("bsc_", "").lower()
                    if 0 < fdv <= MAX_MCAP_USD and liq >= MIN_LIQUIDITY_USD:
                        symbol = pool_name.split("/")[0].strip() if "/" in pool_name else pool_name
                        conn.execute("""
                            INSERT INTO token_queue (address, symbol, market_cap_usd, liquidity_usd, source, discovered_at)
                            VALUES (?, ?, ?, ?, 'geckoterminal', ?)
                            ON CONFLICT(address) DO NOTHING
                        """, (token_addr, symbol, fdv, liq, datetime.now(timezone.utc).isoformat()))
                        inserted += 1
            conn.commit()
            time.sleep(1)
        except Exception as e:
            print(f"[!] GeckoTerminal fetch error (page {page}): {e}")

    print(f"[+] GeckoTerminal processed. Candidates added/updated: {inserted}")

def main():
    conn = init_queue_db()
    fetch_dexscreener_tokens(conn)
    fetch_geckoterminal_tokens(conn)

    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM token_queue WHERE status = 'PENDING'")
    pending_count = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM token_queue")
    total_count = cursor.fetchone()[0]

    print(f"\n[+] Queue Status:")
    print(f"    Pending tokens to audit : {pending_count}")
    print(f"    Total tokens in database: {total_count}")

    print("\nNext step: Run audit on a queued token:")
    cursor.execute("SELECT address, symbol, market_cap_usd FROM token_queue WHERE status = 'PENDING' LIMIT 1")
    row = cursor.fetchone()
    if row:
        print(f"    python3 fetch_and_audit.py --address {row[0]}")

if __name__ == "__main__":
    main()
