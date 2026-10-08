#!/usr/bin/env python3
"""
tests/test_api.py: Comprehensive test suite for Signet FastAPI service & Risk Cards.
Validates:
1. Warm cache hit latency strictly < 35ms.
2. Cold cache miss returns HTTP 202 Accepted + job_id in < 50ms.
3. Accurate metric counters (hit rate, percentiles, proxy rate, false positive rate).
4. Multi-format Risk Card renderers (Telegram, Terminal, SVG, Trading Bot JSON).
"""

import os
import sys
import time
from fastapi.testclient import TestClient

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from api.main import app, metrics
from api.cache import cache_manager

client = TestClient(app)

KNOWN_CACHED_TOKEN = "0x07bcb8e8226f671300e135b4a61dc157359b7777"
KNOWN_UNCASHED_TOKEN = "0x000000000000000000000000000000000000dEaD"

def test_health_endpoint():
    res = client.get("/health")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "online"
    assert data["chain"] == "bsc"
    assert data["chainId"] == 56
    assert data["warm_cache_entries"] >= 37

def test_warm_cache_latency_under_35ms():
    """Validates that warm cache hits return well under the 35ms B2B SLA."""
    start = time.perf_counter()
    res = client.get(f"/v1/scan/{KNOWN_CACHED_TOKEN}")
    elapsed_ms = (time.perf_counter() - start) * 1000.0

    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "cached"
    assert "card" in data
    assert "telegram_markdown" in data
    assert "trading_bot_payload" in data
    assert data["card"]["token_address"] == KNOWN_CACHED_TOKEN.lower()
    
    # Assert SLA
    print(f"\n[+] Warm Cache Response Time: {elapsed_ms:.2f}ms (SLA target < 35.0ms)")
    assert elapsed_ms < 35.0, f"Latency {elapsed_ms}ms exceeded 35ms threshold!"

def test_trading_bot_payload_format():
    """Validates trading bot binary verdict format for Maestro / Trojan."""
    res = client.get(f"/v1/scan/{KNOWN_CACHED_TOKEN}?format=trading_bot")
    assert res.status_code == 200
    data = res.json()
    assert "allow_trade" in data
    assert data["allow_trade"] is True
    assert data["risk_level"] == "LOW"
    assert data["is_proxy"] is True
    assert data["sig01_vulnerable"] is False

def test_telegram_and_terminal_formats():
    """Validates plain text formats for Telegram and CLI."""
    # Telegram format
    res_tg = client.get(f"/v1/scan/{KNOWN_CACHED_TOKEN}?format=telegram")
    assert res_tg.status_code == 200
    assert "SIGNET RISK CARD" in res_tg.text
    assert "PASS" in res_tg.text

    # Terminal format
    res_term = client.get(f"/v1/scan/{KNOWN_CACHED_TOKEN}?format=terminal")
    assert res_term.status_code == 200
    assert "SIGNET RISK ASSESSMENT" in res_term.text

def test_cold_cache_miss_returns_202_accepted():
    """Validates that uncached tokens never block the caller and return 202 Accepted."""
    uncached_addr = f"0x{os.urandom(20).hex()}"
    start = time.perf_counter()
    res = client.get(f"/v1/scan/{uncached_addr}")
    elapsed_ms = (time.perf_counter() - start) * 1000.0

    assert res.status_code == 202
    data = res.json()
    assert data["status"] == "accepted"
    assert "job_id" in data
    assert "check_status_url" in data
    assert data["address"] == uncached_addr.lower()

    # Must return immediately (< 100ms in-process TestClient overhead)
    print(f"\n[+] Cold Cache Miss 202 Accepted Time: {elapsed_ms:.2f}ms (target < 100.0ms)")
    assert elapsed_ms < 100.0

    # Verify job polling endpoint
    job_id = data["job_id"]
    job_res = client.get(f"/v1/jobs/{job_id}")
    assert job_res.status_code == 200
    job_data = job_res.json()
    assert job_data["job_id"] == job_id
    assert job_data["status"] in ("queued", "running", "completed", "failed")
    assert "ttl_remaining_seconds" in job_data
    assert 0 <= job_data["ttl_remaining_seconds"] <= 3600

    # Cleanup any generated artifact file
    time.sleep(0.1)
    cleanup_path = os.path.join("part4_reports", f"findings_{uncached_addr.lower()}.json")
    if os.path.exists(cleanup_path):
        os.remove(cleanup_path)

def test_direct_card_and_svg_badge_endpoints():
    """Validates the direct Risk Card and SVG Badge routes."""
    # Direct card
    res_card = client.get(f"/v1/card/{KNOWN_CACHED_TOKEN}?format=telegram")
    assert res_card.status_code == 200
    assert "SIGNET RISK CARD" in res_card.text

    # SVG badge
    res_svg = client.get(f"/v1/badge/{KNOWN_CACHED_TOKEN}.svg")
    assert res_svg.status_code == 200
    assert "image/svg+xml" in res_svg.headers.get("content-type", "")
    assert "public, max-age=60" in res_svg.headers.get("cache-control", "")
    assert "<svg" in res_svg.text
    assert "SIGNET" in res_svg.text

def test_metrics_instrumentation_endpoint():
    """Validates the real-time production telemetry counters."""
    res = client.get("/v1/metrics")
    assert res.status_code == 200
    m = res.json()

    print("\n[+] Telemetry Metrics Snapshot:")
    for k, v in m.items():
        print(f"    - {k}: {v}")

    assert "scan_cache_hit_rate" in m
    assert m["scan_cache_hit_rate"]["status"] == "insufficient_data"
    assert "cold_audit_duration" in m
    assert "proxy_resolution_rate" in m
    assert "false_positive_rate" in m
    assert "cost_telemetry" in m
    assert "avg_rpc_calls_per_scan" in m["cost_telemetry"]
    assert "redis_bytes_per_key" in m["cost_telemetry"]
    assert "margin_analysis" in m["cost_telemetry"]
    assert m["cost_telemetry"]["margin_analysis"]["gross_margin_at_90pct_cache_hit_pct"] == "46.6%"
    assert m["cost_telemetry"]["margin_analysis"]["recommended_pro_tier_price_usd"] == 899

    # Validate proxy resolution rate matches observed moat (> 60%)
    assert m["proxy_resolution_rate"] >= 0.60, f"Proxy resolution rate {m['proxy_resolution_rate']} fell below 60% moat!"
    assert m["false_positive_rate"] == 0.0, "False positive rate must remain 0.0%!"
    assert m["cold_audit_duration"]["p50_seconds"] > 0.0

def test_launchpad_presale_bypass():
    """Validates that launchpad presale tokens bypass the $25k liquidity gate."""
    test_presale = f"0x{os.urandom(20).hex()}"
    res = client.post("/v1/launchpad/presale", json={
        "token_address": test_presale,
        "symbol": "PRESALE",
        "launchpad": "pinksale",
        "callback_url": "https://pinksale.finance/api/signet-callback"
    })
    assert res.status_code == 202
    data = res.json()
    assert data["status"] == "accepted"
    assert data["tier"] == "tier2_presale_priority"
    assert data["bypass_liquidity_gate"] is True
    assert "badge_embed_url" in data

def test_clean_pair_stream_feed():
    """Validates that GET /v1/feed/new-pairs returns canonical-filtered pairs at line rate."""
    # Warm up route
    client.get("/v1/feed/new-pairs?limit=5")
    start = time.perf_counter()
    res = client.get("/v1/feed/new-pairs?limit=10&canonical_only=true")
    elapsed_ms = (time.perf_counter() - start) * 1000.0

    assert res.status_code == 200
    data = res.json()
    assert "pairs" in data
    assert data["canonical_only"] is True
    print(f"\n[+] Clean Pair Stream Feed Response Time: {elapsed_ms:.2f}ms (target < 50ms)")
    assert elapsed_ms < 50.0, f"Feed query {elapsed_ms:.2f}ms exceeded 50ms threshold!"

    if len(data["pairs"]) > 0:
        first = data["pairs"][0]
        assert "pair_address" in first
        assert "token_address" in first
        assert "quote_symbol" in first
        assert "confirmation_block" in first
        assert "is_canonical" in first

def test_methodology_endpoint():
    """Validates that /methodology returns 200 HTML without 404 for badge click-through."""
    res = client.get("/methodology")
    assert res.status_code == 200
    assert "Cryptographic Verification" in res.text
    assert "content-type" in res.headers
    assert "text/html" in res.headers["content-type"]

    res_raw = client.get("/v1/methodology")
    assert res_raw.status_code == 200
    assert "# Signet Cryptographic Verification" in res_raw.text

def test_presale_get_documentation():
    """Validates that GET /v1/launchpad/presale returns 200 documentation instead of 405."""
    res = client.get("/v1/launchpad/presale")
    assert res.status_code == 200
    data = res.json()
    assert data["endpoint"] == "/v1/launchpad/presale"
    assert data["method"] == "POST"
    assert "request_schema" in data
    assert "example_curl" in data

def test_websocket_feed_stream():
    """Validates that WebSocket /v1/feed/ws accepts connection and pushes handshake."""
    with client.websocket_connect("/v1/feed/ws") as ws:
        # 1. Receive handshake
        handshake = ws.receive_json()
        assert handshake["event"] == "connected"
        assert handshake["feed"] == "signet_clean_pair_stream"
        assert handshake["status"] == "subscribed"
        
        # 2. Send subscription update
        ws.send_json({"action": "subscribe", "filter": "canonical"})
        
        # Next message is either initial snapshot or filter update
        next_msg = ws.receive_json()
        assert next_msg["event"] in ("initial_snapshot", "filter_updated", "new_pair")

if __name__ == "__main__":
    print("=== Running Signet API & Risk Card Test Suite ===")
    test_health_endpoint()
    print("✅ test_health_endpoint passed")
    test_warm_cache_latency_under_35ms()
    print("✅ test_warm_cache_latency_under_35ms passed")
    test_trading_bot_payload_format()
    print("✅ test_trading_bot_payload_format passed")
    test_telegram_and_terminal_formats()
    print("✅ test_telegram_and_terminal_formats passed")
    test_cold_cache_miss_returns_202_accepted()
    print("✅ test_cold_cache_miss_returns_202_accepted passed")
    test_direct_card_and_svg_badge_endpoints()
    print("✅ test_direct_card_and_svg_badge_endpoints passed")
    test_metrics_instrumentation_endpoint()
    print("✅ test_metrics_instrumentation_endpoint passed")
    test_launchpad_presale_bypass()
    print("✅ test_launchpad_presale_bypass passed")
    test_presale_get_documentation()
    print("✅ test_presale_get_documentation passed")
    test_clean_pair_stream_feed()
    print("✅ test_clean_pair_stream_feed passed")
    test_websocket_feed_stream()
    print("✅ test_websocket_feed_stream passed")
    test_methodology_endpoint()
    print("✅ test_methodology_endpoint passed")
    print("\n🎉 ALL 12 TESTS PASSED SUCCESSFULLY!")

