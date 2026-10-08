#!/usr/bin/env python3
"""
scripts/test_feed_ws.py: Signet Real-Time WebSocket Feed Testing Tool

Connects to the Signet Clean Pair Stream WebSocket and renders live 15-block
confirmed PancakeSwap pairs and proxy implementations in real time.

Usage:
  # Test local FastAPI instance:
  python3 scripts/test_feed_ws.py --url ws://localhost:8000/v1/feed/ws

  # Test deployed Fly.io instance:
  python3 scripts/test_feed_ws.py --url wss://signet-api.fly.dev/v1/feed/ws
"""

import sys
import json
import asyncio
import argparse

try:
    import websockets
except ImportError:
    print("[!] Missing 'websockets' package. Install with: pip install websockets")
    sys.exit(1)

async def stream_feed(ws_url: str, filter_mode: str = "canonical", max_events: int = 10):
    print("=" * 70)
    print("       SIGNET REAL-TIME WEBSOCKET FEED CLIENT")
    print("=" * 70)
    print(f"Connecting to: {ws_url}")
    print(f"Filter Mode  : {filter_mode}")
    print("=" * 70)

    try:
        async with websockets.connect(ws_url) as ws:
            event_count = 0
            
            # Send initial subscription filter
            await ws.send(json.dumps({"action": "subscribe", "filter": filter_mode}))

            while event_count < max_events:
                msg = await ws.recv()
                data = json.loads(msg)
                event_type = data.get("event")

                if event_type == "connected":
                    print(f"[*] Handshake Received: Feed '{data.get('feed')}' connected (Depth: {data.get('confirmation_depth_blocks')} blocks)")
                    print("-" * 70)
                elif event_type in ("initial_snapshot", "new_pair"):
                    event_count += 1
                    token = data.get("token_address")
                    quote = data.get("quote_symbol")
                    pair = data.get("pair_address")
                    is_proxy = data.get("is_proxy")
                    proxy_type = data.get("proxy_type") or "Direct/None"
                    impl = data.get("implementation_address") or "N/A"
                    status = data.get("signet_status")

                    prefix = "[SNAPSHOT]" if event_type == "initial_snapshot" else "[LIVE NEW]"
                    print(f"{prefix} Pair: {pair} | Token: {token} ({quote})")
                    print(f"         Proxy: {is_proxy} ({proxy_type}) | Impl: {impl} | Status: {status}")
                    print("-" * 70)
                elif event_type == "filter_updated":
                    print(f"[*] Filter updated on server: {data.get('filter')}")

            print(f"[+] Successfully received {event_count} feed events. Disconnecting cleanly.")

    except Exception as e:
        print(f"[!] WebSocket connection error: {e}")

def main():
    parser = argparse.ArgumentParser(description="Signet WebSocket Feed Test Client")
    parser.add_argument("--url", default="ws://localhost:8000/v1/feed/ws", help="WebSocket URL")
    parser.add_argument("--filter", default="canonical", choices=["canonical", "all"], help="Filter mode")
    parser.add_argument("--max", type=int, default=5, help="Max events to display before exiting")
    args = parser.parse_args()

    asyncio.run(stream_feed(args.url, args.filter, args.max))

if __name__ == "__main__":
    main()
