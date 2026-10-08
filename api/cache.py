#!/usr/bin/env python3
"""
api/cache.py: Production Redis-Backed Cache Layer for Signet

Supports:
1. Redis cluster / standalone connection via REDIS_URL.
2. 24-hour TTL for warm contract verdicts (86,400s).
3. Memory instrumentation: tracks redis_bytes_per_key and memory consumption.
4. Transparent fallback to in-memory store if Redis is unavailable (dev/offline).
"""

import os
import json
from typing import Dict, Any, Optional

try:
    import redis
except ImportError:
    redis = None

DEFAULT_CACHE_TTL = 86400  # 24 Hours

class SignetCacheManager:
    def __init__(self, redis_url: Optional[str] = None):
        self.redis_url = redis_url or os.getenv("REDIS_URL", "redis://localhost:6379/0")
        self.redis_client = None
        self.fallback_memory: Dict[str, Dict[str, Any]] = {}
        self.total_bytes_stored = 0
        self.key_count = 0
        
        self._init_connection()

    def _init_connection(self):
        if redis is None:
            print("[*] redis-py not installed. Using local memory cache.")
            return

        try:
            client = redis.from_url(self.redis_url, decode_responses=True, socket_timeout=1.0)
            client.ping()
            self.redis_client = client
            print(f"[+] Connected to Redis at {self.redis_url}")
        except Exception as e:
            print(f"[-] Redis connection failed ({e}). Operating in memory fallback mode.")
            self.redis_client = None

    @property
    def is_redis_active(self) -> bool:
        return self.redis_client is not None

    def get(self, address: str) -> Optional[Dict[str, Any]]:
        addr_key = f"signet:scan:{address.lower()}"
        if self.redis_client:
            try:
                raw = self.redis_client.get(addr_key)
                if raw:
                    return json.loads(raw)
            except Exception as e:
                print(f"[!] Redis GET error for {addr_key}: {e}")
        
        # Check fallback
        return self.fallback_memory.get(address.lower())

    def set(self, address: str, report: Dict[str, Any], ttl: int = DEFAULT_CACHE_TTL):
        addr_lower = address.lower()
        addr_key = f"signet:scan:{addr_lower}"
        serialized = json.dumps(report)
        payload_bytes = len(serialized.encode("utf-8"))

        if self.redis_client:
            try:
                self.redis_client.set(addr_key, serialized, ex=ttl)
            except Exception as e:
                print(f"[!] Redis SET error for {addr_key}: {e}")
        
        # Always update local memory store and byte counters
        self.fallback_memory[addr_lower] = report
        self.total_bytes_stored += payload_bytes
        self.key_count = max(self.key_count, len(self.fallback_memory))

    def __contains__(self, address: str) -> bool:
        addr_lower = address.lower()
        if self.redis_client:
            try:
                return bool(self.redis_client.exists(f"signet:scan:{addr_lower}"))
            except Exception:
                pass
        return addr_lower in self.fallback_memory

    def __len__(self) -> int:
        if self.redis_client:
            try:
                # Count matching keys
                keys = self.redis_client.keys("signet:scan:0x*")
                if keys:
                    return len(keys)
            except Exception:
                pass
        return len(self.fallback_memory)

    @property
    def bytes_per_key(self) -> int:
        if self.key_count == 0:
            return 1240  # baseline json payload size
        return int(self.total_bytes_stored / self.key_count)

cache_manager = SignetCacheManager()
