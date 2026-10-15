"""
api/auth.py: API Key Authentication for Signet Security Engine

Usage
-----
Set the SIGNET_API_KEYS environment variable to a comma-separated list of
valid API keys before starting the service:

    SIGNET_API_KEYS=sk-live-abc123,sk-live-xyz789

If SIGNET_API_KEYS is not set the service runs in OPEN mode (no auth required).
This lets existing deployments continue working until you're ready to lock down.

Clients pass their key in the X-API-Key header:

    curl -H "X-API-Key: sk-live-abc123" https://signet-api.onrender.com/v1/scan/0x...

Key tiers (enforced by which keys you issue — the middleware itself is
key-agnostic; tier logic lives in your billing system):

    Free   sk-free-...   (issue manually, 50 req/day — enforced externally)
    Pro    sk-pro-...    ($49/mo — issue on Stripe webhook)
    Ent    sk-ent-...    ($299/mo — issue on Stripe webhook)
"""

import os
import logging
from typing import Optional

from fastapi import Header, HTTPException, status

logger = logging.getLogger("signet.auth")

# ---------------------------------------------------------------------------
# Key Store — loaded once at import time
# ---------------------------------------------------------------------------
def _load_keys() -> Optional[set]:
    """Returns a frozenset of valid keys, or None if auth is disabled."""
    raw = os.environ.get("SIGNET_API_KEYS", "").strip()
    if not raw:
        logger.warning(
            "[auth] SIGNET_API_KEYS is not set — running in OPEN mode. "
            "Set this env var to enable key-based access control."
        )
        return None
    keys = {k.strip() for k in raw.split(",") if k.strip()}
    logger.info(f"[auth] Loaded {len(keys)} API key(s). Auth is ENABLED.")
    return keys

VALID_KEYS: Optional[set] = _load_keys()
AUTH_ENABLED: bool = VALID_KEYS is not None


# ---------------------------------------------------------------------------
# FastAPI dependency — add to any route that requires authentication
# ---------------------------------------------------------------------------
async def require_api_key(x_api_key: Optional[str] = Header(default=None, alias="X-API-Key")) -> str:
    """
    FastAPI dependency that validates the X-API-Key header.

    Inject with:
        from api.auth import require_api_key
        from fastapi import Depends

        @app.get("/v1/scan/{address}", dependencies=[Depends(require_api_key)])
        async def scan_token(...):
            ...

    Returns the key string on success so routes can log/attribute usage.
    """
    if not AUTH_ENABLED:
        # Auth is disabled — let request through, return empty sentinel
        return "__open__"

    if not x_api_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={
                "error": "missing_api_key",
                "message": "X-API-Key header is required. Get a key at https://signet-api.onrender.com/pricing",
            },
            headers={"WWW-Authenticate": "ApiKey"},
        )

    if x_api_key not in VALID_KEYS:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={
                "error": "invalid_api_key",
                "message": "The provided API key is not valid or has been revoked.",
            },
        )

    return x_api_key
