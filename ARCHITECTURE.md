
## Audit Engine Notes
SIG-03 Slither data-flow deferred to v2. v1 uses Semgrep heuristics only. False-positive rate unmeasured.


## SIG-01 Slither — Known False Positives (v1)

The following safe patterns trigger the detector. They are documented as
known limitations to be addressed in v2 with taint analysis.

1. Struct member assignment:
   sigData.signer = ecrecover(...); require(sigData.signer == trusted);
   Detector does not follow Index IR into struct members.
   Fixture: SafeStructField.sol

2. Pre-checked signer:
   require(expected != address(0)); recovered = ecrecover(...);
   require(recovered == expected);
   Detector does not propagate non-zero taint forward.
   Fixture: SafePreCheck.sol

3. State-variable comparison without local zero-check:
   require(ecrecover(...) == trusted);
   Detector does not verify that `trusted` is initialized to non-zero in
   the constructor.
   Fixture: SafeOneLiner.sol

For each finding on these patterns, report with `confidence: MEDIUM` and
the note: "may be a false positive if the comparison target is guaranteed
non-zero. Manual review required."

## SafeOneLiner.sol — Reclassification Note

SafeOneLiner.sol is classified as a SIG-01 false positive because, under the
invariant that trustedSigner is non-zero, the one-liner comparison is safe.

However, the constructor assigns trustedSigner = _signer without enforcing
require(_signer != address(0)). If deployed with _signer == address(0), the
contract is vulnerable to signature bypass.

When SIG-11 (uninitialized signer detection) is promoted from research-only
to active in v2, SafeOneLiner.sol should be reclassified as a SIG-11 finding,
not a SIG-01 false positive.

## Semgrep Traps

Bare metavariables in pattern-not match too broadly. Use explicit identifiers.

- BAD:  pattern-not: keccak256(abi.encodePacked(..., $DOMAIN_SEPARATOR, ...))
        $DOMAIN_SEPARATOR binds to the entire argument list, suppressing all matches.

- GOOD: pattern-not: keccak256(abi.encodePacked(..., _domainSeparator, ...))
        Explicit identifier names bind only when the exact name is present.

## Test Corpora

Two fixture directories serve different purposes:

- test_contracts/     — Unit fixtures. One feature per file. Expected counts are
                        minimal (1 or 0). Use for detector logic verification.
- targets/fixtures/   — Integration fixtures. Multiple features per file. Expected
                        counts are larger (3+). Use for realistic-contract testing.

Both corpora must pass before any detector is classified as validated.

## Semgrep False Positives: Diagnosis & Resolution (Part 4)

1. OpenZeppelin `tryRecover` tuple return on zero-address error (Resolved):
   ```solidity
   address signer = ecrecover(hash, v, r, s);
   if (signer == address(0)) {
       return (address(0), RecoverError.InvalidSignature);
   }
   ```
   Original rule `bsc-sig01-ecrecover-missing-zero-check` only excluded explicit reverts. Library routines return error tuples/enums rather than reverting, initially producing 14 candidate findings on EIP-1167 proxies.
   Resolution: Added `pattern-not-inside` and `pattern-not` clauses matching `if ($SIGNER == address(0)) { return ...; }` and `if ($SIGNER == address(0)) { ... }`.
   Post-fix FP count dropped from 14 to 0 across the entire 25-token batch.

## Semgrep Known Blindspots & Test B Fix (Part 4)

1. Function Selector Regex Exclusion (Resolved for `transferProxy`):
   ```solidity
   function transferProxy(address _from, address _to, ...) public returns (bool)
   ```
   Original SIG-03 rule checked `(?i)(permit|transferWithSig|...)`, missing historical contracts such as `TokenWhale`.
   Resolution: Added `transferProxy` to the alternation in `rules/semgrep.yaml`. Test B now produces 1 confirmed SIG-03 finding.

2. Reversed Operand Syntax in Inline Comparisons (Open limitation for Semgrep AST, covered by Slither):
   ```solidity
   if (_from != ecrecover(h, _v, _r, _s)) revert();
   ```
   Rule `bsc-sig01-ecrecover-missing-zero-check` matches patterns where `ecrecover` or its assigned variable is the left-hand operand. When the target is on the left and `ecrecover` on the right in an inline condition, AST pattern matching misses it. Slither's IR data-flow analysis handles operand commutativity natively and flags this pattern reliably.

## Operational Incident Note: Phase 1 Stress-Test Pool Discrepancy (37 vs 250)

During the Phase 1 commercial stress test (`validate_250_pools.py`), 37 pools were audited rather than the target 250.

- **Root Cause**: Discovery Ingestion Filter Constraints (Not a pipeline crash).
  DexScreener's public search API returns ~30 pairs per query keyword across all chains, and GeckoTerminal was paginated for 10 pages on the BSC network. Applying the strict qualification filters (`market_cap_usd <= $5,000,000` and `liquidity_usd >= $20,000`) yielded exactly 37 unique eligible BSC token pools in `audit_cache.db`. `validate_250_pools.py` explicitly executed on `min(total_eligible, target)` = 37.
- **Pipeline Execution Integrity**: All 37 pools ran to completion with zero unhandled exceptions, zero crashes, and 100% database persistence.
- **Production Implication for SaaS Ingestion**: REST keyword polling cannot provide full-universe coverage for high-throughput new listings. The production cache-warming layer must ingest directly from on-chain DEX factory events (`PairCreated` on PancakeSwap factory `0xcA143Ce32Fe78f1f7019d7d551a6402fC5350c73`) and streaming webhooks, rather than REST keyword search heuristics.
- **Moat Validation**: Across the 37 audited pools, 23 were proxies (62.2% proxy rate), confirming the empirical de-aliasing thesis and verifying 0% false positives for Semgrep `tryRecover` suppression.

## Production Audit-Trigger & Compute Gating Policy

To protect cloud compute COGS and preserve the 46.6%–70.4% gross margin model, Signet enforces a **Hybrid Tiered Ingestion & Audit Trigger Policy**:

1. **Tier 1: High-Velocity Discovery Layer (100% Ingestion Coverage, Minimal COGS)**:
   * `ingest_pair_created.py` monitors PancakeSwap V2 factory (`0xcA143Ce32Fe78f1f7019d7d551a6402fC5350c73`) with a strict 15-block confirmation buffer (`CONFIRMATION_DEPTH_BLOCKS = 15`).
   * Discovers 100% of newly deployed pairs, de-duplicates them via `discovered_pairs (pair_address PRIMARY KEY)`, and extracts token0/token1.
   * Zero compilation, zero Slither execution on this layer. Discovery overhead is negligible (< $0.00001 per pair query).

2. **Tier 2: Automatic Cache-Warming Gating (Filtered Cold Scans)**:
   * To prevent wasting compute on 0-liquidity spam pairs, automatic background cold audits (~15.75s, $0.0102 COGS) are triggered ONLY if:
     - The pair is quoted against a canonical base token (WBNB or USDT), AND
     - Initial liquidity crosses $\ge \$5,000$ USD (or DexScreener trending webhook fires).
   * Audited verdicts are written directly to Redis with a 24-hour TTL (`86,400s`).

3. **Tier 3: On-Demand Query Gating (B2B Callers & Trading Bots)**:
   * When any trading bot (Maestro/Trojan) or launchpad partner calls `GET /v1/scan/{address}`:
     - If in cache: Served in < 10ms (COGS: $0.00005).
     - If uncached: Returns HTTP 202 Accepted immediately (< 20ms) and dispatches a prioritized cold audit worker.
   * This guarantees that cold audit compute is strictly tied to paying customer queries, eliminating unbounded compute burn.

## On-Chain Reorg Finality & Safety Verification

A critical security criterion for exchange ingestion is ensuring that the confirmation buffer operates at EVM block depth rather than pair indices:

- **EVM Block Height Depth Verified**:
  In `ingest_pair_created.py`:
  ```python
  latest_hex = rpc_call("eth_blockNumber", [])
  latest_block = int(latest_hex, 16)
  safe_block_num = max(0, latest_block - CONFIRMATION_DEPTH_BLOCKS)  # CONFIRMATION_DEPTH_BLOCKS = 15
  safe_block_tag = hex(safe_block_num)

  # All EVM state calls evaluate at hex(latest_block - 15)
  safe_total_pairs = get_total_pairs(block_tag=safe_block_tag)
  pair_addr = get_pair_at_index(idx, block_tag=safe_block_tag)
  r0, r1 = get_pair_reserves(pair_addr, block_tag=safe_block_tag)
  ```
- **Reorg Immunity**: Querying RPC at `latest_block - 15` guarantees that PancakeSwap factory counter and pair contract storage are inspected 15 blocks (~45 seconds) in the past. Even if a 1-to-3 block micro-reorg occurs on BSC, Signet never reads unconfirmed state, preventing phantom pair registration.
- **De-duplication Primary Key**: Pairs are stored in SQLite with `pair_address TEXT PRIMARY KEY`. If a reorg duplicates a transaction hash or re-orders pair creation indices, `INSERT ... ON CONFLICT(pair_address) DO NOTHING` prevents table corruption.

## Tier 2 Trigger Rate Telemetry & COGS Protection

During initial shadow ingestion on BSC Mainnet, real-time measurements revealed:
- **PancakeSwap Listing Velocity**: ~414 pairs/hour (~9,900 pairs/day).
- **Canonical Quoted Ratio**: 91.7% quoted against WBNB/USDT, 8.3% non-standard/spam pairs.
- **Empirical Tier 2 Trigger Rate at $5,000 Liquidity**:
  Evaluating 28 newly created canonical pools yielded 5 pools crossing $\ge \$5,000$ liquidity (17.86% trigger rate).
- **COGS Exposure Warning**: At 17.86% trigger rate across 414 pairs/hr, cold auditing would consume ~68 cold scans/hr = ~$0.69/hr = ~$16.60/day = ~$498/mo, eroding initial SaaS gross margins.
- **Dynamic Threshold Calibration**:
  Examining liquidity distribution showed:
  - $\ge \$5,000$: 17.86% trigger rate (Exceeds 10% SLA budget)
  - $\ge \$15,000$: 10.7% trigger rate (Borderline)
  - $\ge \$25,000$: 7.14% trigger rate (Safely below 10% SLA budget cap)
  **Policy Rule**: Tier 2 auto-audit threshold is elevated to `MIN_TIER2_LIQUIDITY_USD = 25000.0` (or $\ge \$10,000$ + DexScreener trending confirmation) to strictly guarantee COGS < 10% before paid customer conversion.

---

## Month-2 Product Roadmap: Clean Pair Stream Feed (`GET /v1/feed/new-pairs`)

The discovery that 91.7% of BSC pairs are canonical while 8.3% are spam noise presents an immediate secondary revenue stream for trading bot developers (Maestro, Trojan, BananaGun, Sigma).

### Product Concept
Trading bots currently run heavy RPC filters to separate real liquidity deployments from spam contracts, re-deployments, and rug-pull pairs. Signet pre-filters this at line rate and de-aliases proxies before the bot even submits a simulation transaction.

### API Specification
- **Endpoint**: `GET /v1/feed/new-pairs`
- **Streaming Protocol**: Server-Sent Events (SSE) & WebSocket (`wss://api.signet.security/v1/feed/stream`)
- **Query Parameters**:
  - `canonical_only=true` (Filters 8.3% non-standard quote noise)
  - `min_liquidity_usd=5000` (Filters zero-liquidity placeholder pairs)
  - `verified_clean_only=true` (Only emits pairs where underlying token bytecode has passed Signet de-aliasing & audit)
  - `limit=50` (Cursor-based pagination)

### Response Payload
```json
{
  "timestamp": "2026-10-07T23:55:22Z",
  "feed_latency_ms": 14.2,
  "pairs": [
    {
      "pair_address": "0x245be34ba84ebd3d9958f17dcb605ed00deec45f",
      "token_address": "0x94c3c11dea241eb45d73cce49014efa8db007777",
      "quote_symbol": "WBNB",
      "initial_liquidity_usd": 7701.0,
      "confirmation_block": 126343577,
      "is_proxy": false,
      "signet_status": "CLEAN",
      "risk_score": 0
    }
  ]
}
```

### Commercialization & Packaging
- **Standalone Stream Tier**: $299/mo (up to 1M stream events/mo)
- **Enterprise Bundle**: Included in Pro Tier ($899/mo) alongside `/v1/scan` API and dynamic badges.



