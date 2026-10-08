# Signet Cryptographic Verification & Ingestion Methodology

**Version**: 1.0.0  
**Target Chain**: BNB Smart Chain Mainnet (`chainId: 56`)  
**Specification Link**: [https://signet.security/methodology](https://signet.security/methodology)

---

## 1. Executive Summary & Problem Space

Traditional Web3 security scanners (e.g. Honeypot.is, TokenSniffer, GoPlus) perform state simulations: they check whether a user can buy and sell tokens at block $N$. However, they exhibit two critical blind spots:

1. **The Proxy Blind Spot**: Over 60% of micro-cap BSC tokens are deployed behind **EIP-1167 Minimal Clones** or **EIP-1967 Proxies**. Generic scanners inspect only 45 bytes of unverified bytecode, leaving traders and launchpad presales blind to the actual implementation logic.
2. **The Signature Forgery Blind Spot**: Honeypot checks only verify permissions today. They fail to inspect cryptographic delegation routines (`permit`, `transferWithSig`, `meta-transactions`). If a contract contains an unchecked `ecrecover` return value, any actor can submit a zeroed signature (`v=0, r=0, s=0`) to forge an infinite approval tomorrow.

**Signet** is an automated on-chain de-aliasing engine and cryptographic static analysis primitive designed specifically to detect signature delegation vulnerabilities at line rate.

---

## 2. On-Chain Ingestion & Reorg Finality Layer

Signet operates directly on EVM DEX factory state rather than relying on rate-limited third-party REST APIs:

```
[PancakeSwap V2 Factory] 
       │
       ▼
 [allPairsLength()] ──► Evaluated at block height (latest - 15)
       │
       ▼
 [allPairs(index)]  ──► 15-Block Safe Buffer (~45s depth)
       │
       ├──► Canonical Quote Filter (WBNB/USDT)
       └──► Reorg Immunity (Zero transient ghost pairs)
```

* **Factory Counter Polling**: Queries `allPairsLength()` and `allPairs(uint256)` on the canonical PancakeSwap V2 Factory (`0xcA143Ce32Fe78f1f7019d7d551a6402fC5350c73`) via `eth_call`.
* **15-Block EVM Block Depth**: All factory index, pair token, and reserve queries pass an explicit block tag `hex(latest_block - 15)`. This guarantees that Signet reads BSC state confirmed 15 blocks (~45 seconds) in the past, eliminating micro-reorg state corruption.
* **Canonical Quoting Separation & Spam Filtering**: Filters incoming pairs based on liquidity base assets:
  - **Canonical Pairs (~75–80%)**: Pairs quoted directly against established liquid base currencies (`WBNB`, `USDT`, `USDC`, `BUSD`, `BTCB`, `ETH`, `CAKE`), representing actionable trading pools.
  - **Non-Canonical Pairs / Spam (~20–25%)**: Synthetic token-to-token listings where neither asset is a recognized quote currency (often wash-trading test scripts, dust routing, or placeholder pools). These burn sniper node simulation cycles without offering executable DEX routing, and are filtered before entering downstream queues.

---

## 3. Proxy De-Aliasing Architecture

Across our empirical baseline of 37 micro-cap BSC pools ($20k+ liquidity), **62.2% (23/37) deployed behind proxy patterns**, with **56.8% (21/37) specifically conforming to EIP-1167 Minimal Proxy Clones** and 5.4% (2/37) utilizing EIP-1967/Beacon storage slots.

When a token is evaluated, Signet executes an automated 3-tier de-aliasing sequence:

1. **EIP-1167 Minimal Proxy Clone Detection**:
   Inspects bytecode for the standardized 45-byte runtime pattern:
   ```
   363d3d373d3d3d363d73<20-byte target>5af43d82803e903d91602b57fd5bf3
   ```
   If matched, Signet extracts the target implementation address directly from bytecode bytes 10–30.
2. **EIP-1967 & EIP-1822 Storage Slot Inspection**:
   Calls `eth_getStorageAt` for:
   - Implementation Slot: `0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc`
   - Beacon Slot: `0xa3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50`
3. **Automated Source Resolution**:
   Fetches the verified implementation source code using the unified BscScan/Etherscan V2 API (`chainid=56`) with automated fallback to the decentralized **Sourcify** registry (`repo.sourcify.dev`).

---

## 4. Two-Engine Cryptographic Analysis Hierarchy

Signet combines rapid AST pre-filtering with deep SSA IR taint analysis:

```
[Target Contract Source]
          │
          ▼
┌───────────────────────────────┐
│ Level 1: Semgrep AST Filter   │ ──► Sub-second syntax pattern match
└──────────────┬────────────────┘
               │ (Flags potential signature functions)
               ▼
┌───────────────────────────────┐
│ Level 2: Slither IR Analysis  │ ──► Slither SSA Data-flow & Taint Tracking
└──────────────┬────────────────┘
               │
               ▼
   [Cryptographic Verdict Card]
```

### Vulnerability Definitions:
* **`SIG-01` (Unchecked `ecrecover` Return Value)**:
  `ecrecover` returns `address(0)` when given an invalid signature. If the contract compares the recovered address to a state variable (e.g., `require(ecrecover(...) == trustedSigner)`) and `trustedSigner` is uninitialized or null, an attacker can submit an arbitrary zeroed signature to pass authorization.
  * *Suppression Invariant*: Safe wrappers (such as OpenZeppelin's `ECDSA.tryRecover`) explicitly check `signer != address(0)` and return a boolean. Signet enforces AST suppression to guarantee **0% false positives** on safe wrapper libraries.
* **`SIG-03` (Missing Chain ID Binding in EIP-712 Permitted Signatures)**:
  Signature authorizations that omit `block.chainid` in their domain separator are vulnerable to cross-chain replay attacks. A valid approval signed for BNB Smart Chain can be replayed by an attacker on Ethereum or Polygon.

---

## 5. Compute Gating & Presale Priority Policy

To protect cloud compute COGS and preserve a > 70% gross margin model, Signet enforces a 3-tier compute policy:

| Tier | Trigger Mechanism | Action | Gating Rule |
| :--- | :--- | :--- | :--- |
| **Tier 1: Discovery** | On-chain `PairCreated` polling | Records pair, tokens, and block | 100% coverage, < $0.00001/pair |
| **Tier 2: Cache-Warming** | Newly created DEX pool | Executes cold Slither audit | $\ge \$25,000$ liquidity (Trigger rate < 10%) |
| **Tier 2: Presale Priority** | Launchpad registration webhook | Proactively audits & warms cache | **Bypasses liquidity gate** (presales audited before launch) |
| **Tier 3: On-Demand** | Trading bot / API caller query | < 35ms warm hit; 202 on cold miss | Prioritized async worker |

---

## 6. Service Level Agreements (SLA) & Guarantees

* **Warm Cache Read SLA**: `< 35ms` (empirically benchmarked at 8–12ms from CDN / Redis).
* **Cold Asynchronous Response**: HTTP 202 Accepted returned in `< 20ms` with job tracking ID and 1-hour polling TTL.
* **Zero Layout Shift Invariant**: All embeddable SVG badges conform strictly to `180×28px`.
* **Zero Disruption Pilot Exit**: On Day 15, unrenewed pilot badges transition automatically to a neutral `⚪ [ SIGNET | PILOT EXPIRED ]` state (HTTP 200, matching dimensions, no broken images).

---

## 7. Scope & Liability Disclaimer

Signet operates as an **objective cryptographic static analysis and transparency primitive**. 

* A `[ SIGNET | VERIFIED CLEAN ]` badge verifies that contract bytecode was de-aliased and contains zero detectable `SIG-01` or `SIG-03` signature delegation vulnerabilities.
* Signet does **not** audit business logic, tokenomics, off-chain liquidity management, team identity, or external contract oracles.
* Signet is not a financial guarantee, insurance policy, or investment endorsement.
