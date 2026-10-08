# Signet Month-2 Dual-Engine Allocation Roadmap

**Version**: 1.0.0  
**Status**: Active Operational Strategy  
**Execution Horizon**: Days 5–35 (Month 2 Post-Send)  
**Objective**: Dynamically reallocate engineering bandwidth and capital based on empirical buyer response to the Day-5 outreach campaign across the two primary commercial engines: **Launchpad Transparency Badges** vs. **Clean Pair Stream Feed**.

---

## 1. Executive Allocation Framework

Signet has completed infrastructure and product development for two complementary commercial engines:
1. **Engine 1 (Launchpads)**: 30-second embeddable transparency trust badges (`180×28px` SVG) shielding platforms from listing liability ($1,499/mo White-Label SaaS).
2. **Engine 2 (Trading Bots)**: Line-rate Clean Pair Stream Feed with pre-resolved EIP-1167/EIP-1967 proxy targets and 19% spam filtering ($499/mo standalone, $899/mo Pro Bot bundle).

Rather than dividing bandwidth arbitrarily, Month 2 engineering and go-to-market allocation will pivot decisively based on the first inbound signals received between **Day 5 and Day 10**.

```
                        [Day 5 Campaign Send]
                                  │
                 ┌────────────────┴────────────────┐
                 ▼                                 ▼
      [Launchpad Inbound]                  [Trading Bot Inbound]
                 │                                 │
                 └───────────────┬─────────────────┘
                                 │
                   [Day 6–10 Decision Protocol]
                                 │
        ┌────────────────────────┼────────────────────────┐
        ▼                        ▼                        ▼
 [Signal 1: Launchpad]    [Signal 2: Feed]         [Signal 3: Both]
   80% Engine 1             80% Engine 2             50/50 Dual Track
   20% Engine 2             20% Engine 1             Hire Contract BD
```

---

## 2. Day 6–10 Decision Matrix & Pivot Triggers

| Signal Received (Days 5–10) | Primary Driver | Bandwidth Split | Immediate Strategic Action |
| :--- | :--- | :--- | :--- |
| **Signal 1: Launchpads Lead**<br>($\ge 2$ Launchpad replies, 0 Bot replies) | **Badges / Liability** | **80% Launchpads**<br>20% Feed | • Build self-serve Launchpad Partner Portal.<br>• Automated presale webhook registration dashboard.<br>• Target 10 additional launchpads (GemPad, DxSale, ApeStore, Pump forks). |
| **Signal 2: Trading Bots Lead**<br>($\ge 2$ Bot replies, 0 Launchpad replies) | **Feed / Latency** | **80% Feed**<br>20% Launchpads | • Productionize low-latency WebSocket gateway.<br>• Deploy per-key rate limiting & multi-region BSC RPC nodes.<br>• Target 5 additional sniper bots (Banana Gun, Photon, Sol/EVM snipers). |
| **Signal 3: Both Engines Pull**<br>($\ge 1$ Launchpad AND $\ge 1$ Bot reply) | **Dual Traction** | **50% Launchpads**<br>50% Feed | • Maintain core infrastructure.<br>• Hire/contract 1 Frontend Integration specialist (launchpads) + 1 Node/Systems engineer (feed).<br>• Package cross-sell ($899/mo Pro Bot + Feed bundle). |
| **Signal 4A: Trading Bot Silence (Day 8)**<br>(0 Bot replies post-FU1) | **Channel / Diagnostic** | **Focus Bot Fix** | • Fast-cycle bot teams evaluate in 3–7 days. Silence by Day 8 signals inbox/channel blockage.<br>• Pivot immediately to Telegram outreach (`@MaestroBotsBD`, `@TrojanOnBSC_BD`). |
| **Signal 4B: Launchpad Silence (Day 18)**<br>(0 Launchpad replies post-FU2) | **Offer / Diagnostic** | **Focus Offer Fix** | • Enterprise launchpads lag 5–14 days. Silence by Day 18 signals stakeholder/friction issues.<br>• Deploy zero-friction 20-listing security audit report offer; expand to 10 secondary launchpads. |

---

## 3. Segmented Diagnostic Protocols (Silence Triage)

Because enterprise launchpads and quant trading bots operate on fundamentally different response cycles, silence diagnostics are decoupled:

### Track A Diagnostic (Triggered on Day 8 if 0 Bot Replies):
*Quant trading bot teams move quickly (3–7 day response cycles). If no reply by Day 8:*
1. **Deliverability Check**: Verify SPF/DKIM and spam placement for engineering inboxes (`integrations@maestrobots.com`, `partnerships@trojan.bot`).
2. **Channel Switch to Telegram**: Move to active developer Telegram handles:
   - Maestro: `@MaestroBotsBD` / `t.me/MaestroBots`
   - Trojan: `@TrojanOnBSC_BD` / Official Trojan Bot Portal
   - *Message format*: 2-sentence technical ping with the pre-resolved EIP-1167 cURL command and sandbox key (`X-Signet-Key: sandbox_test_7d`).
3. **Target Expansion (5 Additional Bot Clusters)**: Expand immediately to Banana Gun BSC, Photon BSC, GMGN.ai, BullX, and Maestro dev community.

### Track B Diagnostic (Triggered on Day 18 if 0 Launchpad Replies):
*Launchpad BD/governance cycles lag naturally (5–14 day review cycles). Do not over-rotate on Day 10 silence; trigger only after Follow-Up 2 on Day 18:*
1. **Friction Reduction Pivot (Complimentary Audit Report)**: Shift from asking for a frontend badge embed to offering a zero-commitment listing quality report:
   *"We analyzed your last 20 BSC listings and discovered 11 unverified factory proxies. Can I send the 1-page PDF audit report for your product team?"*
2. **Launchpad Telegram Outreach**: Ping partnership leads directly on Telegram (e.g. PinkSale Partnership Bot, Four.meme community CMs).
3. **Launchpad Target Expansion (10 Secondary Accounts)**: Dispatch to GemPad, DxSale, Unicrypt, ApeStore, and emerging BSC pump forks.

---

### 3.2 Substance-Level Reply Diagnostic Matrix (Content-Driven Triage)

When inbound replies arrive, evaluate the substantive objection/pattern rather than just the arrival event:

| Observed Reply Pattern | Root Diagnosis | Immediate Counter-Action | Strategic Roadmap Pivot |
| :--- | :--- | :--- | :--- |
| **"We already de-alias proxies internally (via Etherscan/Sourcify)"** | **Latency / Efficiency value proposition, not capability.** Bot has a resolver, but pays high external API latency. | Pivot to latency benchmarks: *"Signet pre-populates target bytecode in a single 14ms payload at block depth, saving 1.5–3.0s of post-detection API round-trips before simulation."* | Double down on Line-Rate WebSocket delivery and benchmark reporting. |
| **"We don't want a public badge on UI, but we want the backend pair feed"** | **Segment boundary crossed.** Launchpad fears UI clutter or endorsement optics, but ops team needs ingestion stream. | Pivot from Badge ($1,499/mo) to Backend Ops Feed ($499/mo) or internal presale compliance webhook API. | Decouple UI badge from backend de-aliasing engine in sales deck. |
| **"We only care about Honeypots / Can-Sell tax checks, not proxy ASTs"** | **Surface checker mental model.** Buyer does not yet grasp post-launch proxy upgradeability exploits. | Deploy 1-page case study: demonstrate how an unverified proxy forwarder altered mint logic 48h after passing surface honeypot scans. | Offer joint GoPlus + Signet integration demo showing complementary layers. |
| **"Can you support other chains (Solana, Base, Arbitrum)?"** | **Cross-chain expansion demand.** Buyer’s highest volume cluster is on an alternate EVM or SVM chain. | Qualify volume: *"Base and Arbitrum use the exact same EIP-1167/1967 engine. We can enable Base private staging for your team next sprint."* | Fast-track Base/Arbitrum DEX factory ingestion in Sprint 3. |

---

## 4. Month 2 Engineering Sprint Slices

### Sprint 1 (Days 5–11): Inbound Handling & Pilot Support
* **Core Tasks**:
  - Triage incoming replies in [`RESPONSE_LOG.md`](file:///home/hektic/Downloads/ai-web3-security/skills/RESPONSE_LOG.md).
  - Issue temporary sandbox API tokens (`X-Signet-Key`) for bot evaluators.
  - Generate customized SVG badge preview links for launchpad pilot listings.
  - Monitor live shadow ingestion worker (`task-1603`) to maintain 15-block finality with zero reorg drops.

### Sprint 2 (Days 12–18): Dominant Stream Productionization
* **If Launchpad Track Leads**:
  - Deploy automated webhook consumer for `POST /v1/launchpad/presale`.
  - Add self-serve badge configuration parameters (custom CSS palette, width, border radius).
  - Implement pilot expiration automation: Day-15 automated transition to `⚪ [ SIGNET | PILOT EXPIRED ]` (HTTP 200).
* **If Trading Bot Track Leads**:
  - Implement dedicated WebSocket server (`wss://api.signet.security/v1/feed/ws`) using Redis pub/sub.
  - Deploy sub-15ms push pipeline from PancakeSwap pair creation directly to connected sockets.
  - Instrument per-key telemetry tracking feed query frequency and bandwidth.

### Sprint 3 (Days 19–25): Commercial Conversion & Billing
* **Core Tasks**:
  - Convert 14-day active pilots into commercial subscriptions.
  - Launch automated Stripe / crypto payment gateway (USDT/USDC on BSC) for self-serve feed keys ($499/mo).
  - Issue White-Label enterprise agreements for launchpads ($1,499/mo).
  - Implement automated token revocation for unrenewed API keys with grace-period notifications.

### Sprint 4 (Days 26–32): Scale & Cross-Sell Engine
* **Core Tasks**:
  - Roll out secondary stream as an add-on to converted clients:
    - Launchpads: Upsell canonical pair feed for listing discovery.
    - Trading bots: Upsell `/v1/scan` deep Slither analysis API ($899/mo Pro bundle).
  - Publish public benchmark report: *"State of BSC Factory Proxies: Analysis of 10,000 Pairs"*, establishing Signet as the industry authority on bytecode de-aliasing.

---

## 5. Month 2 Financial & Unit Economics Guardrails

| Metric | Target (Month 2 Exit) | Guardrail / Boundary |
| :--- | :--- | :--- |
| **Active Paying Customers** | **4–6 enterprise accounts** | Minimum 2 customers to confirm PMF |
| **Monthly Recurring Revenue (MRR)** | **$3,500 – $6,000 MRR** | Covers all node infrastructure + surplus |
| **Gross Margin %** | **> 70.0%** | Maintained via Tier 2 gating (< 10% cold audit trigger) |
| **Monthly Cloud & RPC COGS** | **< $650 / month** | 1 BSC archive node + 1 Redis + edge CDN |
| **Feed P99 Query Latency** | **< 25.0ms** | Maintained via WAL mode + SQLite feed indices |
| **Badge CDN Cache Hit Rate** | **> 98.0%** | Enforced via `s-maxage=300` headers on edge |

---

## 6. Summary Checklist for Day 6 Morning

1. [ ] Check all reply channels (Email, Telegram, Form) at 09:00 UTC.
2. [ ] Log any inbound events in [`RESPONSE_LOG.md`](file:///home/hektic/Downloads/ai-web3-security/skills/RESPONSE_LOG.md).
3. [ ] If $\ge 2$ replies in either track, trigger the corresponding sprint allocation from Section 2.
4. [ ] If zero replies, verify email deliverability and prepare Follow-Up 1 for Day 9 (Bots) and Day 11 (Launchpads).
