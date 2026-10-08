# Signet Launchpad Badge Integration Guide
**Target Audience**: Frontend & Smart Contract Engineers at PinkSale, Four.meme, GraFun, and BSC DEX Launchpads  
**Engine Version**: Signet v1.0 | BSC Mainnet (`chainId: 56`)  
**Base Endpoint**: `https://api.signet.security` (or self-hosted / staging endpoint)

---

## 1. Executive Summary

Honeypot detectors and token tax simulators only verify if a user can sell *today*. They cannot detect whether a deployer has hidden an unverified `ecrecover` zero-address bypass or omitted chain-ID bindings to forge token approvals and drain user balances *tomorrow*.

**Signet provides real-time cryptographic verification of smart contract delegation security.**

Integrating the Signet badge into your token presale or fair-launch page gives your users an instant, cryptographic signal that:
1. **The contract does not permit signature forgery** (SIG-01 Slither SSA IR validated).
2. **Permits cannot be replayed across chains** (SIG-03 Semgrep validated).
3. **The contract is de-aliased** across EIP-1167 / EIP-1967 proxy implementations.

---

## 2. Instant Embed (HTML & Markdown)

Paste this snippet into your token listing page template:

### HTML Embed
```html
<!-- Signet Security Seal -->
<a href="https://signet.security/scan/0x07bcb8e8226f671300e135b4a61dc157359b7777" 
   target="_blank" 
   rel="noopener noreferrer"
   title="View Signet Cryptographic Verification Report">
  <img src="https://api.signet.security/v1/badge/0x07bcb8e8226f671300e135b4a61dc157359b7777.svg" 
       alt="Signet Security Badge" 
       width="180" 
       height="28" 
       loading="lazy" />
</a>
```

### Markdown Embed (For GitHub, Medium, or GitBook Docs)
```markdown
[![Signet Security Seal](https://api.signet.security/v1/badge/0x07bcb8e8226f671300e135b4a61dc157359b7777.svg)](https://signet.security/scan/0x07bcb8e8226f671300e135b4a61dc157359b7777)
```

---

## 3. React / Next.js Component

For seamless integration into React/Next.js launchpad interfaces with automatic modal previews:

```tsx
import React, { useState } from 'react';

interface SignetBadgeProps {
  tokenAddress: string;
  apiBaseUrl?: string;
  theme?: 'dark' | 'light';
}

export const SignetSecurityBadge: React.FC<SignetBadgeProps> = ({
  tokenAddress,
  apiBaseUrl = 'https://api.signet.security',
}) => {
  const [modalOpen, setModalOpen] = useState(false);
  const badgeUrl = `${apiBaseUrl}/v1/badge/${tokenAddress}.svg`;
  const reportUrl = `${apiBaseUrl}/v1/scan/${tokenAddress}`;

  return (
    <div className="inline-flex items-center gap-2">
      <button
        onClick={() => setModalOpen(true)}
        className="transition-transform hover:scale-105 focus:outline-none"
        aria-label="View Signet Cryptographic Audit Details"
      >
        <img
          src={badgeUrl}
          alt="Signet Security Verification"
          width={180}
          height={28}
          className="rounded shadow-sm"
          onError={(e) => {
            // Graceful fallback to unverified if network timeout
            (e.target as HTMLImageElement).src = `${apiBaseUrl}/v1/badge/0x0000000000000000000000000000000000000000.svg`;
          }}
        />
      </button>

      {modalOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm p-4">
          <div className="bg-slate-900 border border-slate-700 rounded-xl max-w-lg w-full p-6 text-white shadow-2xl">
            <div className="flex justify-between items-center mb-4 border-b border-slate-800 pb-3">
              <h3 className="font-bold text-lg flex items-center gap-2">
                🛡️ Signet Cryptographic Verification
              </h3>
              <button 
                onClick={() => setModalOpen(false)}
                className="text-slate-400 hover:text-white text-xl"
              >
                ✕
              </button>
            </div>
            
            <p className="text-sm text-slate-300 mb-4">
              Detailed cryptographic verification for contract <code className="bg-slate-800 px-1 py-0.5 rounded text-emerald-400">{tokenAddress}</code>.
            </p>

            <iframe 
              src={reportUrl} 
              className="w-full h-64 border border-slate-800 rounded bg-slate-950 text-xs p-2"
              title="Signet Audit Report"
            />

            <div className="mt-4 flex justify-end gap-2">
              <a
                href={`https://bscscan.com/address/${tokenAddress}#code`}
                target="_blank"
                rel="noreferrer"
                className="px-3 py-1.5 text-xs bg-slate-800 hover:bg-slate-700 rounded text-slate-300"
              >
                View on BscScan
              </a>
              <button
                onClick={() => setModalOpen(false)}
                className="px-4 py-1.5 text-xs bg-emerald-600 hover:bg-emerald-500 rounded font-medium text-white"
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
```

---

## 4. Badge States & Visual Specifications

The SVG endpoint dynamically renders one of four distinct states based on the contract bytecode and Slither/Semgrep verdicts:

| Badge State | Visual Appearance | Meaning / Criteria | Allow Presale? |
| :--- | :--- | :--- | :--- |
| **VERIFIED CLEAN** | `[ SIGNET \| VERIFIED CLEAN ]` (Green `#28a745`) | Bytecode verified. EIP-712/permit validated. No unchecked `ecrecover`. Chain-ID bound. | ✅ **Recommended** |
| **FORGERY RISK** | `[ SIGNET \| FORGERY RISK ]` (Red `#dc3545`) | Unchecked `ecrecover` return allows `address(0)` signature forgery (SIG-01). Deployer can forge permits. | 🚨 **Block Presale** |
| **REPLAY RISK** | `[ SIGNET \| REPLAY RISK ]` (Orange `#fd7e14`) | Permitted signatures lack chain ID binding (SIG-03). Signatures can be hijacked across chains. | ⚠️ **Warning Banner** |
| **UNVERIFIED** | `[ SIGNET \| UNVERIFIED ]` (Grey `#6c757d`) | Bytecode not verified on BscScan/Sourcify. Cryptographic logic closed-source. | ⚪ **Manual Review** |

---

## 5. Automated Presale Pipeline Integration (Webhook API)

If your launchpad runs automated screening before permitting pools to go live, call the async scanning endpoint during pool creation:

### Step 1: Enqueue Token for Cryptographic Scan
```bash
curl -X GET "https://api.signet.security/v1/scan/0x07bcb8e8226f671300e135b4a61dc157359b7777?callback_url=https://your-launchpad.com/api/signet-webhook"
```

#### Response (Cold Cache Miss — HTTP 202 Accepted, < 20ms):
```json
{
  "status": "accepted",
  "job_id": "job_3a8b41f92e70",
  "address": "0x07bcb8e8226f671300e135b4a61dc157359b7777",
  "message": "Cold audit initiated. Background worker compiling and running Slither IR analysis.",
  "check_status_url": "/v1/jobs/job_3a8b41f92e70",
  "estimated_duration_seconds": 15.0
}
```

### Step 2: Receive Webhook Callback (Automatic Retry with Backoff)
When compilation and static analysis finish (p50 ~15.75s), Signet delivers a POST webhook:

```json
{
  "job_id": "job_3a8b41f92e70",
  "address": "0x07bcb8e8226f671300e135b4a61dc157359b7777",
  "status": "completed",
  "card": {
    "token_symbol": "HOOKS",
    "status": "VERIFIED_CLEAN",
    "badge_text": "🟢 SIGNET VERIFIED [CLEAN]",
    "allow_trade": true,
    "is_proxy": true,
    "proxy_type": "EIP-1167",
    "implementation_address": "0x024f18294970b5c76c0691b87f138a0317156422",
    "sig01_status": "PASS",
    "sig03_status": "PASS",
    "recommendation": "SAFE: Zero signature delegation vulnerabilities detected."
  }
}
```

* **Retry Policy**: 3 attempts with exponential backoff (1s, 2s, 4s).
* **Job TTL**: Job results remain queryable at `/v1/jobs/{job_id}` for **1 hour (3600s)**.

---

## 6. SLA & Performance Guarantee

* **Badge Embed Latency**: `< 10ms` (served from CDN & Redis cache).
* **Cold Analysis**: Asynchronous background queue; never blocks frontend page load.
* **Uptime Target**: 99.9% availability across BSC Mainnet (`chainId: 56`).
* **Zero False Positives**: Validated on 41 test fixtures and 37 live BSC tokens with 0% false positives.

---

## 7. Pilot Program, Exit Policy & Conversion Path

### 14-Day Free Pilot Terms
* **Access**: Unrestricted API and badge embedding for all presale pools on your platform.
* **Support**: Shared Telegram engineering channel with direct dev access (`@SignetSecurityDev`).
* **Co-Marketing**: Launchpad featured as a verified security partner on Signet's weekly BSC Risk Map.

### What Happens on Day 15 (Zero-Disruption Invariant)
We enforce a strict **Zero-Disruption Guarantee**:
* **The badge NEVER disappears or 404s**: If an agreement is not renewed on Day 15, the badge seamlessly renders a neutral fallback:
  `⚪ [ SIGNET | PILOT EXPIRED ]` (HTTP 200, identical 180x28px dimension, zero layout shifts).
* **Existing presale pages do NOT break**: All previous audits remain cached and readable.
* **No Sudden Cutoff**: 72-hour and 24-hour advance notifications sent via Telegram before pilot expiration.

### Post-Pilot Pricing Tiers
| Tier | Monthly Fee | Features |
| :--- | :--- | :--- |
| **Community Free Tier** | $0 / month | Public badge embed, rate-limited to 50 new pools/day, standard Signet watermark. |
| **Pro Launchpad Tier** | $899 / month | Unlimited badges, dedicated background worker, priority queue, co-branded modal. |
| **Enterprise Launchpad**| $2,499 / month | Custom badge styling, 99.9% uptime SLA, webhook dead-letter alerts, direct pager support. |

### Integration Ownership
* **Frontend Embed**: 100% self-serve. Drop in the `<img src="..." />` or React component. Requires zero backend changes and zero staging credentials from your team.
* **Webhook Screening (Optional)**: If you choose automated presale gating, we provide an instant test harness to verify your webhook handler in < 30 minutes.

---

## 8. Frontend Hardening & CDN Caching Specifications

* **SVG Sanitization Resilient**: Pure vector SVG with inline presentation attributes. Contains no `<script>`, no external styles, and no remote fonts that CSP or SVG sanitizers block.
* **CDN Caching Policy**:
  * Cached Badges: `Cache-Control: public, max-age=60, s-maxage=300` (browser caches 1m, Cloudflare/CloudFront caches 5m).
  * Pending Audits: `Cache-Control: no-cache, no-store, must-revalidate` (guarantees the badge refreshes once the audit completes).
* **Dimensions**: Fixed `180px` width by `28px` height with standard 4px border radius.

---

## 9. Scope Limitations & Legal Disclaimers (Liability Boundary)

To protect both launchpads and Signet, the badge represents a strictly bounded cryptographic inspection signal—**not an investment endorsement or full-stack security warranty**:

1. **Evaluated Scope**:
   * Signet evaluates cryptographic signature delegation entry points (SIG-01 unchecked `ecrecover` zero-address bypass, SIG-03 missing chain-ID replay binding) and performs on-chain proxy de-aliasing (EIP-1167, EIP-1967, EIP-1822).
2. **Explicit Non-Scope**:
   * Signet does **NOT** evaluate:
     * Economic soundness, tokenomics, team identity, liquidity locker duration, or non-signature rug-pull vectors.
     * Dynamic buy/sell taxes, trading disable switches, or blacklists (covered by standard honeypot simulators).
     * Reentrancy, logic bugs, price oracle manipulation, or flash-loan attack surfaces.
3. **Meaning of the Badges**:
   * `🟢 VERIFIED CLEAN`: Confirms that zero cryptographic signature delegation flaws were detected in the analyzed implementation bytecode. **It does NOT guarantee that the token is safe to invest in or immune to economic rugs.**
   * `⚪ UNVERIFIED`: Indicates that contract bytecode is closed-source or unverified; cryptographic delegation safety cannot be algorithmically proven.
4. **Integration Recommendation**:
   * Launchpads should render the badge linked directly to the methodology report (`https://signet.security/methodology`) alongside their standard user-facing token risk disclosure.

---

## 10. Contact & Integration Kickoff

* **Direct Engineering Support**: Telegram `@SignetSecurityDev`
* **BD & Partnerships**: `partnerships@signet.security`
* **Website**: `https://signet.security`

