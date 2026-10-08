# Signet — Agent Handoff Document

**Last Updated:** 2026-10-08 ~06:52 MST
**Session Duration:** ~18 hours (product build → deploy → outreach)
**Project Root:** `~/Downloads/ai-web3-security/skills/`
**Git Repo:** `git@github.com:DecarloFreelance/signet.git`

---

## 1. What Signet Is

On-chain proxy de-aliasing and cryptographic signature verification for BSC tokens. Resolves EIP-1167 / EIP-1967 / EIP-1822 proxies, runs Slither/Semgrep analysis on the underlying implementation, detects zero-address forgery (SIG-01) and cross-chain replay (SIG-03) flaws that standard scanners miss.

**Core differentiator:** Honeypot protection only checks if you can sell today. Signet checks if the deployer can forge your approval tomorrow.

---

## 2. Current Production State

### Deployed API
- **URL:** https://signet-api.fly.dev
- **Host:** Fly.io, region yyz (Toronto)
- **App name:** signet-api
- **Deploy command:** `cd ~/Downloads/ai-web3-security/skills && fly deploy`

### Verified Working Endpoints (all HTTP 200 / WS 101)
- GET / — landing page
- GET /docs — Swagger UI
- GET /methodology — cryptographic verification methodology
- GET /integration — launchpad badge integration guide
- GET /case-study — the 48-hour proxy upgrade blind spot
- GET /v1/metrics — live telemetry
- GET /v1/badge/{address}.svg — embeddable verification badge
- GET /v1/feed/new-pairs — clean pair stream (with proxy de-aliasing)
- WS /v1/feed/ws — real-time WebSocket pair stream (verified on wss://signet-api.fly.dev/v1/feed/ws)
- GET /v1/launchpad/presale — presale integration documentation & schema
- POST /v1/launchpad/presale — presale cache-warming registration
- GET /v1/scan/{address} — full audit verdict

### Local Ingestion Daemon
- **Task ID:** task-1603
- **Status:** RUNNING
- **Command:** /home/hektic/Downloads/ai-web3-security/.venv/bin/python3 ingest_pair_created.py --daemon --no-audit --interval 6
- **DB:** audit_cache.db (WAL mode, ~5,000 pairs indexed; baked into latest Fly deploy)

---

## 3. Outreach Campaign State

### Live Attempts (3)
| Target | Channel | Status | Sent | FU1 Due |
|--------|---------|--------|------|---------|
| PinkSale | TG @babypinkpink | Cold | 2026-10-08 | Day 11 (Oct 19) |
| Maestro | TG @MaestroSupport (contact request) | Cold | 2026-10-08 | Day 9 (Oct 17) |
| Four.meme | Email support@four.meme | Cold | 2026-10-08 06:52 MST | Day 12 (Oct 20) |

### Dropped Targets (2)
- **Trojan on BSC** — Solana-only. No BSC version exists.
- **GraFun** — Domain gra.fun dead (no A record). Project shut down.

### Bounced Addresses (Do Not Reuse)
- partnerships@pinksale.finance (bounced → pivoted to TG)
- integrations@maestrobots.com (never sent, unverified)
- team@four.meme (bounced → correct is support@four.meme)

---

## 4. The Three-Verification Rule

Before sending to ANY new target, verify:
1. Does the project exist on the chain you are targeting?
2. Does the domain have MX records? (`dig MX <domain> +short` — empty = no email)
3. Is the contact channel published on their own site/docs?

Three checks. Five minutes. Saves a day of bounces.

---

## 5. Key Files

| File | Purpose |
|------|---------|
| api/main.py | FastAPI service — all routes |
| api/scanner.py | Audit engine (proxy + Slither + Semgrep) |
| api/card.py | Risk card renderers |
| api/cache.py | Redis/memory cache |
| ingest_pair_created.py | Live PancakeSwap ingestion daemon |
| scripts/recompute_stats.py | Recomputes stats across collateral |
| scripts/pre_dispatch_check.sh | T-24h verification suite |
| OUTREACH_EMAILS.md | All email templates + follow-ups + inbound playbook |
| RESPONSE_LOG.md | Campaign ledger |
| METHODOLOGY.md | Served at /methodology |
| INTEGRATION.md | Served at /integration |
| CASE_STUDY_PROXY_UPGRADE.md | Served at /case-study |
| MONTH_2_ROADMAP.md | Strategic pivot triggers |
| Dockerfile | Container build |
| fly.toml | Fly config (yyz, 256MB, auto-stop) |
| .dockerignore | Build exclusions |

---

## 6. Credentials & Infrastructure

- **Fly.io:** decarlofreelance@gmail.com (personal org)
- **GitHub:** git@github.com:DecarloFreelance/signet.git (v1.0, commit 75d2226)
- **Sending email:** decarlofreelance@gmail.com
- **Domain:** NONE registered
- **Mail infra:** NONE
- **Fly billing:** No payment method — trial expires ~Oct 15. ADD CARD BEFORE THEN.

---

## 7. Known Constraints

- Fly machine sleeps when idle — first request wakes in ~500ms
- Deployed DB frozen at last fly deploy (~5,000 pairs); local daemon keeps accumulating
- Custom domain pending purchase/DNS wiring (currently served at signet-api.fly.dev)

---

## 8. Next Actions

### When a Reply Arrives
1. Do NOT respond immediately. Paste the reply for review.
2. Match against OUTREACH_EMAILS.md Part IV: Inbound Response-Handling Playbook.
3. Scenarios A (spec), B (TokenSniffer objection), C (white-label) have pre-written responses.

### Cadence Dates
- Oct 17 (Day 9): Maestro FU1 if no reply
- Oct 19 (Day 11): PinkSale FU1 if no reply
- Oct 20 (Day 12): Four.meme FU1 if no reply

Templates in OUTREACH_EMAILS.md Part III.

### Optional Daily Task
`cd ~/Downloads/ai-web3-security/skills && fly deploy` — bakes local DB into deployed app.

### Fly.io Billing
Add payment method before ~Oct 15 or app stops.

---

## 9. How to Resume

1. Read this file: `cat AGENT_HANDOFF.md`
2. Check for replies:
   - Gmail: decarlofreelance@gmail.com
   - Telegram: @babypinkpink, @MaestroSupport
3. Check API: `curl -s -o /dev/null -w "%{http_code}
" https://signet-api.fly.dev/`
4. Check daemon: `ps aux | grep ingest_pair_created`
5. If reply received → paste it and draft response
6. If cadence date reached → send follow-up
7. Otherwise → wait

That is the entire state. Nothing else matters until a reply arrives.
