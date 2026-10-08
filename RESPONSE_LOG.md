# Signet Day-5 Outreach & Response Ledger

**Campaign Start Date**: Day 5  
**Active Targets**: 5 initial enterprise prospects across 2 distinct tracks.  
**Policy**: Maintain strict cadence compliance. Never send Follow-Up $N+1$ without logging Follow-Up $N$. Stop cadence immediately upon prospect reply and transition stage.

---

## 1. Cadence Schedules

| Track | Target Segment | Initial Send | Follow-Up 1 (+Days) | Follow-Up 2 (+Days) | Follow-Up 3 (+Days) |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Track A** | **Trading Bots** | **2026-10-08** | Day 9 (+4d) | Day 14 (+5d) | Day 26 (+12d) |
| **Track B** | **Launchpads** | **2026-10-08** | Day 11 (+6d) | Day 19 (+8d) | Day 35 (+16d) |

---

## 2. Active Prospect Ledger

| Company | Track | Primary Contact | Alternate Channel | Send Date | FU1 Date / Sent | FU2 Date / Sent | FU3 Date / Sent | Reply Channel | Stage | Notes & Status |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **PinkSale** | Track B (Launchpad) | `@babypinkpink` (TG — email bounced) | Telegram DM | 2026-10-08 | Day 11 [ ] | Day 19 [ ] | Day 35 [ ] | TG | `Cold` | Telegram DM delivered 2026-10-08. Awaiting reply. |
| **Maestro Bots** | Track A (Bot) | `@MaestroSupport` (TG — requested BD contact) | TG support channel | 2026-10-08 | Day 9 [ ] | Day 14 [ ] | Day 26 [ ] | TG | `Cold` | Contact-request sent 2026-10-08. Awaiting BD contact. |
| **Four.meme** | Track B (Launchpad) | `support@four.meme` (correct address per their GitBook) | Official TG community | 2026-10-08 | Day 12 [ ] | Day 20 [ ] | Day 36 [ ] | Email | `Cold` | Email sent 2026-10-08. Awaiting reply. |
| ~~Trojan on BSC~~ | — | — | — | — | — | — | — | — | `DROPPED` | Solana-only. No BSC product exists. Not a valid target. |
| ~~GraFun~~ | — | — | — | — | — | — | — | — | `DROPPED` | Domain dead (no A record). Project shut down / red-flagged on DappBay. Not contactable. |

---

## 3. Stage Progression Definitions

* **`Cold`**: Email dispatched; awaiting response or cadence trigger.
* **`Replied`**: Prospect responded. **Cadence paused immediately.** Route to appropriate playbook scenario (A: Spec, B: GoPlus Objection, C: White-Label).
* **`Sandbox Active`** *(Track A)*: Prospect issued sandbox token (`sandbox_test_7d`) for `GET /v1/feed/new-pairs`. Log query volume in telemetry.
* **`Preview Generated`** *(Track B)*: 3 live listing preview badges generated and shared with product lead.
* **`Technical Sync`**: 15-minute integration call or Telegram group initiated with engineering/BD.
* **`Pilot Active`**: Launchpad has embed live on $\ge 1$ listing page (14-day window active); or bot ingesting live stream in staging.
* **`Converted`**: Commercial contract signed ($499/mo Feed, $899/mo Pro Bot, or $1,499/mo White-Label Launchpad).
* **`Declined / Closed`**: Prospect declined or Follow-Up 3 completed with no response. Log reason and archive.

---

## 4. Response Event Log

*Log inbound interactions in reverse chronological order:*

| Timestamp | Company | Contact | Channel | Event / Message Summary | Next Action & Owner |
| :--- | :--- | :--- | :--- | :--- | :--- |
| *Day 5* | *All* | — | *Email* | *Initial Day-5 outreach batch dispatched.* | *Monitor inboxes; prepare Day 9/11 follow-ups.* |
| 2026-10-08 06:47 MST | Four.meme | team@four.meme | Email | Initial outreach dispatched (proxy de-aliasing pitch, 3-listing badge preview offer). | Monitor inbox; FU1 scheduled Day 12. |

---

## 5. Inbound Dispatch Routing Rules

1. **If Launchpad replies asking for spec**:
   - Send Scenario A1 playbook template within 2 hours.
   - Include 1-page [INTEGRATION.md](https://signet-api.fly.dev/integration) link and `<img src="...">` snippet.
2. **If Trading Bot replies asking for API access**:
   - Issue temporary token via `api/main.py`.
   - Send Scenario A2 playbook template with cURL and WebSocket sample.
3. **If Competitor objection raised (TokenSniffer / GoPlus)**:
   - Deploy Scenario B template: explain orthogonal bytecode de-aliasing primitive vs surface tax simulation.
4. **If White-Label / Self-Hosting requested**:
   - Deploy Scenario C template ($1,499/mo Managed vs $36,000/yr On-Prem appliance with bounded 60-day pilot credit).
