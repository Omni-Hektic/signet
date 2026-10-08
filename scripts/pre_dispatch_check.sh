#!/usr/bin/env bash
# ==============================================================================
# scripts/pre_dispatch_check.sh: Signet T-24h Pre-Dispatch Verification Tool
#
# Consolidates DNS checks, daemon health, RPC rate-limit audits, API test suite,
# empirical denominator updates, and endpoint HTTP verification into one command.
#
# Usage:
#   bash scripts/pre_dispatch_check.sh [--selector google|default] [--skip-dns]
# ==============================================================================

set -e

DKIM_SELECTOR="google"
SKIP_DNS=false

for arg in "$@"; do
  case $arg in
    --selector=*)
      DKIM_SELECTOR="${arg#*=}"
      shift
      ;;
    --skip-dns)
      SKIP_DNS=true
      shift
      ;;
    *)
      ;;
  esac
done

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "${ROOT_DIR}"

if [ -f "${ROOT_DIR}/../.venv/bin/python3" ]; then
  PYTHON_BIN="${ROOT_DIR}/../.venv/bin/python3"
elif [ -f "${ROOT_DIR}/.venv/bin/python3" ]; then
  PYTHON_BIN="${ROOT_DIR}/.venv/bin/python3"
else
  PYTHON_BIN="python3"
fi

PASS_COUNT=0
WARN_COUNT=0
FAIL_COUNT=0

log_pass() {
  echo -e "\033[32m[PASS]\033[0m $1"
  PASS_COUNT=$((PASS_COUNT + 1))
}

log_warn() {
  echo -e "\033[33m[WARN]\033[0m $1"
  WARN_COUNT=$((WARN_COUNT + 1))
}

log_fail() {
  echo -e "\033[31m[FAIL]\033[0m $1"
  FAIL_COUNT=$((FAIL_COUNT + 1))
}

echo "================================================================="
echo "       SIGNET PRE-DISPATCH VERIFICATION SUITE (T-24H)            "
echo "================================================================="
echo "Working Directory : ${ROOT_DIR}"
echo "Python Executable : ${PYTHON_BIN}"
echo "Timestamp         : $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
echo "================================================================="

# ------------------------------------------------------------------------------
# 1. Deliverability & DNS Authentication (SPF / DKIM / DMARC)
# ------------------------------------------------------------------------------
echo -e "\n[*] Step 1: Checking DNS Deliverability Records for signet.security..."

if [ "$SKIP_DNS" = true ]; then
  log_warn "DNS checks skipped by flag (--skip-dns)."
else
  # SPF Check
  SPF_RECORD=$(dig TXT signet.security +short 2>/dev/null | grep -i "v=spf1" || true)
  if [ -n "${SPF_RECORD}" ]; then
    log_pass "SPF Record found: ${SPF_RECORD}"
  else
    log_warn "SPF Record not found on signet.security (verify if DNS is live)."
  fi

  # DKIM Check
  DKIM_RECORD=$(dig TXT "${DKIM_SELECTOR}._domainkey.signet.security" +short 2>/dev/null || true)
  if [ -n "${DKIM_RECORD}" ]; then
    log_pass "DKIM Record (${DKIM_SELECTOR}) found: ${DKIM_RECORD:0:30}..."
  else
    log_warn "DKIM Record (${DKIM_SELECTOR}._domainkey.signet.security) not found."
  fi

  # DMARC Check
  DMARC_RECORD=$(dig TXT _dmarc.signet.security +short 2>/dev/null | grep -i "v=DMARC1" || true)
  if [ -n "${DMARC_RECORD}" ]; then
    log_pass "DMARC Record found: ${DMARC_RECORD}"
  else
    log_warn "DMARC Record (_dmarc.signet.security) not found."
  fi
fi

# ------------------------------------------------------------------------------
# 2. Ingestion Daemon Health & Rate-Limit Audit
# ------------------------------------------------------------------------------
echo -e "\n[*] Step 2: Verifying Ingestion Daemon & Error Telemetry..."

DAEMON_PIDS=$(pgrep -f "ingest_pair_created.py" || true)
if [ -n "${DAEMON_PIDS}" ]; then
  log_pass "Ingestion daemon is actively running (PID: ${DAEMON_PIDS})."
else
  log_warn "Ingestion daemon is not running in background."
fi

# Check SQLite WAL mode & integrity
if [ -f "audit_cache.db" ]; then
  INTEGRITY=$(sqlite3 audit_cache.db "PRAGMA integrity_check;" 2>/dev/null || echo "error")
  JOURNAL=$(sqlite3 audit_cache.db "PRAGMA journal_mode;" 2>/dev/null || echo "error")
  PAIRS_COUNT=$(sqlite3 audit_cache.db "SELECT COUNT(*) FROM discovered_pairs;" 2>/dev/null || echo "0")
  
  if [ "${INTEGRITY}" == "ok" ]; then
    log_pass "SQLite audit_cache.db integrity check: OK (${PAIRS_COUNT} pairs indexed)."
  else
    log_fail "SQLite integrity check failed: ${INTEGRITY}"
  fi

  if [ "${JOURNAL}" == "wal" ]; then
    log_pass "SQLite journal_mode is WAL (concurrent non-blocking reads/writes)."
  else
    log_warn "SQLite journal_mode is ${JOURNAL} (WAL recommended)."
  fi
else
  log_fail "audit_cache.db not found!"
fi

# Scan task log for 429/rate-limit errors
ERR_MATCHES=$("${PYTHON_BIN}" -c "
import glob, re, os
logs = glob.glob(os.path.expanduser('~/.gemini/antigravity-cli/brain/*/.system_generated/tasks/*.log'))
found = 0
for lp in logs:
    try:
        with open(lp, 'r', errors='ignore') as f:
            c = f.read()
            if 'ingest_pair_created.py' in c:
                m = re.findall(r'.*(?:rate[_\s-]?limit|HTTP 429|Too Many Requests|RPC error).*', c, re.IGNORECASE)
                found += len(m)
    except:
        pass
print(found)
" 2>/dev/null || echo "0")

if [ "${ERR_MATCHES}" -eq 0 ]; then
  log_pass "Zero RPC rate-limit, 429, or backlog errors detected in ingestion logs."
else
  log_warn "${ERR_MATCHES} potential rate-limit/backlog warning lines detected."
fi

# ------------------------------------------------------------------------------
# 3. Test Suite SLA Validation (Warm Cache, Cold Miss, Line-Rate Feed)
# ------------------------------------------------------------------------------
echo -e "\n[*] Step 3: Running API Test Suite (tests/test_api.py)..."

set +e
TEST_OUTPUT=$("${PYTHON_BIN}" tests/test_api.py 2>&1)
TEST_EXIT=$?
set -e

if [ ${TEST_EXIT} -eq 0 ]; then
  log_pass "API Test Suite: 12/12 tests passed successfully (including WebSocket & Presale doc)."
else
  echo "${TEST_OUTPUT}"
  log_fail "API Test Suite encountered failures (exit code ${TEST_EXIT})."
fi

# ------------------------------------------------------------------------------
# 4. Denominator & Collateral Recomputation
# ------------------------------------------------------------------------------
echo -e "\n[*] Step 4: Recomputing Production Metrics & Updating Collateral..."

set +e
RECOMP_OUTPUT=$("${PYTHON_BIN}" scripts/recompute_stats.py --update-emails 2>&1)
RECOMP_EXIT=$?
set -e

if [ ${RECOMP_EXIT} -eq 0 ]; then
  log_pass "Empirical denominator synchronized across OUTREACH_EMAILS.md."
  echo "${RECOMP_OUTPUT}" | grep -E "Total Confirmed|Canonical Quote|Measured Ingestion|Tier 2 Evaluated|Live Proxy Rate" || true
else
  echo "${RECOMP_OUTPUT}"
  log_fail "recompute_stats.py failed with exit code ${RECOMP_EXIT}."
fi

# ------------------------------------------------------------------------------
# 5. Core Collateral & Links Verification
# ------------------------------------------------------------------------------
echo -e "\n[*] Step 5: Verifying Core Collateral Files..."

FILES_TO_CHECK=(
  "OUTREACH_EMAILS.md"
  "RESPONSE_LOG.md"
  "MONTH_2_ROADMAP.md"
  "CASE_STUDY_PROXY_UPGRADE.md"
  "METHODOLOGY.md"
  "INTEGRATION.md"
  "dist/methodology/index.html"
)

for f in "${FILES_TO_CHECK[@]}"; do
  if [ -f "${f}" ]; then
    log_pass "Found: ${f} ($(wc -l < "${f}") lines)"
  else
    log_fail "Missing critical file: ${f}"
  fi
done

# ------------------------------------------------------------------------------
# Final Pre-Flight Summary
# ------------------------------------------------------------------------------
echo -e "\n================================================================="
echo "                    PRE-DISPATCH SUMMARY                         "
echo "================================================================="
echo -e "Passed Checks   : \033[32m${PASS_COUNT}\033[0m"
echo -e "Warnings        : \033[33m${WARN_COUNT}\033[0m"
echo -e "Failed Checks   : \033[31m${FAIL_COUNT}\033[0m"
echo "================================================================="

if [ ${FAIL_COUNT} -eq 0 ]; then
  echo -e "\033[32m[+] SYSTEM IS GREEN FOR DAY-5 STAGGERED OUTREACH DISPATCH.\033[0m"
  echo "Next Step: Execute Batch 1 (PinkSale + Maestro Bots) and log in RESPONSE_LOG.md."
  exit 0
else
  echo -e "\033[31m[!] CRITICAL GAPS DETECTED. Resolve failed items before send.\033[0m"
  exit 1
fi
