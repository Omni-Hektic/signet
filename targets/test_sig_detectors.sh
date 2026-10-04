#!/bin/bash
# Test harness for SIG-01 and SIG-03 detectors
#
# Tests Semgrep rules against vulnerable and safe Solidity contracts.
#
# Usage: bash test_sig_detectors.sh
#
# Prerequisites:
#   - semgrep installed: pip install semgrep
#   - Solidity test fixtures in /tmp/

set -euo pipefail

TEST_DIR="/tmp/sig_detector_tests"
RULES_DIR="/tmp"
FIXTURES_DIR="/tmp"

echo "=== SIG-01 & SIG-03 Detector Test Harness ==="
echo ""

# Create test directory
mkdir -p "$TEST_DIR"
cd "$TEST_DIR"

echo "[1/5] Setting up test environment..."
echo "  Test directory: $TEST_DIR"
echo "  Rules directory: $RULES_DIR"
echo "  Fixtures directory: $FIXTURES_DIR"
echo ""

# Check for semgrep
if ! command -v semgrep &> /dev/null; then
  echo "ERROR: semgrep not installed. Install with: pip install semgrep"
  exit 1
fi
echo "✓ semgrep available: $(semgrep --version)"
echo ""

# Copy fixtures to test directory
echo "[2/5] Copying test fixtures..."
cp "$FIXTURES_DIR/VulnerableSig01.sol" "$TEST_DIR/" 2>/dev/null || echo "  ⚠️  VulnerableSig01.sol not found"
cp "$FIXTURES_DIR/VulnerableSig03.sol" "$TEST_DIR/" 2>/dev/null || echo "  ⚠️  VulnerableSig03.sol not found"
cp "$FIXTURES_DIR/SafeSig.sol" "$TEST_DIR/" 2>/dev/null || echo "  ⚠️  SafeSig.sol not found"
echo "✓ Fixtures copied"
echo ""

# Test SIG-01 rule
echo "[3/5] Testing SIG-01 (ecrecover zero-check) rule..."
echo ""

if [ -f "$RULES_DIR/sig-01-ecrecover-zero-check.yaml" ]; then
  echo "=== SIG-01: VulnerableSig01.sol (should flag) ==="
  semgrep --config "$RULES_DIR/sig-01-ecrecover-zero-check.yaml" "$TEST_DIR/VulnerableSig01.sol" --json \
    > "$TEST_DIR/sig01-vulnerable.json" 2>&1 || true

  # Count findings
  VULN_COUNT=$(jq '.results | length' "$TEST_DIR/sig01-vulnerable.json" 2>/dev/null || echo "0")
  echo "Findings: $VULN_COUNT"
  if [ "$VULN_COUNT" -gt 0 ]; then
    echo "✅ PASS: Correctly detected vulnerabilities in VulnerableSig01.sol"
    jq '.results[] | "\(.rule.id): \(.message)"' "$TEST_DIR/sig01-vulnerable.json" | head -3
  else
    echo "⚠️  WARN: No findings in VulnerableSig01.sol (expected to find SIG-01)"
  fi
  echo ""

  echo "=== SIG-01: SafeSig.sol (should NOT flag) ==="
  semgrep --config "$RULES_DIR/sig-01-ecrecover-zero-check.yaml" "$TEST_DIR/SafeSig.sol" --json \
    > "$TEST_DIR/sig01-safe.json" 2>&1 || true

  SAFE_COUNT=$(jq '.results | length' "$TEST_DIR/sig01-safe.json" 2>/dev/null || echo "0")
  echo "Findings: $SAFE_COUNT"
  if [ "$SAFE_COUNT" -eq 0 ]; then
    echo "✅ PASS: Correctly accepted SafeSig.sol (no false positives)"
  else
    echo "⚠️  WARN: Found $SAFE_COUNT finding(s) in SafeSig.sol (possible false positive)"
    jq '.results[] | "\(.rule.id): \(.message)"' "$TEST_DIR/sig01-safe.json" | head -3
  fi
  echo ""
else
  echo "⚠️  SIG-01 rule file not found at $RULES_DIR/sig-01-ecrecover-zero-check.yaml"
  echo ""
fi

# Test SIG-03 rule
echo "[4/5] Testing SIG-03 (chain-id binding) rule..."
echo ""

if [ -f "$RULES_DIR/sig-03-chain-id-domain-separator.yaml" ]; then
  echo "=== SIG-03: VulnerableSig03.sol (should flag) ==="
  semgrep --config "$RULES_DIR/sig-03-chain-id-domain-separator.yaml" "$TEST_DIR/VulnerableSig03.sol" --json \
    > "$TEST_DIR/sig03-vulnerable.json" 2>&1 || true

  VULN_COUNT=$(jq '.results | length' "$TEST_DIR/sig03-vulnerable.json" 2>/dev/null || echo "0")
  echo "Findings: $VULN_COUNT"
  if [ "$VULN_COUNT" -gt 0 ]; then
    echo "✅ PASS: Correctly detected vulnerabilities in VulnerableSig03.sol"
    jq '.results[] | "\(.rule.id): \(.message)"' "$TEST_DIR/sig03-vulnerable.json" | head -3
  else
    echo "⚠️  WARN: No findings in VulnerableSig03.sol (expected to find SIG-03)"
  fi
  echo ""

  echo "=== SIG-03: SafeSig.sol (should NOT flag) ==="
  semgrep --config "$RULES_DIR/sig-03-chain-id-domain-separator.yaml" "$TEST_DIR/SafeSig.sol" --json \
    > "$TEST_DIR/sig03-safe.json" 2>&1 || true

  SAFE_COUNT=$(jq '.results | length' "$TEST_DIR/sig03-safe.json" 2>/dev/null || echo "0")
  echo "Findings: $SAFE_COUNT"
  if [ "$SAFE_COUNT" -eq 0 ]; then
    echo "✅ PASS: Correctly accepted SafeSig.sol (no false positives)"
  else
    echo "⚠️  WARN: Found $SAFE_COUNT finding(s) in SafeSig.sol (possible false positive)"
    jq '.results[] | "\(.rule.id): \(.message)"' "$TEST_DIR/sig03-safe.json" | head -3
  fi
  echo ""
else
  echo "⚠️  SIG-03 rule file not found at $RULES_DIR/sig-03-chain-id-domain-separator.yaml"
  echo ""
fi

# Summary
echo "[5/5] Test Summary"
echo ""
echo "Test results saved to: $TEST_DIR/"
echo "  - sig01-vulnerable.json: SIG-01 findings in VulnerableSig01.sol"
echo "  - sig01-safe.json: SIG-01 findings in SafeSig.sol (should be empty)"
echo "  - sig03-vulnerable.json: SIG-03 findings in VulnerableSig03.sol"
echo "  - sig03-safe.json: SIG-03 findings in SafeSig.sol (should be empty)"
echo ""

# Print final verdict
echo "=== VERDICT ==="
SIG01_VULN=$(jq '.results | length' "$TEST_DIR/sig01-vulnerable.json" 2>/dev/null || echo "0")
SIG01_SAFE=$(jq '.results | length' "$TEST_DIR/sig01-safe.json" 2>/dev/null || echo "0")
SIG03_VULN=$(jq '.results | length' "$TEST_DIR/sig03-vulnerable.json" 2>/dev/null || echo "0")
SIG03_SAFE=$(jq '.results | length' "$TEST_DIR/sig03-safe.json" 2>/dev/null || echo "0")

echo ""
echo "SIG-01 (ecrecover zero-check):"
echo "  VulnerableSig01.sol: $SIG01_VULN findings (expected > 0) $([ "$SIG01_VULN" -gt 0 ] && echo "✅" || echo "❌")"
echo "  SafeSig.sol: $SIG01_SAFE findings (expected 0) $([ "$SIG01_SAFE" -eq 0 ] && echo "✅" || echo "❌")"
echo ""
echo "SIG-03 (chain-id binding):"
echo "  VulnerableSig03.sol: $SIG03_VULN findings (expected > 0) $([ "$SIG03_VULN" -gt 0 ] && echo "✅" || echo "❌")"
echo "  SafeSig.sol: $SIG03_SAFE findings (expected 0) $([ "$SIG03_SAFE" -eq 0 ] && echo "✅" || echo "❌")"
echo ""

# Overall result
if [ "$SIG01_VULN" -gt 0 ] && [ "$SIG01_SAFE" -eq 0 ] && [ "$SIG03_VULN" -gt 0 ] && [ "$SIG03_SAFE" -eq 0 ]; then
  echo "✅ All tests passed!"
  exit 0
else
  echo "⚠️  Some tests did not meet expected thresholds (see results above)"
  exit 1
fi
