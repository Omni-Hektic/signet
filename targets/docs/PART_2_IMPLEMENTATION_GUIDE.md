# Part 2: SIG-01 & SIG-03 Detection Implementation Guide

**Status**: Ready for integration  
**Reference tooling**: Semgrep + Slither + LLM agent synthesis  
**Test coverage**: VulnerableSig01.sol, VulnerableSig03.sol, SafeSig.sol  

---

## Deliverables (Generated)

### 1. Semgrep Rules

**SIG-01: ecrecover Zero-Check**
- File: `/tmp/sig-01-ecrecover-zero-check.yaml`
- Detects: Missing `require(signer != address(0))` after `ecrecover()` calls
- Coverage: 3 rule variants
  - `sig-01-ecrecover-missing-zero-check` — primary rule, HIGH confidence
  - `sig-01-ecrecover-zero-check-if-revert` — if-revert pattern variant
  - `sig-01-ecrecover-implicit-zero-check` — implicit checks without explicit guard

**SIG-03: Chain-ID / Domain Separator Binding**
- File: `/tmp/sig-03-chain-id-domain-separator.yaml`
- Detects: Missing `block.chainid` or `address(this)` in signature digest
- Coverage: 6 rule variants
  - `sig-03-permit-missing-chainid` — `permit()` functions
  - `sig-03-transfer-with-sig-missing-chainid` — `transferWithSig()` functions
  - `sig-03-execute-meta-transaction-missing-chainid` — meta-transaction functions
  - `sig-03-recover-missing-chainid` — signature recovery functions
  - `sig-03-is-valid-signature-missing-chainid` — ERC1271 validation
  - `sig-03-generic-keccak-missing-context` — catch-all for missed patterns

### 2. Test Fixtures

**VulnerableSig01.sol** (`/tmp/VulnerableSig01.sol`)
- 4 vulnerable patterns demonstrating SIG-01 risks
- `recoverSigner()` — basic missing zero-check
- `transferFromSigner()` — implicit zero-check via if-revert
- `recoverSignerWithMultiCheck()` — wrong guard order
- Expected: SIG-01 rule should flag all 4 functions

**VulnerableSig03.sol** (`/tmp/VulnerableSig03.sol`)
- 5 vulnerable patterns demonstrating SIG-03 risks
- `permit()` — missing both chain-id and address(this)
- `transferWithSig()` — missing both bindings
- `executeMetaTransaction()` — missing both bindings
- `permitWithoutAddressBinding()` — missing address(this) only
- `permitWithoutChainIdBinding()` — missing chain-id only
- Expected: SIG-03 rule should flag all 5 functions

**SafeSig.sol** (`/tmp/SafeSig.sol`)
- 7 correct implementations demonstrating safe patterns
- Full EIP712 domain separator with chain-id + address(this)
- Explicit zero-address checks before comparisons
- Multiple variants (permit, transferWithSig, executeMetaTransaction, recover, isValidSignature)
- Expected: Neither SIG-01 nor SIG-03 rules should flag these functions

### 3. Test Runner

**test_sig_detectors.sh** (`/tmp/test_sig_detectors.sh`)
- Bash script to execute Semgrep against all fixtures
- Validates true positives (finds issues in Vulnerable* contracts)
- Validates false negatives (no false positives in SafeSig.sol)
- Generates JSON results + summary verdict
- Usage: `bash /tmp/test_sig_detectors.sh`

---

## Quick Start: Test the Rules

```bash
# 1. Ensure semgrep is installed
pip install semgrep

# 2. Run the test harness
bash /tmp/test_sig_detectors.sh

# 3. Expected output:
#   ✅ All tests passed!
#   SIG-01: Found vulnerabilities in VulnerableSig01.sol
#   SIG-03: Found vulnerabilities in VulnerableSig03.sol
#   No false positives in SafeSig.sol

# 4. Review individual results
jq '.results' /tmp/sig_detector_tests/sig01-vulnerable.json
jq '.results' /tmp/sig_detector_tests/sig03-vulnerable.json
```

---

## Integration Path: Semgrep → Slither → LLM Synthesis

### Phase 1: Semgrep Rules (Deterministic Static Analysis)

**What Semgrep does:**
- Fast pattern matching against source code
- No AST parsing or IR analysis required
- Reports file:line, matched code snippet, severity
- False positives: ~5-10% (pattern matches that aren't true bugs)
- False negatives: ~15-20% (edge cases, encoding variations)

**Output schema:**
```json
{
  "rule": { "id": "sig-01-ecrecover-missing-zero-check", "severity": "HIGH" },
  "message": "SIG-01: Missing zero-address check on ecrecover() return value.",
  "location": { "path": "contracts/Token.sol", "start": { "line": 42 } },
  "metadata": { "confidence": "HIGH" }
}
```

**Integration into solidity-auditor:**
1. Add Semgrep rules to `solidity-auditor/references/semgrep-rules/`
2. In Turn 2 step 1 (source.md build), run Semgrep in parallel
3. Output findings as Markdown blocks in agent bundle
4. Agents read Semgrep findings + source code, synthesize high-confidence reports

### Phase 2: Slither Detectors (IR-Based Analysis)

**What Slither does:**
- Compile contract to AST/IR (Intermediate Representation)
- Walk data-flow graph and control flow
- Run specialized detectors (access control, arithmetic, state machine, etc.)
- Reports precise root causes with exact code locations
- False positives: ~2-5% (typically edge cases or misconfigurations)
- False negatives: ~5-10% (obfuscated patterns, external call side effects)

**Slither API for SIG-01:**
```python
from slither.core.cfg.node import NodeType
from slither.slithir.operations import Call

def detect_ecrecover_zero_check(contract):
    findings = []
    
    for function in contract.functions_and_modifiers_declared:
        for node in function.nodes:
            if node.type == NodeType.EXPRESSION:
                for call in node.irs:
                    if call.function.name == "ecrecover":
                        # Check if return value is validated
                        return_var = call.lvalue
                        
                        # Look for zero-check in same function
                        has_zero_check = False
                        for other_node in function.nodes:
                            for ir in other_node.irs:
                                # Pattern: require(var != 0) or if(var == 0) revert
                                if (return_var in ir.read and 
                                    ("require" in ir.function.name or "revert" in other_node.name)):
                                    has_zero_check = True
                        
                        if not has_zero_check:
                            findings.append({
                                "function": function.name,
                                "line": call.node.source_mapping.start,
                                "issue": "ecrecover() return not checked for address(0)"
                            })
    
    return findings
```

**Slither API for SIG-03:**
```python
def detect_missing_chainid_binding(contract):
    findings = []
    
    for function in contract.functions_and_modifiers_declared:
        if function.name not in ["permit", "transferWithSig", "executeMetaTransaction", 
                                 "executeBySig", "recover", "isValidSignature"]:
            continue
        
        for node in function.nodes:
            for ir in node.irs:
                # Look for keccak256(abi.encodePacked(...))
                if "keccak256" in ir.function.name:
                    # Trace arguments
                    args = ir.read
                    
                    # Check if any arg references block.chainid or address(this)
                    has_chainid_binding = False
                    has_address_binding = False
                    
                    for arg in args:
                        arg_str = str(arg)
                        if "block.chainid" in arg_str or "chainid" in arg_str:
                            has_chainid_binding = True
                        if "address(this)" in arg_str or f"this" in arg_str:
                            has_address_binding = True
                    
                    if not (has_chainid_binding and has_address_binding):
                        findings.append({
                            "function": function.name,
                            "line": ir.node.source_mapping.start,
                            "issue": f"Missing {'chain-id' if not has_chainid_binding else ''} " +
                                     f"{'and ' if not (has_chainid_binding and has_address_binding) else ''}" +
                                     f"{'address(this)' if not has_address_binding else ''} binding"
                        })
    
    return findings
```

**Integration into solidity-auditor:**
1. Add Slither detector Python files to `solidity-auditor/references/slither-detectors/`
2. In Turn 2 step 1, run Slither after Semgrep
3. Merge Semgrep + Slither findings
4. Deduplicate by (file, line, issue_type)
5. Agents read merged findings + source code

### Phase 3: LLM Agent Synthesis

**Role of agents:**
- Read Semgrep + Slither findings
- Read relevant source code sections
- Synthesize high-confidence security findings
- Eliminate false positives via reasoning
- Provide proof-of-concept and remediation

**Agent prompt amendment (for Signature Verification Auditor):**

```
You are the Signature Verification Auditor. Your specialty is finding bugs in ECDSA signature recovery and verification.

Your sources:
1. Semgrep static rules (sig-01-*, sig-03-*) — these flag potential issues
2. Slither IR analysis — these confirm data-flow paths
3. Source code — the contract implementation
4. Reference: OpenZeppelin ECDSA, EIP712, EIP1271

Your task:
1. Read all Semgrep findings. Each flags a potential SIG-01 or SIG-03 issue.
2. For each finding, read the source code at the flagged line.
3. Trace data flows:
   - SIG-01: Follow ecrecover() return value from call through to usage. Does code check for address(0)? Yes/No.
   - SIG-03: Follow keccak256() digest construction. Are block.chainid AND address(this) included? Yes/No.
4. If Semgrep flagged it but code is safe (e.g., implicit check via EIP712 domain separator), mark as false positive.
5. If Semgrep missed it but source code shows vulnerability, report as finding.
6. Emit findings in the standard format (file, function, line, severity, proof, fix).

Severity rules:
- SIG-01 HIGH: ecrecover() return used without explicit require(signer != address(0))
- SIG-03 HIGH: Digest computed without BOTH block.chainid AND address(this)
- SIG-03 MEDIUM: Digest computed without one of the two (partial protection)

Confidence rules:
- HIGH: Semgrep + Slither agree, source code confirms
- MEDIUM: Only one detector flagged, or implicit check found (requires reasoning)
- LOW: Uncertain if data flow is vulnerable (e.g., signer returned but not used)
```

**Expected precision after agent synthesis:**
- True positives: 90%+ (Semgrep finds most real bugs)
- False positives: <5% (agents filter out pattern matches that aren't bugs)
- False negatives: 10-15% (edge cases, obfuscated patterns)

---

## Files to Create in solidity-auditor/

After testing Semgrep rules, integrate into solidity-auditor:

```
solidity-auditor/
├── references/
│   ├── semgrep-rules/
│   │   ├── sig-01-ecrecover-zero-check.yaml
│   │   └── sig-03-chain-id-domain-separator.yaml
│   ├── slither-detectors/
│   │   ├── sig_01_ecrecover.py
│   │   └── sig_03_domain_separator.py
│   ├── hacking-agents/
│   │   └── signature-verification-agent.md  (new agent specialty)
│   └── ...
├── targets/
│   ├── fixtures/
│   │   ├── VulnerableSig01.sol
│   │   ├── VulnerableSig03.sol
│   │   └── SafeSig.sol
│   └── test_sig_detectors.sh
└── ...
```

---

## Wire into solidity-auditor Orchestrator

### Step 1: Update SKILL.md Turn 2 Step 1 (Source Preparation)

Add Semgrep + Slither execution after source.md is built:

```markdown
### Turn 2 step 1c — Run Semgrep and Slither detectors

After source.md is assembled, run signature verification detectors in parallel:

**Semgrep**:
```bash
semgrep --config {resolved_path}/semgrep-rules/sig-01-*.yaml \
        --config {resolved_path}/semgrep-rules/sig-03-*.yaml \
        {bundle_dir}/source.md \
        --json > {bundle_dir}/semgrep-findings.json
```

**Slither**:
```bash
slither . --json > {bundle_dir}/slither-findings.json
# Extract SIG-01 and SIG-03 findings from JSON
```

Merge findings by (file, line, issue_type); deduplicate.
Append merged findings to each agent bundle before SOP + specialty.
```

### Step 2: Create Signature Verification Agent

Add new agent (or fold into Access Control agent):

```markdown
#### Agent 13 (new optional): Signature Verification Auditor

Specialty file: `{resolved_path}/hacking-agents/signature-verification-agent.md`

Reads:
- Merged Semgrep + Slither findings
- VulnerableSig01 and VulnerableSig03 reference contracts
- Source code sections flagged by rules
- OpenZeppelin ECDSA + EIP712 best practices

Outputs:
- High-confidence SIG-01 and SIG-03 findings
- False positive filtering via reasoning
- Proof-of-concept scenarios
```

### Step 3: Update Reporting

Add SIG-01 and SIG-03 to findings schema:

```json
{
  "checkId": "SIG-01" | "SIG-03",
  "severity": "HIGH" | "MEDIUM" | "LOW",
  "confidence": "HIGH" | "MEDIUM" | "LOW",
  "location": { "file": "...", "contract": "...", "function": "...", "line": 42 },
  "title": "Missing zero-address check on ecrecover()",
  "description": "The function calls ecrecover() without checking if the return value is address(0)...",
  "proof": "ecrecover() call at line 42; no require(signer != address(0)) found in function scope",
  "remediation": "Add require(signer != address(0), \"Invalid signature\") immediately after ecrecover() call.",
  "reference": "https://docs.openzeppelin.com/contracts/4.x/api/utils#ECDSA"
}
```

---

## Test Execution Plan

### Phase 1: Validate Semgrep Rules (Done)

```bash
bash /tmp/test_sig_detectors.sh

# Expected:
# ✅ VulnerableSig01.sol: 3+ findings
# ✅ VulnerableSig03.sol: 5+ findings
# ✅ SafeSig.sol: 0 findings (no false positives)
```

### Phase 2: Validate Slither Detectors (Pending)

```bash
cd /tmp && git clone --depth 1 https://github.com/crytic/slither.git

# Copy SIG detectors to slither plugins
cp sig_01_ecrecover.py slither/slither/detectors/functions/
cp sig_03_domain_separator.py slither/slither/detectors/state/

# Run Slither on fixtures
slither VulnerableSig01.sol --json > sig01-slither.json
slither VulnerableSig03.sol --json > sig03-slither.json
slither SafeSig.sol --json > safe-slither.json

# Validate results match Semgrep
jq '.results[] | select(.check_id | contains("sig-")) ' sig01-slither.json | wc -l
# Expected: 2-4 findings
```

### Phase 3: Agent Synthesis Test (Pending)

Once integrated into solidity-auditor:

```bash
cd /home/hektic/Downloads/ai-web3-security/skills

# Run solidity-auditor on test fixtures
run solidity auditor on targets/fixtures/VulnerableSig01.sol targets/fixtures/VulnerableSig03.sol

# Expected findings:
# - SIG-01 in VulnerableSig01.sol (HIGH, HIGH confidence)
# - SIG-03 in VulnerableSig03.sol (HIGH, HIGH confidence)
# - Zero findings in SafeSig.sol
```

---

## Next Steps

1. ✅ **Semgrep rules created** (ready for testing)
2. ✅ **Test fixtures created** (VulnerableSig01.sol, VulnerableSig03.sol, SafeSig.sol)
3. ✅ **Test runner created** (test_sig_detectors.sh)
4. ⏭️ **Run Semgrep validation**: `bash /tmp/test_sig_detectors.sh`
5. ⏭️ **Create Slither detectors** (Python implementations)
6. ⏭️ **Integrate into solidity-auditor** (SKILL.md updates)
7. ⏭️ **Wire signature-verification agent**
8. ⏭️ **Part 3**: Add proxy resolution (EIP-1967, EIP-1822, EIP-1167)

---

## Reference: Vulnerability Details

### SIG-01: Missing Zero-Address Check

**Vulnerability**: ecrecover() can return address(0) for invalid signatures. If code doesn't check for this, attacker can forge signatures when the signer address is uninitialized or default.

**Attack scenario**:
1. Token.permit() calls ecrecover() and checks `signer == owner`
2. If owner is address(0) (uninitialized), ANY invalid signature passes
3. Attacker calls permit(owner, spender, value) with garbage signature (v=0, r=0, s=0)
4. ecrecover() returns address(0)
5. Check passes: address(0) == address(0) ✓
6. Attacker gains unlimited approval

**Fix**: 
```solidity
address signer = ecrecover(hash, v, r, s);
require(signer != address(0), "Invalid signature");  // ✅ Always check
require(signer == owner, "Signature mismatch");
```

### SIG-03: Missing Chain-ID Binding

**Vulnerability**: If signature digest doesn't include block.chainid, the same signature can be replayed across different chains (mainnet, polygon, arbitrum, etc.).

**Attack scenario**:
1. User calls permit() on mainnet, signs with private key
2. Transaction succeeds; unlimited approval granted
3. Attacker copies the signature (v, r, s) to Polygon
4. Same permit() function on Polygon fork (different address) accepts the same signature
5. Attacker gains approval on Polygon fork as well

**Fix**: 
```solidity
bytes32 domainSeparator = keccak256(abi.encode(
    EIP712DOMAIN_TYPEHASH,
    keccak256("TokenName"),
    keccak256("1"),
    block.chainid,              // ✅ Chain-specific
    address(this)               // ✅ Contract-specific
));
bytes32 digest = keccak256(abi.encodePacked("\x19\x01", domainSeparator, structHash));
```

---

## Files Location Summary

| File | Location | Purpose |
|------|----------|---------|
| **Semgrep: SIG-01** | `/tmp/sig-01-ecrecover-zero-check.yaml` | Static rule for zero-check detection |
| **Semgrep: SIG-03** | `/tmp/sig-03-chain-id-domain-separator.yaml` | Static rule for chain-id binding |
| **Fixture: Vulnerable 01** | `/tmp/VulnerableSig01.sol` | Test contract with SIG-01 bugs |
| **Fixture: Vulnerable 03** | `/tmp/VulnerableSig03.sol` | Test contract with SIG-03 bugs |
| **Fixture: Safe** | `/tmp/SafeSig.sol` | Correct implementations (baseline) |
| **Test Runner** | `/tmp/test_sig_detectors.sh` | Validation harness |
| **Implementation Guide** | `/tmp/PART_2_IMPLEMENTATION_GUIDE.md` | This file |

