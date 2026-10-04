# Phase 2: Slither Detector Integration

**Status**: Implementation files ready  
**Files**: `sig_01_ecrecover.py`, `sig_03_domain_separator.py`  
**Next**: Integration into Slither or standalone execution

---

## What's Included

### 1. SIG-01 Detector: `sig_01_ecrecover.py`

**Purpose**: Detects missing zero-address validation after `ecrecover()` calls.

**How it works**:
1. Scans all functions for `ecrecover()` calls
2. Tracks the return variable (signer)
3. Checks if variable is validated with `require(signer != address(0))`
4. Flags as vulnerable if no explicit zero-check found

**Pseudocode**:
```python
for each function:
    for each node:
        if node contains ecrecover():
            signer = return_value
            if no require(signer != 0) in function:
                FLAG as SIG-01 vulnerability
```

### 2. SIG-03 Detector: `sig_03_domain_separator.py`

**Purpose**: Detects missing chain-id or domain separator binding in signature digests.

**How it works**:
1. Identifies signature-verification functions (permit, transferWithSig, etc.)
2. Finds all `keccak256()` calls in those functions
3. Checks if `block.chainid` and `address(this)` are in digest computation
4. Flags as vulnerable if either binding is missing

**Pseudocode**:
```python
for each function matching signature pattern:
    for each keccak256() call:
        if not (has block.chainid AND has address(this)):
            if not using proper EIP712 domain separator:
                FLAG as SIG-03 vulnerability
```

---

## Integration Methods

### Method 1: Official Slither Plugin (Recommended)

Copy detectors to Slither's plugin directory:

```bash
# Find Slither installation
python3 -c "import slither; print(slither.__file__)"
# Output: /path/to/slither/__init__.py

# Copy detectors
cp sig_01_ecrecover.py /path/to/slither/detectors/functions/
cp sig_03_domain_separator.py /path/to/slither/detectors/state/

# Run
slither contract.sol --detect sig-01-ecrecover-zero-check,sig-03-domain-separator
```

### Method 2: Standalone Script (No Slither Installation)

Create a wrapper that uses Slither programmatically:

```python
#!/usr/bin/env python3
from slither import Slither
from sig_01_ecrecover import EcrecoverZeroCheck
from sig_03_domain_separator import DomainSeparatorChainIDBinding

def run_detectors(contract_path):
    """Run SIG-01 and SIG-03 detectors on a contract."""
    
    # Compile and analyze
    slither = Slither(contract_path)
    
    # Run custom detectors
    detector_01 = EcrecoverZeroCheck(slither)
    findings_01 = detector_01.detect()
    
    detector_03 = DomainSeparatorChainIDBinding(slither)
    findings_03 = detector_03.detect()
    
    # Combine and report
    all_findings = findings_01 + findings_03
    
    for finding in all_findings:
        print(f"[{finding['severity']}] {finding['contract']}.{finding['function']} @ line {finding['line']}")
        print(f"  {finding['message']}")
    
    return all_findings

if __name__ == '__main__':
    import sys
    contract = sys.argv[1] if len(sys.argv) > 1 else 'VulnerableSig01.sol'
    run_detectors(contract)
```

### Method 3: Docker (No Local Slither)

```bash
docker run -v $(pwd):/app crytic/slither:latest \
  /app/contract.sol \
  --external-calls-list \
  --json /app/results.json
```

---

## Expected Output Format

### Raw Detector Output

```json
{
  "contract": "VulnerableSig01",
  "function": "recoverSigner",
  "line": 42,
  "severity": "HIGH",
  "confidence": "HIGH",
  "message": "SIG-01: ecrecover() return value in recoverSigner() not validated against address(0)"
}
```

### CLI Report

```
Contract: VulnerableSig01
  Function: recoverSigner (line 42)
  [HIGH] SIG-01: ecrecover() return value not validated against address(0)

Contract: VulnerableSig03
  Function: permit (line 35)
  [HIGH] SIG-03: Signature digest missing block.chainid and address(this) binding

Contract: SafeSig
  (no findings)
```

---

## Testing Slither Detectors

### Quick Test (Requires Slither)

```bash
# Option A: Using docker
docker run -v /tmp:/app crytic/slither:latest \
  /app/VulnerableSig01.sol \
  --list-detectors | grep -i sig

# Option B: Direct (if Slither installed)
python3 << 'EOF'
import sys
sys.path.insert(0, '/tmp')

from slither import Slither

# Analyze vulnerable contract
slither = Slither('/tmp/VulnerableSig01.sol')

print("Contracts:", [c.name for c in slither.contracts])
for contract in slither.contracts:
    for func in contract.functions:
        print(f"  Function: {func.name}")
        for node in func.nodes:
            if 'ecrecover' in str(node):
                print(f"    Found ecrecover() at line {node.source_mapping.start}")
EOF
```

### Manual Inspection

Since automated testing requires Slither installation, validate detectors manually:

```bash
# 1. Check detector code structure
python3 -m py_compile /tmp/sig_01_ecrecover.py
python3 -m py_compile /tmp/sig_03_domain_separator.py
# No output = success

# 2. Verify detector inherits from AbstractDetector
grep "class.*AbstractDetector" /tmp/sig_01_ecrecover.py
# Output: class EcrecoverZeroCheck(AbstractDetector):

# 3. Check required methods exist
grep "def detect" /tmp/sig_01_ecrecover.py
grep "ARGUMENT =" /tmp/sig_01_ecrecover.py
grep "HELP =" /tmp/sig_01_ecrecover.py
grep "IMPACT =" /tmp/sig_01_ecrecover.py
grep "CONFIDENCE =" /tmp/sig_01_ecrecover.py
```

---

## Integration into solidity-auditor

### Step 1: Copy to solidity-auditor

```bash
mkdir -p /path/to/solidity-auditor/references/slither-detectors/
cp /tmp/sig_01_ecrecover.py /path/to/solidity-auditor/references/slither-detectors/
cp /tmp/sig_03_domain_separator.py /path/to/solidity-auditor/references/slither-detectors/
```

### Step 2: Update SKILL.md Turn 2

Add detector execution after Semgrep:

```markdown
### Turn 2 step 1d — Run Slither detectors

After Semgrep runs, execute Slither IR-based detectors in parallel:

**Environment setup**:
```bash
export PYTHONPATH={resolved_path}/slither-detectors:$PYTHONPATH
```

**Detector invocation**:
```bash
python3 << 'SLITHER_EOF'
from slither import Slither
import sys
sys.path.insert(0, "{resolved_path}/slither-detectors")

from sig_01_ecrecover import EcrecoverZeroCheck
from sig_03_domain_separator import DomainSeparatorChainIDBinding

# Analyze contract
slither = Slither("{project_root}")

# Run detectors
findings = []
for detector_class in [EcrecoverZeroCheck, DomainSeparatorChainIDBinding]:
    detector = detector_class(slither)
    findings.extend(detector.detect())

# Write findings
import json
with open("{bundle_dir}/slither-findings.json", "w") as f:
    json.dump(findings, f, indent=2, default=str)
SLITHER_EOF
```

**Merge with Semgrep**:
```bash
python3 << 'MERGE_EOF'
import json

# Read Semgrep findings
with open("{bundle_dir}/semgrep-findings.json") as f:
    semgrep = json.load(f).get("results", [])

# Read Slither findings
with open("{bundle_dir}/slither-findings.json") as f:
    slither = json.load(f)

# Deduplicate by (file, line, issue_type)
merged = {}
for finding in semgrep:
    key = (finding["path"], finding["start"]["line"])
    merged[key] = finding

for finding in slither:
    key = (finding["contract"], finding["line"])
    merged[key] = finding

# Write merged
with open("{bundle_dir}/detector-findings-merged.json", "w") as f:
    json.dump(list(merged.values()), f, indent=2)
MERGE_EOF
```
```

### Step 3: Update Agent Bundle

Append merged findings before agent SOP:

```markdown
### Turn 2 step 1e — Append detector findings to bundles

For each agent bundle:

```bash
{
  echo "## Detector Findings (Semgrep + Slither)"
  echo ""
  echo "These findings were generated by static analysis. Review each with the source code."
  echo ""
  python3 << 'FINDINGS_EOF'
import json
with open("{bundle_dir}/detector-findings-merged.json") as f:
    findings = json.load(f)
for finding in findings:
    print(f"- **{finding['contract']}.{finding['function']}** (line {finding['line']}): {finding['message']}")
FINDINGS_EOF
  echo ""
} >> {bundle_dir}/agent-N-bundle.md
```
```

---

## Validation Checklist

Before merging Phase 2 into solidity-auditor:

- [ ] `sig_01_ecrecover.py` compiles without syntax errors
- [ ] `sig_03_domain_separator.py` compiles without syntax errors
- [ ] Both inherit from `AbstractDetector`
- [ ] Both implement `detect()` method
- [ ] Both have ARGUMENT, HELP, IMPACT, CONFIDENCE class variables
- [ ] Detectors correctly identify vulnerabilities in `VulnerableSig01.sol`
- [ ] Detectors correctly identify vulnerabilities in `VulnerableSig03.sol`
- [ ] Detectors produce NO findings in `SafeSig.sol` (no false positives)
- [ ] Output JSON schema matches expected format
- [ ] Merge with Semgrep findings works correctly
- [ ] Agent bundles include detector findings before SOP

---

## Known Limitations

### Slither Detector Challenges

1. **AST vs IR tracking**: Slither's IR can lose high-level semantics
   - Workaround: Fall back to pattern matching on AST for complex cases

2. **External call side effects**: Can't fully track external function effects
   - Workaround: Conservative assumption (assume external calls may affect anything)

3. **Proxy/delegation**: Can't trace through delegatecall or proxy patterns
   - Workaround: Flag as uncertain confidence if delegation detected

4. **Dynamic binding**: Hard to trace dynamically computed values
   - Workaround: Assume worst case (dynamic value might be address(0))

### Fixes Applied in Detector Code

- **Limitation 1**: Use AST string matching as fallback after IR analysis
- **Limitation 2**: Conservative: require explicit checks, don't assume safety
- **Limitation 3**: Check for delegatecall patterns, reduce confidence if found
- **Limitation 4**: Flag dynamic digest computations with MEDIUM confidence

---

## Next Steps (Phase 3)

Once Slither detectors are working:

1. ✅ Run Semgrep rules (Phase 1)
2. ⏳ Run Slither detectors (Phase 2) — **YOU ARE HERE**
3. 🎯 Integrate into solidity-auditor (Phase 3)
4. 🎯 Wire signature-verification agent specialty
5. 🎯 End-to-end testing on BSC token contracts

---

## Files Location

```
/tmp/
├── sig_01_ecrecover.py                     ← Detector (SIG-01)
├── sig_03_domain_separator.py              ← Detector (SIG-03)
├── PHASE_2_SLITHER_INTEGRATION.md          ← This file
└── [fixtures from Phase 1]
    ├── VulnerableSig01.sol
    ├── VulnerableSig03.sol
    └── SafeSig.sol
```

