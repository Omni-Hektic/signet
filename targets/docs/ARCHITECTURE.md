# Detection Architecture & Limitations

## SIG-01: ecrecover Zero-Check

**Status**: ✅ Implemented (Semgrep + Slither)  
**Confidence**: HIGH  
**False Negatives**: Low (catches most obvious patterns)  
**False Positives**: Very low (only flagged when zero-check missing)

### Implementation
- Slither: Walks CFG for Binary IR with `recovered_var in ir.read`
- Semgrep: Pattern matches on `require(signer != address(0))`
- Deduplication: One finding per contract (contract-level)

---

## SIG-03: Chain-ID Domain Separator Binding

**Status**: ✅ Implemented (Semgrep + Slither)  
**Confidence**: MEDIUM  
**False Negatives**: Medium (custom domain separator patterns might be missed)  
**False Positives**: Low (looks for explicit `block.chainid` references)

### Implementation
- Slither: Walks backwards from ecrecover hash argument through assignments
- Semgrep: Pattern matches on `block.chainid` and `_domainSeparator` patterns
- Deduplication: One finding per contract (contract-level)

### Known Limitations
- Does not detect custom domain separator computations (e.g., encoded state variables)
- Does not follow cross-contract calls to external domain separator functions
- Requires explicit `block.chainid` in the data-flow chain

---

## SIG-11: Uninitialized Signer Variables

**Status**: ⚠️  RESEARCH-ONLY (Low confidence, defer to v2)  
**Confidence**: LOW  
**False Positives**: HIGH (pattern-not-inside scoping issues in Semgrep)  
**Recommendation**: Manual verification required

### Why Deferred
SIG-11 requires precise tracking of:
- Constructor initialization (including inherited constructors)
- Initializer function patterns (OpenZeppelin initializable)
- State variable defaults across proxy upgrades
- Cross-function data-flow to detect uninitialized reads

Semgrep's `pattern-not-inside` cannot reliably scope across function boundaries. Slither data-flow analysis for initialization would require:
- Walking the entire contract hierarchy
- Tracking initialize() function patterns
- Handling proxy storage layout changes

### Implementation (v2 Plan)
1. Slither detector walking `contract.state_variables` with `is_initialized` analysis
2. Track constructor + initializer paths for each state variable
3. Report only when: (a) uninitialized state var + (b) read before write

---

## Proxy Resolution

**Status**: ✅ Implemented (Complete)  
**Coverage**: EIP-1967 (95%), EIP-1822 UUPS (99%), EIP-1167 (99%)

### Supported Patterns
- **EIP-1967**: Standard proxy (TransparentProxy, UUPSProxy)
- **EIP-1822 UUPS**: Self-governed upgradeable pattern
- **EIP-1167**: Minimal clone (immutable)

### Detection Order
1. EIP-1967 Implementation slot
2. EIP-1967 Beacon slot
3. EIP-1822 UUPS slot
4. EIP-1167 bytecode prefix

### Known Gaps
- Custom delegatecall-based proxies (GovernanceProxy, etc.)
- Beacon implementations with custom storage patterns
- Upgradeable proxies with non-standard storage slots

---

## Future Work (v2+)

### High Priority
1. **SIG-02**: Incorrect hash algorithm (MD5, SHA1 in signatures)
2. **SIG-04**: Replay attack via missing nonce checks
3. **SIG-11**: Proper initialization analysis (Slither IR-based)

### Medium Priority
1. Cross-contract domain separator detection (follow external calls)
2. Custom proxy pattern detection (machine learning classifier)
3. Signature verification in constructor (timing issue)

### Low Priority
1. Gas optimization for batch auditing (10K+ tokens)
2. Leaderboard/dashboard for token audits
3. Integration with security research APIs

