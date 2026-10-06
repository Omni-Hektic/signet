
## Audit Engine Notes
SIG-03 Slither data-flow deferred to v2. v1 uses Semgrep heuristics only. False-positive rate unmeasured.


## SIG-01 Slither — Known False Positives (v1)

The following safe patterns trigger the detector. They are documented as
known limitations to be addressed in v2 with taint analysis.

1. Struct member assignment:
   sigData.signer = ecrecover(...); require(sigData.signer == trusted);
   Detector does not follow Index IR into struct members.
   Fixture: SafeStructField.sol

2. Pre-checked signer:
   require(expected != address(0)); recovered = ecrecover(...);
   require(recovered == expected);
   Detector does not propagate non-zero taint forward.
   Fixture: SafePreCheck.sol

3. State-variable comparison without local zero-check:
   require(ecrecover(...) == trusted);
   Detector does not verify that `trusted` is initialized to non-zero in
   the constructor.
   Fixture: SafeOneLiner.sol

For each finding on these patterns, report with `confidence: MEDIUM` and
the note: "may be a false positive if the comparison target is guaranteed
non-zero. Manual review required."

## SafeOneLiner.sol — Reclassification Note

SafeOneLiner.sol is classified as a SIG-01 false positive because, under the
invariant that trustedSigner is non-zero, the one-liner comparison is safe.

However, the constructor assigns trustedSigner = _signer without enforcing
require(_signer != address(0)). If deployed with _signer == address(0), the
contract is vulnerable to signature bypass.

When SIG-11 (uninitialized signer detection) is promoted from research-only
to active in v2, SafeOneLiner.sol should be reclassified as a SIG-11 finding,
not a SIG-01 false positive.

## Semgrep Traps

Bare metavariables in pattern-not match too broadly. Use explicit identifiers.

- BAD:  pattern-not: keccak256(abi.encodePacked(..., $DOMAIN_SEPARATOR, ...))
        $DOMAIN_SEPARATOR binds to the entire argument list, suppressing all matches.

- GOOD: pattern-not: keccak256(abi.encodePacked(..., _domainSeparator, ...))
        Explicit identifier names bind only when the exact name is present.

## Test Corpora

Two fixture directories serve different purposes:

- test_contracts/     — Unit fixtures. One feature per file. Expected counts are
                        minimal (1 or 0). Use for detector logic verification.
- targets/fixtures/   — Integration fixtures. Multiple features per file. Expected
                        counts are larger (3+). Use for realistic-contract testing.

Both corpora must pass before any detector is classified as validated.

## Semgrep False Positives: Diagnosis & Resolution (Part 4)

1. OpenZeppelin `tryRecover` tuple return on zero-address error (Resolved):
   ```solidity
   address signer = ecrecover(hash, v, r, s);
   if (signer == address(0)) {
       return (address(0), RecoverError.InvalidSignature);
   }
   ```
   Original rule `bsc-sig01-ecrecover-missing-zero-check` only excluded explicit reverts. Library routines return error tuples/enums rather than reverting, initially producing 14 candidate findings on EIP-1167 proxies.
   Resolution: Added `pattern-not-inside` and `pattern-not` clauses matching `if ($SIGNER == address(0)) { return ...; }` and `if ($SIGNER == address(0)) { ... }`.
   Post-fix FP count dropped from 14 to 0 across the entire 25-token batch.

## Semgrep Known Blindspots & Test B Fix (Part 4)

1. Function Selector Regex Exclusion (Resolved for `transferProxy`):
   ```solidity
   function transferProxy(address _from, address _to, ...) public returns (bool)
   ```
   Original SIG-03 rule checked `(?i)(permit|transferWithSig|...)`, missing historical contracts such as `TokenWhale`.
   Resolution: Added `transferProxy` to the alternation in `rules/semgrep.yaml`. Test B now produces 1 confirmed SIG-03 finding.

2. Reversed Operand Syntax in Inline Comparisons (Open limitation for Semgrep AST, covered by Slither):
   ```solidity
   if (_from != ecrecover(h, _v, _r, _s)) revert();
   ```
   Rule `bsc-sig01-ecrecover-missing-zero-check` matches patterns where `ecrecover` or its assigned variable is the left-hand operand. When the target is on the left and `ecrecover` on the right in an inline condition, AST pattern matching misses it. Slither's IR data-flow analysis handles operand commutativity natively and flags this pattern reliably.

