# BSC Signature Security Auditor (v1.0)

A specialized defensive static analysis pipeline designed to audit BNB Smart Chain (BSC) tokens ($\le \$1,000,000\text{ USD}$ market cap, $\ge \$5,000\text{ USD}$ liquidity) for cryptographic signature-verification flaws and replay vulnerabilities.

---

## 1. What This Tool Does

Audits BSC tokens for signature-verification weaknesses using a two-engine hierarchical verification model:

* **SIG-01 (Unchecked `ecrecover` Zero-Address Return)**:
  * **Engine**: Slither Intermediate Representation (Slither IR / SSA data-flow) — *Primary Detector*.
  * **Mechanism**: Verifies that the address returned by `ecrecover` is strictly validated against `address(0)` before authorization or state assignment, preventing signature forgery via malformed signatures ($v/r/s = 0$).
* **SIG-03 (Missing Chain-ID / Domain Separator Binding)**:
  * **Engine**: Semgrep — *Syntactic Pre-Filter*.
  * **Mechanism**: Flags digest calculations (`keccak256(abi.encodePacked(...))`) in signature verification entrypoints that omit `block.chainid`, `address(this)`, or an EIP-712 domain separator, exposing contracts to cross-chain and cross-contract signature replay attacks.
* **On-Chain Proxy Resolution**:
  * Resolves proxy contracts transparently via BSC RPC before fetching source code:
    * **EIP-1967**: Implementation slot (`0x360894...bbc`) and Beacon slot (`0xa3f0ad...d50`).
    * **EIP-1822**: Universal Upgradeable Proxy Standard (UUPS) slot (`0xc5f16f...cf7`).
    * **EIP-1167**: Minimal Clone Proxy bytecode matching prefix `0x363d3d373d3d3d363d73` and suffix `5af43d82803e903d91602b57fd5bf3`.
* **Source Retrieval & Toolchain Management**:
  * Fetches verified multi-file and standard JSON contract sources using the unified **Etherscan V2 API** (`chainid=56`) with automatic public fallback to Sourcify (confirmed exercised across all verified contracts during unauthenticated batch scanning).
  * Dynamically switches Solidity compilers matching contract metadata using `solc-select`.
* **Standardized Reporting & Programmatic Status Derivation**:
  * Emits machine-readable JSON finding logs and structured Markdown audit reports with programmatic `(status, action)` derivation (`CONFIRMED` / `DISCLOSE`, `FLAGGED` / `REVIEW`, `INFO` / `INFO_ONLY`, `UNVERIFIED` / `MANUAL_REVIEW`).

---

## 2. What This Tool Does Not Do

This tool is intentionally scoped for high-confidence signature verification auditing and does not attempt full general-purpose smart-contract formal verification.

| Gap | Impact |
| :--- | :--- |
| **SIG-03 Slither data-flow** | Misses non-standard function names and assembly-built digests |
| **SIG-11 uninitialized signer** | Does not detect constructor-set signers left at `address(0)` |
| **Assembly `ecrecover`** | `staticcall(gas(), 0x01, ...)` produces no finding |
| **Struct-field recovery** | Known false positive on `sigData.signer = ecrecover(...)` |
| **Pre-checked signer** | Known false positive on `require(expected != address(0)); ...` |
| **Non-standard permit names** | SIG-03 Semgrep regex misses `_transferWithSignature`, `spendWithSig`, etc. |

---

## 3. How to Run It

### Prerequisites & Setup

Ensure Python 3.10+, `slither-analyzer` 0.11.6+, `semgrep` 1.179.0+, and `solc-select` are installed in your environment:

```bash
# Clone and navigate to workspace
cd skills

# Create and activate virtual environment
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# Export required Etherscan V2 API key
export ETHERSCAN_KEY="your_etherscan_v2_api_key"
```

### Complete Discover → Fetch → Audit → Report Workflow

```bash
# 1. Discover micro-cap BSC tokens from DexScreener & GeckoTerminal
python3 discover_tokens.py

# 2. Audit a specific token address (handles proxy resolution, fetching, and multi-compiler analysis)
python3 fetch_and_audit.py --address 0x3efbfff95576e1d23cf6ead0acd2e73f4d6a7777 --apikey $ETHERSCAN_KEY --out findings.json

# 3. Generate structured Markdown audit report from JSON findings
python3 generate_report.py --input findings.json --out report.md

# 4. Run batch audit across 25 live tokens in queue
python3 batch_audit_part4.py 25 --output batch_audit_results_v3.csv
```

---

## 4. Known Limitations

Detailed architectural trade-offs, detector edge cases, and known limitations are cataloged in [`ARCHITECTURE.md`](ARCHITECTURE.md):

* **Slither Known False Positives (v1)**: Struct member assignment, pre-checked signer propagation, and state variable constructor initialization are documented in [`ARCHITECTURE.md#sig-01-slither--known-false-positives-v1`](ARCHITECTURE.md#sig-01-slither--known-false-positives-v1).
* **SafeOneLiner.sol Constructor Reclassification**: Invariant analysis on uninitialized signers versus zero-check false positives is detailed in [`ARCHITECTURE.md#safeonelinersol--reclassification-note`](ARCHITECTURE.md#safeonelinersol--reclassification-note).
* **Semgrep Metavariable Footguns**: Rules for explicit identifiers versus unconstrained metavariable wildcards in `pattern-not` are explained in [`ARCHITECTURE.md#semgrep-traps`](ARCHITECTURE.md#semgrep-traps).
* **Semgrep Known Blindspots & AST Limitations**: Inline reversed operands (`if (_from != ecrecover(...))`) and non-standard function selectors are analyzed in [`ARCHITECTURE.md#semgrep-known-blindspots--test-b-fix-part-4`](ARCHITECTURE.md#semgrep-known-blindspots--test-b-fix-part-4).
* **OpenZeppelin Error Tuple Suppression**: Resolution of library non-reverting return patterns (`tryRecover`) is documented in [`ARCHITECTURE.md#semgrep-false-positives-diagnosis--resolution-part-4`](ARCHITECTURE.md#semgrep-false-positives-diagnosis--resolution-part-4).

---

## Release: v1.0 Shipped

* **Primary Engine**: Slither SIG-01 (Validated on synthetic corpora, injected live source, and historical exploits, with 3 documented false-positive patterns on safe fixtures, cataloged in ARCHITECTURE.md).
* **Pre-Filter Engine**: Semgrep SIG-03 (yielding a 0.0% false-positive rate on the 25-token validation batch, see part4_report.md for methodology; verified recall on `TokenWhale.transferProxy`).
* **Proxy Resolution**: 100% accuracy on EIP-1967, EIP-1822, and EIP-1167.
* **Corpus Validation**: 25 live BSC tokens evaluated with 0 unhandled exceptions.
