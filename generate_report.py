#!/usr/bin/env python3
import json
import sys

REMEDIATION_MAP = {
    "SIG-01": (
        "Enforce explicit zero validation on the return value of ecrecover, "
        "or replace direct precompile invocation with OpenZeppelin's `ECDSA.recover`."
    ),
    "SIG-02": (
        "Implement a per-signer `mapping(address => uint256) public nonces` that increments on each "
        "executed signature to prevent replay attacks."
    ),
    "SIG-03": (
        "Adopt the EIP-712 standard and bind `block.chainid` and `address(this)` inside the domain separator "
        "to prevent cross-chain and cross-contract signature replays."
    ),
    "SIG-05": (
        "Add a `uint256 deadline` parameter to the signed struct and enforce "
        "`require(block.timestamp <= deadline, 'Expired signature');` before state changes."
    ),
    "SIG-11": (
        "Ensure the expected signer variable is immutable, declared with an initial non-zero constant, "
        "or enforce `require(expectedSigner != address(0))` prior to verifying equality with ecrecover."
    ),
    "UNVERIFIED_SOURCE": (
        "Contract bytecode was deployed without verified source code on BscScan. "
        "Direct interaction is high-risk until the team publishes and verifies contract source."
    )
}

VERIFY_STEPS = {
    "SIG-01": "Call the vulnerable function with v=0, r=bytes32(0), s=bytes32(0) and verify whether execution succeeds when targeting an address(0) state variable.",
    "SIG-02": "Submit the same signature payload twice in consecutive transactions and verify if the second execution succeeds instead of reverting.",
    "SIG-03": "Fork the BSC state to a local node with a different chain ID and verify if a signature generated for chain ID 56 executes successfully.",
    "SIG-05": "Generate a signature with a past timestamp or wait past deadline and verify if execution succeeds.",
    "SIG-11": "Inspect deployment storage layout. If signer slot contains 0x0, submit an invalid signature returning 0x0 to achieve authorization.",
    "UNVERIFIED_SOURCE": "Query BscScan API getsourcecode or inspect bytecode directly with a decompiler."
}

def generate_markdown(json_path: str, md_out_path: str):
    with open(json_path) as f:
        data = json.load(f)

    meta = data.get("auditMetadata", {})
    token = data.get("token", {})
    findings = data.get("findings", [])

    proxy_str = "No"
    if token.get("proxy", {}).get("isProxy"):
        proxy_str = f"Yes ({token.get('proxy', {}).get('type', 'Unknown')}) -> {token.get('proxy', {}).get('implementation', 'N/A')}"

    lines = [
        f"# Smart Contract Signature Security Audit",
        f"",
        f"- **Token Address**: `{token.get('address')}`",
        f"- **Source Hash**: `{token.get('sourceHash', 'N/A')}`",
        f"- **Proxy**: `{proxy_str}`",
        f"- **Scan Timestamp**: `{meta.get('scanTimestamp')}`",
        f"- **Analyzer Engine**: `{meta.get('analyzer')}`",
        f"",
        f"---",
        f"",
        f"## Summary of Findings",
        f"",
        f"| Check ID | Severity | Confidence | Action Required | Location |",
        f"| :--- | :--- | :--- | :--- | :--- |"
    ]

    if not findings:
        lines.append("| None | - | - | - | Clean analysis |")
    else:
        for f in findings:
            loc = f.get("location", {})
            loc_str = f"{loc.get('file', '')}:{loc.get('line', 0)}" if loc.get("file") else "N/A"
            lines.append(
                f"| **{f.get('checkId')}** | `{f.get('severity')}` | `{f.get('confidence')}` | **{f.get('action', 'LOG')}** | `{loc_str}` |"
            )

    lines.extend(["", "---", "", "## Detailed Vulnerability Analysis", ""])

    for idx, f in enumerate(findings, 1):
        cid = f.get("checkId", "")
        remediation = REMEDIATION_MAP.get(cid, "Review signature verification logic against OpenZeppelin standards.")
        verify = VERIFY_STEPS.get(cid, "Simulate execution with malformed signature parameters.")

        lines.extend([
            f"### {idx}. [{f.get('severity')}] {cid}: {f.get('title')}",
            f"",
            f"- **Action**: `{f.get('action', 'LOG')}`",
            f"- **Confidence**: `{f.get('confidence')}`",
            f"- **Location**: `{f.get('location', {}).get('file', 'N/A')}#L{f.get('location', {}).get('line', 0)}`",
            f"",
            f"#### Description",
            f"{f.get('description', f.get('title'))}",
            f"",
            f"#### Remediation Guidance",
            f"{remediation}",
            f"",
            f"#### How to Defensively Verify",
            f"`{verify}`",
            f"",
            f"---",
            f""
        ])

    with open(md_out_path, "w") as out:
        out.write("\n".join(lines))
    print(f"[+] Markdown report generated at: {md_out_path}")

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python3 generate_report.py <findings.json> <report.md>")
        sys.exit(1)
    generate_markdown(sys.argv[1], sys.argv[2])
