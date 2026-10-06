#!/usr/bin/env python3
import json
import subprocess
import sys
import os
import shutil

TEST_DIR = "test_contracts"

def run_semgrep():
    if not shutil.which("semgrep"):
        print("[-] semgrep not found in PATH. Skipping semgrep test.")
        return None

    print("[*] Running Semgrep on test suite...")
    cmd = ["semgrep", "--config", "rules/semgrep.yaml", TEST_DIR, "--json"]
    proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
    try:
        return json.loads(proc.stdout).get("results", [])
    except Exception as e:
        print(f"[!] Semgrep execution output parse error: {e}")
        return []

def run_slither():
    if not shutil.which("slither"):
        print("[-] slither not found in PATH. Skipping slither test.")
        return None

    print("[*] Running Slither custom detectors on test suite...")
    cmd = [
        "slither", TEST_DIR,
        "--detect", "sig-01-zero-check,sig-03-domain-separator",
        "--json", "test_slither_out.json"
    ]
    subprocess.run(cmd, capture_output=True, check=False)
    if os.path.exists("test_slither_out.json"):
        with open("test_slither_out.json") as f:
            try:
                data = json.load(f)
                return data.get("results", {}).get("detectors", [])
            except Exception:
                return []
    return []

def main():
    semgrep_hits = run_semgrep()
    slither_hits = run_slither()

    if semgrep_hits is None and slither_hits is None:
        print("[!] Neither semgrep nor slither found in PATH.")
        print("    Install them with: pip install semgrep slither-analyzer")
        sys.exit(1)

    findings = {"VulnerableSig01.sol": [], "VulnerableSig03.sol": [], "SafeSig.sol": []}

    if semgrep_hits:
        for hit in semgrep_hits:
            filename = os.path.basename(hit["path"])
            if filename in findings:
                findings[filename].append(f"Semgrep:{hit['check_id']}")

    if slither_hits:
        for hit in slither_hits:
            for elem in hit.get("elements", []):
                fname = os.path.basename(elem.get("source_mapping", {}).get("filename_relative", ""))
                if fname in findings:
                    findings[fname].append(f"Slither:{hit['check']}")

    print("\n=== Test Results Summary ===")
    success = True

    # 1. VulnerableSig01 must flag SIG-01
    v01_checks = findings["VulnerableSig01.sol"]
    if any("sig01" in c or "sig-01" in c for c in v01_checks):
        print("  [PASS] VulnerableSig01.sol correctly triggered SIG-01")
    else:
        print("  [FAIL] VulnerableSig01.sol did NOT trigger SIG-01")
        success = False

    # 2. VulnerableSig03 must flag SIG-03
    v03_checks = findings["VulnerableSig03.sol"]
    if any("sig03" in c or "sig-03" in c for c in v03_checks):
        print("  [PASS] VulnerableSig03.sol correctly triggered SIG-03")
    else:
        print("  [FAIL] VulnerableSig03.sol did NOT trigger SIG-03")
        success = False

    # 3. SafeSig must produce ZERO findings
    safe_checks = set(findings["SafeSig.sol"])
    if len(safe_checks) == 0:
        print("  [PASS] SafeSig.sol produced 0 findings (No False Positives)")
    else:
        print(f"  [FAIL] SafeSig.sol produced false positives: {safe_checks}")
        success = False

    sys.exit(0 if success else 1)

if __name__ == "__main__":
    main()
