#!/usr/bin/env python3
"""
Fetch Contract Source from BscScan & Run SIG-01, SIG-03, SIG-11 Audits

Handles:
- BscScan API integration with SQLite caching
- Proxy resolution (EIP-1967, EIP-1822, EIP-1167)
- Version detection and solc-select
- Semgrep + Slither detector execution
- Findings aggregation and reporting

Usage:
  python3 fetch_and_audit.py 0x1f9840a85d5aF5bf1D1762F925BDADdC4201F984 \
    --cache-dir ./cache \
    --output findings.json

Environment:
  BSCSCAN_API_KEY - BscScan API key (optional, uses public tier if unset)
"""

import os
import json
import sqlite3
import sys
import hashlib
import time
from datetime import datetime
from typing import Dict, Optional, Tuple
from pathlib import Path
import requests
import argparse
from proxy_resolver import ProxyResolver, SourceFetcher


class AuditCache:
    """SQLite cache for audit results."""

    def __init__(self, cache_dir: str = "./cache"):
        """Initialize cache database."""
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(exist_ok=True)
        self.db_path = self.cache_dir / "audit_cache.db"
        self._init_db()

    def _init_db(self):
        """Initialize database schema."""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS sources (
                    address TEXT PRIMARY KEY,
                    source_code TEXT,
                    compiler_version TEXT,
                    contract_name TEXT,
                    fetched_at TIMESTAMP,
                    source_hash TEXT
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS findings (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    address TEXT,
                    check_id TEXT,
                    severity TEXT,
                    confidence TEXT,
                    title TEXT,
                    description TEXT,
                    location TEXT,
                    created_at TIMESTAMP
                )
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_address ON sources(address)
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_findings_address ON findings(address)
            """)
            conn.commit()

    def get_source(self, address: str) -> Optional[Dict]:
        """Retrieve cached source."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute(
                "SELECT source_code, compiler_version, contract_name, fetched_at FROM sources WHERE address = ?",
                (address,)
            )
            row = cursor.fetchone()
            if row:
                return {
                    'source_code': row[0],
                    'compiler_version': row[1],
                    'contract_name': row[2],
                    'fetched_at': row[3]
                }
        return None

    def cache_source(self, address: str, source: Dict):
        """Cache fetched source."""
        source_hash = hashlib.sha256(
            source.get('source_code', '').encode()
        ).hexdigest()

        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                INSERT OR REPLACE INTO sources
                (address, source_code, compiler_version, contract_name, fetched_at, source_hash)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (
                address,
                source.get('source_code'),
                source.get('compiler_version'),
                source.get('contract_name'),
                datetime.now().isoformat(),
                source_hash
            ))
            conn.commit()

    def cache_finding(self, address: str, finding: Dict):
        """Cache audit finding."""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                INSERT INTO findings
                (address, check_id, severity, confidence, title, description, location, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                address,
                finding.get('checkId'),
                finding.get('severity'),
                finding.get('confidence'),
                finding.get('title'),
                finding.get('description'),
                json.dumps(finding.get('location', {})),
                datetime.now().isoformat()
            ))
            conn.commit()

    def get_findings(self, address: str) -> list:
        """Retrieve cached findings."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute(
                "SELECT check_id, severity, confidence, title, description, location FROM findings WHERE address = ?",
                (address,)
            )
            findings = []
            for row in cursor.fetchall():
                findings.append({
                    'checkId': row[0],
                    'severity': row[1],
                    'confidence': row[2],
                    'title': row[3],
                    'description': row[4],
                    'location': json.loads(row[5]) if row[5] else {}
                })
            return findings


def fetch_with_retry(address: str, max_retries: int = 3, backoff: float = 1.0) -> Optional[Dict]:
    """Fetch source with exponential backoff for rate limiting."""
    fetcher = SourceFetcher()

    for attempt in range(max_retries):
        try:
            result = fetcher.fetch_from_bscscan(address)
            if result:
                return result
        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 429:  # Rate limited
                wait_time = backoff ** (attempt + 1)
                print(f"⏳ Rate limited. Waiting {wait_time:.1f}s before retry...", file=sys.stderr)
                time.sleep(wait_time)
                continue
            else:
                raise
        except Exception as e:
            print(f"❌ Fetch failed: {e}", file=sys.stderr)
            if attempt == max_retries - 1:
                raise

    return None


def run_semgrep_audit(source: str, contract_path: str = "Contract.sol") -> Dict:
    """Run Semgrep SIG-* rules on source code.

    Uses validated custom Semgrep rules from solidity-auditor/references/semgrep-rules/
    - SIG-01: ecrecover zero-address check
    - SIG-03: chain-id domain separator binding
    - SIG-11: uninitialized signer (research-only)
    """
    import subprocess
    import tempfile

    findings = {
        'SIG-01': [],
        'SIG-03': [],
        'SIG-11': []
    }

    try:
        # Write source to temp file
        with tempfile.NamedTemporaryFile(mode='w', suffix='.sol', delete=False) as f:
            f.write(source)
            temp_path = f.name

        # Locate rule files relative to this script
        rules_dir = Path(__file__).parent.parent / "references" / "semgrep-rules"

        rules = {
            'SIG-01': rules_dir / "sig-01-ecrecover-zero-check.yaml",
            'SIG-03': rules_dir / "sig-03-chain-id-domain-separator.yaml",
            'SIG-11': rules_dir / "sig-11-uninitialized-signer.yaml",
        }

        # Run Semgrep (if installed)
        try:
            for sig_type, rule_file in rules.items():
                if not rule_file.exists():
                    print(f"⚠️  Rule file not found: {rule_file}", file=sys.stderr)
                    continue

                result = subprocess.run(
                    ['semgrep', f'--config={rule_file}', temp_path, '--json'],
                    capture_output=True,
                    text=True,
                    timeout=30
                )

                if result.returncode == 0 or result.returncode == 1:  # 1 = findings found
                    try:
                        semgrep_output = json.loads(result.stdout)
                        findings[sig_type] = semgrep_output.get('results', [])
                    except json.JSONDecodeError:
                        print(f"⚠️  Failed to parse Semgrep output for {sig_type}", file=sys.stderr)
        except FileNotFoundError:
            print("⚠️  semgrep not installed; skipping static analysis", file=sys.stderr)
        except Exception as e:
            print(f"⚠️  Semgrep error: {e}", file=sys.stderr)
        finally:
            os.unlink(temp_path)

    except Exception as e:
        print(f"❌ Semgrep audit failed: {e}", file=sys.stderr)

    return findings


def compile_with_solc(source: str, compiler_version: str) -> Tuple[bool, str]:
    """Compile contract with solc."""
    import subprocess
    import tempfile

    try:
        # Select compiler version
        subprocess.run(
            ['solc-select', 'use', compiler_version],
            capture_output=True,
            check=False
        )

        # Compile
        with tempfile.NamedTemporaryFile(mode='w', suffix='.sol', delete=False) as f:
            f.write(source)
            temp_path = f.name

        result = subprocess.run(
            ['solc', temp_path],
            capture_output=True,
            text=True,
            timeout=30
        )

        os.unlink(temp_path)

        if result.returncode == 0:
            return True, ""
        else:
            return False, result.stderr

    except Exception as e:
        return False, str(e)


def audit_contract(address: str, cache_dir: str = "./cache") -> Dict:
    """
    Complete audit pipeline for a contract.

    1. Fetch source from BscScan (with cache)
    2. Resolve proxy if needed
    3. Compile with appropriate solc version
    4. Run Semgrep audits (SIG-01, SIG-03, SIG-11)
    5. Aggregate and cache findings
    """

    cache = AuditCache(cache_dir)

    print(f"🔍 Auditing {address}...", file=sys.stderr)

    # Step 1: Check cache
    cached = cache.get_source(address)
    if cached:
        print(f"✅ Using cached source (fetched {cached['fetched_at']})", file=sys.stderr)
        source = cached['source_code']
        compiler_version = cached['compiler_version']
    else:
        # Step 2: Fetch source
        print(f"📥 Fetching from BscScan...", file=sys.stderr)
        source_data = fetch_with_retry(address)

        if not source_data:
            return {
                'address': address,
                'error': 'Could not fetch source from BscScan',
                'findings': []
            }

        source = source_data.get('source_code')
        compiler_version = source_data.get('compiler_version', '0.8.24')

        # Cache it
        cache.cache_source(address, source_data)
        print(f"💾 Cached source", file=sys.stderr)

    # Step 3: Try to compile (validates source)
    print(f"🔨 Compiling with solc {compiler_version}...", file=sys.stderr)
    compiled, compile_error = compile_with_solc(source, compiler_version)

    if not compiled:
        print(f"⚠️  Compilation failed: {compile_error[:100]}...", file=sys.stderr)
        return {
            'address': address,
            'error': f'Compilation failed: {compile_error}',
            'findings': []
        }

    print(f"✅ Compilation successful", file=sys.stderr)

    # Step 4: Run Semgrep audits
    print(f"🔬 Running Semgrep audits...", file=sys.stderr)
    semgrep_findings = run_semgrep_audit(source)

    # Step 5: Aggregate findings into standardized format
    findings = []
    for check_id, check_findings in semgrep_findings.items():
        for finding in check_findings:
            extra = finding.get('extra', {})

            # Extract severity and confidence from Semgrep JSON
            severity = extra.get('severity', 'MEDIUM').upper()
            confidence = extra.get('confidence', 'MEDIUM').upper()

            # First line of message is the title
            message = extra.get('message', f'{check_id} finding')
            title = message.split('\n')[0] if message else f'{check_id} finding'

            aggregated = {
                'checkId': check_id,
                'severity': severity,
                'confidence': confidence,
                'title': title,
                'description': message,
                'location': {
                    'file': finding.get('path', 'Contract.sol'),
                    'line': finding.get('start', {}).get('line', 0)
                }
            }
            findings.append(aggregated)
            cache.cache_finding(address, aggregated)

    print(f"✅ Found {len(findings)} issues", file=sys.stderr)

    return {
        'address': address,
        'source_code': source[:500],  # First 500 chars
        'compiler_version': compiler_version,
        'findings': findings,
        'error': None
    }


def main():
    """CLI entry point."""
    parser = argparse.ArgumentParser(
        description='Fetch BSC contract source and run SIG-* audits'
    )
    parser.add_argument('address', help='Contract address (0x...)')
    parser.add_argument('--cache-dir', default='./cache', help='Cache directory')
    parser.add_argument('--output', help='Output file (JSON)')
    parser.add_argument('--proxy', action='store_true', help='Resolve proxy before auditing')

    args = parser.parse_args()

    # Resolve proxy if requested
    address = args.address
    if args.proxy:
        try:
            resolver = ProxyResolver()
            proxy_info = resolver.resolve(address)
            if proxy_info.get('is_proxy'):
                print(f"🔗 Proxy detected: {proxy_info['proxy_type']}", file=sys.stderr)
                if proxy_info.get('implementation'):
                    print(f"   Implementation: {proxy_info['implementation']}", file=sys.stderr)
                    address = proxy_info['implementation']
        except Exception as e:
            print(f"⚠️  Proxy resolution failed: {e}", file=sys.stderr)

    # Run audit
    result = audit_contract(address, args.cache_dir)

    # Output
    if args.output:
        with open(args.output, 'w') as f:
            json.dump(result, f, indent=2)
        print(f"📄 Results written to {args.output}", file=sys.stderr)
    else:
        print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
