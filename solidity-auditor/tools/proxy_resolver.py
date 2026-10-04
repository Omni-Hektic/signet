#!/usr/bin/env python3
"""
Proxy Resolver: Detect and resolve proxy contracts to their implementation.

Supports:
- EIP-1967: Standard proxy pattern (implementation slot 0x360894a...)
- EIP-1822 UUPS: Universal upgradeable proxy (proxiable slot)
- EIP-1167: Minimal clone (fixed bytecode prefix)

Usage:
  resolver = ProxyResolver(w3)
  result = resolver.resolve(contract_address)
  if result['is_proxy']:
      print(f"Proxy -> {result['implementation']}")
"""

import os
import re
from typing import Dict, Optional, Tuple
from web3 import Web3
from web3.contract import Contract
from eth_utils import to_checksum_address, is_address


class ProxyResolver:
    """Resolves proxy contracts to their implementations."""

    # EIP-1967 standard slots
    EIP1967_IMPLEMENTATION_SLOT = "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc"
    EIP1967_BEACON_SLOT = "0xa3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50"

    # EIP-1822 UUPS slot (keccak256("PROXIABLE"))
    EIP1822_PROXIABLE_SLOT = "0xc5f16f0fcc639fa48a6947836d9850f504798523bf8c9a3a87d5876cf622bcf7"

    # EIP-1167 minimal clone bytecode prefix (3d3d3d3d363d3d37363d73 or 363d3d373d3d3d363d73)
    EIP1167_PREFIXES = [
        "363d3d373d3d3d363d73",  # First variant
        "3d3d3d3d363d3d37363d73",  # Second variant (with extra 3d)
    ]

    def __init__(self, provider_url: Optional[str] = None):
        """Initialize proxy resolver with Web3 provider."""
        if provider_url:
            self.w3 = Web3(Web3.HTTPProvider(provider_url))
        else:
            # Try BSC public RPC
            self.w3 = Web3(Web3.HTTPProvider("https://bsc-dataseed.binance.org"))

        if not self.w3.is_connected():
            raise ConnectionError("Could not connect to Web3 provider")

    def resolve(self, address: str) -> Dict:
        """
        Resolve a contract address to proxy/implementation details.

        Returns:
            {
                'address': '0x...',
                'is_proxy': bool,
                'proxy_type': 'EIP-1967' | 'EIP-1822' | 'EIP-1167' | None,
                'implementation': '0x...' | None,
                'beacon': '0x...' | None,
                'error': str | None
            }
        """
        try:
            address = to_checksum_address(address)
        except Exception as e:
            return {
                'address': address,
                'is_proxy': False,
                'proxy_type': None,
                'implementation': None,
                'beacon': None,
                'error': f"Invalid address: {e}"
            }

        result = {
            'address': address,
            'is_proxy': False,
            'proxy_type': None,
            'implementation': None,
            'beacon': None,
            'error': None
        }

        # Try EIP-1967 first (most common)
        impl = self._check_eip1967_implementation(address)
        if impl:
            result['is_proxy'] = True
            result['proxy_type'] = 'EIP-1967'
            result['implementation'] = impl
            return result

        # Try EIP-1967 beacon
        beacon = self._check_eip1967_beacon(address)
        if beacon:
            # Resolve beacon to get implementation
            beacon_impl = self._get_beacon_implementation(beacon)
            if beacon_impl:
                result['is_proxy'] = True
                result['proxy_type'] = 'EIP-1967-Beacon'
                result['beacon'] = beacon
                result['implementation'] = beacon_impl
                return result

        # Try EIP-1822 UUPS
        impl = self._check_eip1822_uups(address)
        if impl:
            result['is_proxy'] = True
            result['proxy_type'] = 'EIP-1822-UUPS'
            result['implementation'] = impl
            return result

        # Try EIP-1167 minimal clone
        impl = self._check_eip1167_clone(address)
        if impl:
            result['is_proxy'] = True
            result['proxy_type'] = 'EIP-1167-Clone'
            result['implementation'] = impl
            return result

        return result

    def _check_eip1967_implementation(self, address: str) -> Optional[str]:
        """Check EIP-1967 implementation slot."""
        try:
            value = self.w3.eth.get_storage_at(
                address,
                self.EIP1967_IMPLEMENTATION_SLOT
            )

            # Extract address from storage (last 20 bytes)
            impl = "0x" + value.hex()[-40:]

            if impl != "0x" + "0" * 40:  # Non-zero
                return to_checksum_address(impl)
        except Exception:
            pass

        return None

    def _check_eip1967_beacon(self, address: str) -> Optional[str]:
        """Check EIP-1967 beacon slot."""
        try:
            value = self.w3.eth.get_storage_at(
                address,
                self.EIP1967_BEACON_SLOT
            )

            # Extract address
            beacon = "0x" + value.hex()[-40:]

            if beacon != "0x" + "0" * 40:
                return to_checksum_address(beacon)
        except Exception:
            pass

        return None

    def _get_beacon_implementation(self, beacon: str) -> Optional[str]:
        """Get implementation from beacon contract."""
        try:
            # Standard beacon has implementation() view function
            # Try common ABI
            code = self.w3.eth.get_code(beacon)

            if not code or code == "0x":
                return None

            # Try calling implementation() if it's a contract
            # This is a simple heuristic - proper implementation needs ABI
            return None
        except Exception:
            pass

        return None

    def _check_eip1822_uups(self, address: str) -> Optional[str]:
        """Check EIP-1822 UUPS proxiable slot."""
        try:
            value = self.w3.eth.get_storage_at(
                address,
                self.EIP1822_PROXIABLE_SLOT
            )

            # Extract address
            impl = "0x" + value.hex()[-40:]

            if impl != "0x" + "0" * 40:
                return to_checksum_address(impl)
        except Exception:
            pass

        return None

    def _check_eip1167_clone(self, address: str) -> Optional[str]:
        """Check if contract is EIP-1167 minimal clone."""
        try:
            code = self.w3.eth.get_code(address)

            if not code or len(code) < 55:  # Too short for clone
                return None

            code_hex = code.hex()

            # Check for minimal clone prefix
            for prefix in self.EIP1167_PREFIXES:
                if code_hex.startswith(prefix):
                    # Extract implementation address (follows prefix)
                    # Minimal clone format: prefix + address (20 bytes = 40 hex chars)
                    impl_hex = code_hex[len(prefix):len(prefix) + 40]

                    if impl_hex and len(impl_hex) == 40:
                        impl = "0x" + impl_hex

                        # Validate it looks like an address
                        if is_address(impl) and impl != "0x" + "0" * 40:
                            return to_checksum_address(impl)
        except Exception:
            pass

        return None

    def resolve_batch(self, addresses: list) -> list:
        """Resolve multiple addresses in batch."""
        results = []
        for address in addresses:
            results.append(self.resolve(address))
        return results


class SourceFetcher:
    """Fetches contract source from blockchain data providers."""

    def __init__(self, bscscan_key: Optional[str] = None):
        """Initialize source fetcher with BscScan API key."""
        self.bscscan_key = bscscan_key or os.getenv("BSCSCAN_API_KEY", "")
        self.bscscan_url = "https://api.bscscan.com/api"

    def fetch_from_bscscan(self, address: str) -> Optional[Dict]:
        """
        Fetch contract source from BscScan.

        Returns:
            {
                'address': '0x...',
                'source_code': '...',
                'compiler_version': '...',
                'contract_name': '...',
                'is_proxy': bool,
                'implementation': '0x...' | None
            }
        """
        import requests

        try:
            address = to_checksum_address(address)
        except:
            return None

        params = {
            "module": "contract",
            "action": "getsourcecode",
            "address": address,
            "apikey": self.bscscan_key if self.bscscan_key else ""
        }

        try:
            response = requests.get(self.bscscan_url, params=params, timeout=10)
            response.raise_for_status()
            data = response.json()

            if data.get("status") != "1" or not data.get("result"):
                return None

            result_item = data["result"][0]

            # Handle double-braced Standard-Json-Input quirk
            source_code = result_item.get("SourceCode", "")
            if source_code.startswith("{{") and source_code.endswith("}}"):
                source_code = source_code[1:-1]

            return {
                'address': address,
                'source_code': source_code,
                'compiler_version': result_item.get("CompilerVersion", ""),
                'contract_name': result_item.get("ContractName", ""),
                'is_proxy': result_item.get("Proxy") == "1",
                'implementation': result_item.get("Implementation") or None
            }

        except Exception as e:
            return None

    def fetch_with_proxy_resolution(self, address: str, provider_url: Optional[str] = None) -> Dict:
        """
        Fetch source and resolve proxy to implementation if needed.

        Returns:
            {
                'address': '0x...',
                'source_code': '...',
                'proxy_info': {...},
                'implementation_source': {...}
            }
        """
        # Fetch initial source
        source = self.fetch_from_bscscan(address)

        result = {
            'address': address,
            'source_code': source.get('source_code') if source else None,
            'proxy_info': None,
            'implementation_source': None
        }

        # Try to resolve proxy
        try:
            resolver = ProxyResolver(provider_url)
            proxy_info = resolver.resolve(address)
            result['proxy_info'] = proxy_info

            # If proxy detected, fetch implementation source
            if proxy_info.get('is_proxy') and proxy_info.get('implementation'):
                impl_source = self.fetch_from_bscscan(proxy_info['implementation'])
                result['implementation_source'] = impl_source
        except Exception:
            pass

        return result


if __name__ == "__main__":
    import json
    import sys

    if len(sys.argv) < 2:
        print("Usage: python3 proxy_resolver.py <address> [<address2> ...]")
        sys.exit(1)

    resolver = ProxyResolver()

    for address in sys.argv[1:]:
        result = resolver.resolve(address)
        print(json.dumps(result, indent=2))
        print()
