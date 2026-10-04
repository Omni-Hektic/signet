"""
Slither Detector: SIG-03 Missing Chain-ID / Domain Separator Binding

Detects: Missing block.chainid or address(this) in signature digest computations.

This detector identifies functions like permit(), transferWithSig(), executeMetaTransaction()
that compute keccak256 digests without including chain-id or contract address binding.

Vulnerability: Without these bindings, signatures can be replayed across different chains
or contract versions.

Usage:
  slither contract.sol --detect sig-03-domain-separator
"""

from typing import List, Set, Tuple
from slither.core.contract import Contract
from slither.core.function import Function
from slither.core.cfg.node import Node, NodeType
from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification
from slither.slithir.operations import Call, Phi
from slither.core.variables.variable import Variable
from slither.core.solidity_types import ElementaryType


class DomainSeparatorChainIDBinding(AbstractDetector):
    """
    Detects missing chain-id or domain separator binding in signature digests.

    SIG-03: Vulnerability when:
    1. Function is a signature-verification function (permit, transferWithSig, etc.)
    2. Function computes keccak256(abi.encodePacked(...) or abi.encode(...)
    3. Arguments to keccak256 do NOT include:
       - block.chainid, OR
       - address(this)

    Safe patterns:
    - Full EIP712 domain separator with block.chainid and address(this)
    - keccak256(abi.encodePacked(..., block.chainid, address(this), ...))
    - Calling _domainSeparator() or similar that includes both bindings

    Partially safe (still flagged):
    - Only block.chainid, no address(this)
    - Only address(this), no block.chainid
    """

    ARGUMENT = "sig-03-domain-separator"
    HELP = "Signature digest missing chain-id or domain-separator binding"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.HIGH

    # Functions that commonly compute and verify signatures
    SIGNATURE_FUNCTIONS = {
        "permit",
        "transferwithsig",
        "executemetatransaction",
        "executesbysig",
        "executebysig",
        "recover",
        "isvalidsignature",
        "isvalid",
        "verifysignature",
        "validate",
        "validatesignature",
    }

    def _is_signature_function(self, function: Function) -> bool:
        """Check if function name matches signature-verification pattern."""
        func_name = function.name.lower()

        # Direct match
        if func_name in self.SIGNATURE_FUNCTIONS:
            return True

        # Pattern match (contains "sig", "permit", "sign")
        keywords = ["sig", "permit", "sign", "recover", "verify"]
        return any(kw in func_name for kw in keywords)

    def _find_keccak256_calls(self, function: Function) -> List[Tuple[Node, str]]:
        """Find all keccak256 calls in function. Returns list of (node, arg_str)."""
        keccak_calls = []

        for node in function.nodes:
            # Check node expression for keccak256
            if hasattr(node, 'expression') and node.expression:
                expr_str = str(node.expression)
                if "keccak256" in expr_str:
                    keccak_calls.append((node, expr_str))

            # Check IR operations
            for ir in node.irs:
                ir_str = str(ir)
                if "keccak256" in ir_str:
                    keccak_calls.append((node, ir_str))

        return keccak_calls

    def _has_chainid_binding(self, arg_str: str) -> bool:
        """Check if argument string contains block.chainid reference."""
        keywords = ["block.chainid", "chainid", "chain_id"]
        return any(kw in arg_str for kw in keywords)

    def _has_address_binding(self, arg_str: str) -> bool:
        """Check if argument string contains address(this) reference."""
        keywords = ["address(this)", "this"]
        return any(kw in arg_str for kw in keywords)

    def _has_domain_separator(self, function: Function, node: Node) -> bool:
        """
        Check if function computes or uses a proper EIP712 domain separator.

        Safe patterns:
        - _domainSeparator()
        - _domainSeparatorV4()
        - DOMAIN_SEPARATOR
        - domainSeparator
        """
        func_str = " ".join(str(n) for n in function.nodes)

        domain_patterns = [
            "_domainseparator",
            "_domainseparatorv4",
            "domain_separator",
            "domainseparator",
            "eip712domain",
        ]

        return any(pat in func_str.lower() for pat in domain_patterns)

    def detect(self) -> List:
        """Main detection function."""
        results = []

        for contract in self.compilation_unit.contracts:
            for function in contract.functions_and_modifiers_declared:
                # Skip if not a signature-related function
                if not self._is_signature_function(function):
                    continue

                # Find all keccak256 calls in this function
                keccak_calls = self._find_keccak256_calls(function)

                for node, keccak_arg in keccak_calls:
                    has_chainid = self._has_chainid_binding(keccak_arg)
                    has_address = self._has_address_binding(keccak_arg)
                    has_domain = self._has_domain_separator(function, node)

                    # If neither binding present and no domain separator, it's vulnerable
                    if not has_domain and not (has_chainid and has_address):
                        severity = "HIGH"
                        confidence = "HIGH"

                        # Reduce confidence if one binding is present (might be intentional)
                        if has_chainid or has_address:
                            confidence = "MEDIUM"
                            severity = "MEDIUM"  # Partial protection still risky

                        missing = []
                        if not has_chainid:
                            missing.append("block.chainid")
                        if not has_address:
                            missing.append("address(this)")

                        finding = {
                            'contract': contract.name,
                            'function': function.name,
                            'line': node.source_mapping.start,
                            'node': node,
                            'severity': severity,
                            'confidence': confidence,
                            'message': f"SIG-03: Signature digest in {function.name}() missing {' and '.join(missing)} binding"
                        }
                        results.append(finding)

        return results
