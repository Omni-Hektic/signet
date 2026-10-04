"""
Slither Detector: SIG-01 Missing Zero-Address Check on ecrecover()

Detects: Missing require(signer != address(0)) after ecrecover() calls.

This detector extends Slither's built-in ecrecover detector to catch the common
pattern where ecrecover() return value is used without validating it's not address(0).

Usage:
  slither contract.sol --detect sig-01-ecrecover-zero-check
"""

from typing import List, Set
from slither.core.contract import Contract
from slither.core.function import Function
from slither.core.cfg.node import Node, NodeType
from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification
from slither.slithir.operations import Call, Condition
from slither.slithir.variables import TmpVariable, StateIRVariable
from slither.core.solidity_types import ElementaryType


class EcrecoverZeroCheck(AbstractDetector):
    """
    Detects ecrecover() calls without zero-address validation.

    SIG-01: Vulnerability when:
    1. Contract calls ecrecover(hash, v, r, s)
    2. Return value is stored in variable (signer)
    3. Variable is used in comparison (require/if) without checking != address(0)

    Safe patterns:
    - require(signer != address(0), "Invalid signature")
    - if (signer == address(0)) revert()
    - Any explicit address(0) check before use
    """

    ARGUMENT = "sig-01-ecrecover-zero-check"
    HELP = "ecrecover() return value not validated against address(0)"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.HIGH

    def _find_zero_check_in_function(self, function: Function, target_var) -> bool:
        """Check if target_var has an explicit zero-address check in the function."""

        zero_address_checks = []

        for node in function.nodes:
            for ir in node.irs:
                # Look for patterns that validate against zero
                # Pattern 1: require(var != 0) or require(var != address(0))
                if "require" in str(node):
                    node_str = str(node)
                    if target_var in node_str and ("!= 0" in node_str or "!= address(0)" in node_str):
                        zero_address_checks.append(node)

                # Pattern 2: if (var == address(0)) revert()
                if "if" in str(node) and target_var in str(node):
                    # Check if this is a zero check
                    if "== 0" in str(node) or "== address(0)" in str(node):
                        # Check if followed by revert
                        for successor in node.sons:
                            if "revert" in str(successor):
                                zero_address_checks.append(node)

        return len(zero_address_checks) > 0

    def _trace_variable_usage(self, function: Function, var, node_start: Node) -> List[Node]:
        """Trace where a variable is used after ecrecover() call."""
        uses = []

        for node in function.nodes:
            for ir in node.irs:
                # Check if this IR reads the variable
                if hasattr(ir, 'read') and ir.read:
                    for read_var in ir.read:
                        if read_var == var or str(read_var) == str(var):
                            uses.append(node)

        return uses

    def _check_ecrecover_call(self, node: Node, function: Function) -> bool:
        """
        Check if a node contains an ecrecover() call.
        Returns True if call is unsafe (no zero-check), False if safe.
        """

        for ir in node.irs:
            # Look for Call operations to ecrecover
            if isinstance(ir, Call):
                # Check if this is calling ecrecover
                if hasattr(ir, 'function') and ir.function and 'ecrecover' in str(ir.function).lower():
                    # Found ecrecover call
                    # Now check if return value is validated

                    # Get the return variable
                    if hasattr(ir, 'lvalue') and ir.lvalue:
                        return_var = ir.lvalue

                        # Check if there's a zero-address check for this variable
                        has_check = self._find_zero_check_in_function(function, return_var)

                        # If no explicit check found, flag as vulnerable
                        return not has_check

        return False

    def detect(self) -> List:
        """Main detection function."""
        results = []

        for contract in self.compilation_unit.contracts:
            for function in contract.functions_and_modifiers_declared:
                for node in function.nodes:
                    is_vulnerable = self._check_ecrecover_call(node, function)

                    if is_vulnerable:
                        # Generate finding
                        finding = {
                            'contract': contract.name,
                            'function': function.name,
                            'line': node.source_mapping.start,
                            'node': node,
                            'severity': 'HIGH',
                            'confidence': 'HIGH',
                            'message': f"SIG-01: ecrecover() return value in {function.name}() not validated against address(0)"
                        }
                        results.append(finding)

        return results
