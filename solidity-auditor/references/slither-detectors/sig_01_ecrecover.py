#!/usr/bin/env python3
"""
SIG-01: Missing Zero-Address Check on ecrecover() Result

Detects ecrecover() calls without explicit guard against address(0).
Walks CFG forward from each ecrecover to find Binary comparisons.
"""

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification
from slither.slithir.operations import SolidityCall, Binary, BinaryType
from slither.slithir.variables import Constant


class SIG01EcrecoverZeroCheck(AbstractDetector):
    """
    Detects missing zero-address check on ecrecover() results.

    Ecrecover returns address(0) for invalid signatures. Without explicit checking,
    this can bypass access controls.
    """

    ARGUMENT = "sig-01-ecrecover-zero-check"
    HELP = "Missing zero-address check on ecrecover() result"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.HIGH
    WIKI_TITLE = "SIG-01: Missing zero-address check on ecrecover result"
    WIKI_DESCRIPTION = "Detects ecrecover() calls without explicit guard against address(0), which is returned for invalid signatures."
    WIKI_EXPLOIT_SCENARIO = "An attacker provides an invalid signature (random v, r, s). ecrecover returns address(0). If the code doesn't check for this, the address(0) comparison may incorrectly pass or bypass access controls."
    WIKI_RECOMMENDATION = "Always validate that recovered address is not address(0) before using it. Example: require(recovered != address(0), 'Invalid signature');"

    def _detect(self):
        results = []
        findings_dedup = set()  # Dedup by node object id, not key tuple

        for contract in self.compilation_unit.contracts:
            # Only check functions declared in this contract (not inherited)
            for function in contract.functions_and_modifiers_declared:
                # Step 1: Find all ecrecover() calls
                ecrecover_calls = []  # List of (node, ir) for each ecrecover

                for node in function.nodes:
                    for ir in node.irs:
                        if isinstance(ir, SolidityCall):
                            if ir.function.name == "ecrecover":
                                if ir.lvalue:
                                    ecrecover_calls.append((node, ir))

                # Step 2: For each ecrecover, walk CFG to find zero-check
                for ecrecover_node, ecrecover_ir in ecrecover_calls:
                    recovered_var = ecrecover_ir.lvalue
                    node_id = id(ecrecover_node)

                    if node_id in findings_dedup:
                        continue

                    # Walk CFG from ecrecover onwards
                    has_zero_check = self._find_zero_check(function, recovered_var)

                    if not has_zero_check:
                        findings_dedup.add(node_id)
                        results.append(self.generate_result(
                            [ecrecover_node],
                            f"Missing zero-address check on ecrecover() result in {function.name}",
                            contract=contract
                        ))

        return results

    def _find_zero_check(self, function, recovered_var):
        """
        Walk the function's CFG, looking for Binary IR where:
        - The binary op involves recovered_var (ir.read contains it)
        - The op type is EQUAL or NOT_EQUAL
        - The comparison guards against address(0) or msg.sender
        """
        for node in function.nodes:
            for ir in node.irs:
                if not isinstance(ir, Binary):
                    continue

                # Check if recovered_var is read by this binary operation
                if recovered_var not in ir.read:
                    continue

                # Check for safe comparison patterns
                operands = ir.operands
                if len(operands) != 2:
                    continue

                left, right = operands
                op_type = ir.type

                # Pattern 1: recovered_var != address(0) or address(0) != recovered_var
                # This guards against zero
                if op_type in (BinaryType.NOT_EQUAL, BinaryType.DIFF):
                    if left == recovered_var and self._is_address_zero(right):
                        return True
                    if right == recovered_var and self._is_address_zero(left):
                        return True

                # Pattern 2: recovered_var == msg.sender or msg.sender == recovered_var
                # msg.sender is never address(0), so this is implicitly safe
                if op_type == BinaryType.EQUAL:
                    if left == recovered_var and self._is_msg_sender(right):
                        return True
                    if right == recovered_var and self._is_msg_sender(left):
                        return True

        return False

    def _is_address_zero(self, value):
        """Check if a value represents address(0) or 0."""
        if value is None:
            return False

        # Constant 0
        if isinstance(value, Constant):
            return value.value == 0

        # String representation check
        val_str = str(value).lower().strip()
        return val_str in ("0", "0x0", "0x00", "address(0)")

    def _is_msg_sender(self, value):
        """Check if a value is msg.sender."""
        if value is None:
            return False
        val_str = str(value).lower().strip()
        return val_str == "msg.sender"
