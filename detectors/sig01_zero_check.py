from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification
from slither.slithir.operations import SolidityCall, Binary, BinaryType, Assignment, TypeConversion

class Sig01ZeroCheckDetector(AbstractDetector):
    ARGUMENT = "sig-01-zero-check"
    HELP = "Detects ecrecover calls without explicit zero-address validation"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.HIGH
    WIKI = "https://github.com/crytic/slither/wiki"
    WIKI_TITLE = "Missing zero address check on ecrecover"
    WIKI_DESCRIPTION = "ecrecover returns address(0) on malformed signature."
    WIKI_EXPLOIT_SCENARIO = "Malformed signature returns address(0) and bypasses authorization."
    WIKI_RECOMMENDATION = "Check that recovered address is not address(0)."

    def _is_zero_operand(self, op, function):
        if hasattr(op, "value") and op.value == 0:
            return True
        if str(op) in ["0", "address(0)"]:
            return True
        for ir in function.slithir_operations:
            if isinstance(ir, TypeConversion) and ir.lvalue == op:
                if hasattr(ir.variable, "value") and ir.variable.value == 0:
                    return True
                if str(ir.variable) in ["0", "address(0)"]:
                    return True
        return False

    def _detect(self):
        results = []
        for contract in self.compilation_unit.contracts_derived:
            for function in contract.functions_and_modifiers_declared:
                has_unvalidated_recovery = False
                unvalidated_calls = []

                for node in function.nodes:
                    for ir in node.irs:
                        if isinstance(ir, SolidityCall) and ir.function.name.startswith("ecrecover("):
                            recovered_var = ir.lvalue
                            if not recovered_var:
                                continue

                            # Track aliases (e.g. recovered := TMP_0)
                            vars_to_track = {recovered_var}
                            for n in function.nodes:
                                for op in n.irs:
                                    if isinstance(op, Assignment) and op.rvalue in vars_to_track:
                                        vars_to_track.add(op.lvalue)

                            # Check if any tracked variable is compared to 0 / address(0) or msg.sender
                            validated = False
                            for n in function.nodes:
                                for op in n.irs:
                                    if isinstance(op, Binary) and op.type in [BinaryType.EQUAL, BinaryType.NOT_EQUAL]:
                                        has_tracked = any(v in op.read for v in vars_to_track)
                                        if has_tracked:
                                            other_ops = [v for v in op.read if v not in vars_to_track]
                                            for other in other_ops:
                                                if self._is_zero_operand(other, function) or str(other) == "msg.sender":
                                                    validated = True

                            if not validated:
                                has_unvalidated_recovery = True
                                unvalidated_calls.append(recovered_var)

                # Per-function deduplication: emit at most one finding per vulnerable function
                if has_unvalidated_recovery:
                    info = [
                        "Function '", function, "' in contract '", contract,
                        "' executes ecrecover without verifying != address(0)\n"
                    ]
                    results.append(self.generate_result(info))

        return results
