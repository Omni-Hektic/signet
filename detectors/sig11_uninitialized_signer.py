from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification
from slither.slithir.operations import Binary, BinaryType, SolidityCall
from slither.core.variables.state_variable import StateVariable

class Sig11UninitializedSignerDetector(AbstractDetector):
    """RESEARCH ONLY — not reliable for disclosure."""
    ARGUMENT = "sig-11-uninitialized-signer"
    HELP = "Detects ecrecover output compared to state variables that may remain address(0) [RESEARCH ONLY]"
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/crytic/slither/wiki"
    WIKI_TITLE = "ecrecover compared to uninitialized signer"
    WIKI_DESCRIPTION = "ecrecover return is compared to a state variable that may be address(0)."
    WIKI_EXPLOIT_SCENARIO = "Malformed signature returns address(0) and bypasses authorization."
    WIKI_RECOMMENDATION = "Initialize the signer state variable or check != address(0)."

    def _is_written_in_ancestors(self, contract, var: StateVariable) -> bool:
        """Checks if variable is assigned in contract constructor or any inherited constructor."""
        if contract.constructor and var in contract.constructor.variables_written:
            return True

        for parent in contract.inheritance:
            if parent.constructor and var in parent.constructor.variables_written:
                return True
        return False

    def _is_written_in_initializers(self, contract, var: StateVariable) -> bool:
        """Checks if variable is assigned in initialize functions (proxy initializers)."""
        for fn in contract.functions_and_modifiers_declared:
            mod_names = [m.name.lower() for m in fn.modifiers]
            is_init_func = (
                "initialize" in fn.name.lower() or
                any("initializer" in m for m in mod_names)
            )
            if is_init_func and var in fn.variables_written:
                return True
        return False

    def _has_setter(self, contract, var: StateVariable) -> bool:
        """Checks if a setter exists that allows assigning the state variable post-deployment."""
        for fn in contract.functions_and_modifiers_declared:
            if fn.is_constructor:
                continue
            if var in fn.variables_written:
                return True
        return False

    def _detect(self):
        results = []
        for contract in self.compilation_unit.contracts_derived:
            address_state_vars = [
                v for v in contract.state_variables
                if str(v.type) == "address" and not v.is_constant and not getattr(v, "is_immutable", False)
            ]

            for s_var in address_state_vars:
                if s_var.expression is not None:
                    continue

                written_in_ctor = self._is_written_in_ancestors(contract, s_var)
                written_in_init = self._is_written_in_initializers(contract, s_var)

                if written_in_ctor or written_in_init:
                    continue

                has_setter = self._has_setter(contract, s_var)

                for function in contract.functions_and_modifiers_declared:
                    for node in function.nodes:
                        for ir in node.irs:
                            if isinstance(ir, Binary) and ir.type == BinaryType.EQUAL:
                                if s_var in ir.read:
                                    recovered_vars = [
                                        op.lvalue for n in function.nodes for op in n.irs
                                        if isinstance(op, SolidityCall) and op.function.name == "ecrecover"
                                    ]
                                    if any(r in ir.read for r in recovered_vars if r is not None):
                                        impact = DetectorClassification.MEDIUM if has_setter else DetectorClassification.HIGH
                                        desc = "has a post-deployment setter" if has_setter else "is NEVER initialized"
                                        info = [
                                            "ecrecover return in '", function,
                                            "' is compared against state variable '", s_var,
                                            "' which is uninitialized at deployment (", desc, ").\n"
                                        ]
                                        res = self.generate_result(info)
                                        res["impact"] = impact
                                        results.append(res)
        return results
