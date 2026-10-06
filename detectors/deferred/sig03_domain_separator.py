from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification
from slither.slithir.operations import SolidityCall

class Sig03DomainSeparatorDetector(AbstractDetector):
    ARGUMENT = "sig-03-domain-separator"
    HELP = "Detects ecrecover verification lacking block.chainid or domain separator binding"
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.HIGH
    WIKI = "https://github.com/crytic/slither/wiki"

    def _get_upstream_dependencies(self, root_var, function):
        """Walks backwards through ir.read to find all variables influencing root_var."""
        visited = set()
        queue = [root_var]
        dependencies = set()

        while queue:
            curr = queue.pop(0)
            if curr in visited:
                continue
            visited.add(curr)
            dependencies.add(str(curr).lower())

            for node in function.nodes:
                for ir in node.irs:
                    if hasattr(ir, "lvalue") and ir.lvalue == curr:
                        for r in ir.read:
                            if r not in visited:
                                queue.append(r)
        return dependencies

    def _detect(self):
        results = []
        for contract in self.compilation_unit.contracts_derived:
            for function in contract.functions_and_modifiers_declared:
                for node in function.nodes:
                    for ir in node.irs:
                        if isinstance(ir, SolidityCall) and ir.function.name == "ecrecover":
                            if not ir.arguments:
                                continue
                            digest_var = ir.arguments[0]
                            deps = self._get_upstream_dependencies(digest_var, function)

                            # Verify chain binding: chainid, address(this), or precalculated domain separator
                            has_chainid = any("chainid" in d for d in deps)
                            has_this = any("this" in d for d in deps)
                            has_domain_sep = any("domain" in d and "separator" in d for d in deps)

                            if not (has_domain_sep or (has_chainid and has_this)):
                                info = [
                                    "Digest '", digest_var, "' in function '", function,
                                    "' is verified via ecrecover without binding block.chainid or a domain separator\n"
                                ]
                                results.append(self.generate_result(info))
        return results
