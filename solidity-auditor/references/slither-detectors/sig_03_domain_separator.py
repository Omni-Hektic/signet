#!/usr/bin/env python3
"""
SIG-03: Missing Chain-ID / Domain Separator Binding

Detects ecrecover-based signature verification that doesn't bind to chain-id,
preventing replay attacks across chains.
"""

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification
from slither.slithir.operations import SolidityCall, Assignment
from slither.slithir.variables import StateIRVariable, Constant
from typing import Any


class SIG03DomainSeparatorBinding(AbstractDetector):
    """
    Detects signature verification functions missing chain-id binding.

    Vulnerable pattern: Signature digest computed without including block.chainid
    or a domain separator that depends on chainid. This allows replay attacks across
    networks (mainnet → sidechain).

    Safe patterns:
    - Hash includes block.chainid
    - Hash includes state var initialized with block.chainid in constructor
    - Hash computed via external function that includes chainid
    """

    ARGUMENT = "sig-03-domain-separator-binding"
    HELP = "Missing chain-id binding in signature digest"
    WIKI_TITLE = "SIG-03: Missing chain-id or domain-separator binding"
    WIKI_DESCRIPTION = "Detects signature verification functions that compute digests without including block.chainid or an EIP-712 domain separator. This enables replay attacks across chains."
    WIKI_EXPLOIT_SCENARIO = "A signature valid on mainnet can be replayed on a sidechain (e.g., Polygon) if the digest doesn't include block.chainid. Attacker obtains a valid mainnet signature and replays it on a sidechain."
    WIKI_RECOMMENDATION = "Include block.chainid in the signature digest, or use an EIP-712 domain separator that is initialized with block.chainid in the constructor."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM

    def _detect(self):
        results = []
        findings_dedup = set()
        
        for contract in self.compilation_unit.contracts:
            for function in contract.functions_and_modifiers_declared:
                # Only check functions that look like sig verification
                if not self._is_sig_verification_function(function.name):
                    continue
                
                # Find ecrecover calls in this function
                for node in function.nodes:
                    for ir in node.irs:
                        if isinstance(ir, SolidityCall):
                            if ir.function.name == "ecrecover":
                                # Found ecrecover; check its first argument (the hash)
                                if ir.arguments and len(ir.arguments) > 0:
                                    hash_arg = ir.arguments[0]
                                    dedup_key = (contract.name, function.name, id(node))
                                    
                                    if dedup_key in findings_dedup:
                                        continue
                                    
                                    # Walk backwards to find the source of the hash
                                    has_chainid = self._hash_includes_chainid(
                                        function, hash_arg, contract
                                    )
                                    
                                    if not has_chainid:
                                        findings_dedup.add(dedup_key)
                                        results.append(self.generate_result(
                                            [node],
                                            f"Missing chain-id binding in signature digest ({function.name})",
                                            contract=contract
                                        ))
        
        return results
    
    def _is_sig_verification_function(self, func_name: str) -> bool:
        """Check if function name matches known sig verification patterns."""
        patterns = [
            "permit",
            "transferwithsig",
            "executebysg",
            "executemetaxaction",
            "recover",
            "isvalidsignature",
            "verifysig",
            "checkssig",
        ]
        return any(p in func_name.lower() for p in patterns)
    
    def _hash_includes_chainid(self, function, hash_var: Any, contract) -> bool:
        """
        Walk backwards from hash_var through function's IR to see if
        block.chainid or a domain separator variable appears in the data-flow.
        
        Returns True if chainid binding is detected.
        """
        # Collect all variables and expressions that feed into hash_var
        visited = set()
        to_explore = [hash_var]
        
        while to_explore:
            current = to_explore.pop(0)
            if id(current) in visited:
                continue
            visited.add(id(current))
            
            # Direct reference to block.chainid?
            if self._is_block_chainid(current):
                return True
            
            # Walk backwards through assignments in this function
            for node in function.nodes:
                for ir in node.irs:
                    if isinstance(ir, Assignment):
                        # If this assignment's lvalue matches current, explore its rvalue
                        if ir.lvalue == current:
                            rval = ir.rvalue
                            
                            # Check if rvalue is or contains block.chainid
                            if self._is_block_chainid(rval):
                                return True
                            
                            # Check if rvalue reads from domain separator variable
                            if isinstance(rval, StateIRVariable):
                                if self._is_domain_separator_var(rval.name):
                                    # Check if this var was initialized with chainid
                                    if self._domain_sep_has_chainid(rval, contract):
                                        return True
                            
                            # Queue rvalue for further exploration
                            to_explore.append(rval)
                    
                    # Also check SolidityCall returns
                    elif isinstance(ir, SolidityCall):
                        if ir.lvalue == current:
                            # Function call result — check if function references chainid
                            called_func = ir.function
                            if self._function_includes_chainid(called_func):
                                return True
        
        return False
    
    def _is_block_chainid(self, value: Any) -> bool:
        """Check if value is block.chainid."""
        if value is None:
            return False
        
        # Check string representation
        val_str = str(value).lower().strip()
        return "block.chainid" in val_str or "chainid" in val_str
    
    def _is_domain_separator_var(self, var_name: str) -> bool:
        """Check if variable name suggests domain separator."""
        var_lower = var_name.lower()
        patterns = [
            "domainseparator",
            "domain_separator",
            "_domainseparator",
            "_domain_separator",
            "domainsep",
            "domain_sep",
        ]
        return any(p in var_lower for p in patterns)
    
    def _domain_sep_has_chainid(self, state_var: StateIRVariable, contract) -> bool:
        """Check if a state variable is initialized with block.chainid in constructor."""
        for fn in contract.functions:
            if fn.name == "constructor":
                # Walk constructor's IR looking for assignment to state_var with chainid
                for node in fn.nodes:
                    for ir in node.irs:
                        if isinstance(ir, Assignment):
                            if ir.lvalue == state_var:
                                # Check if rvalue involves block.chainid
                                if self._is_block_chainid(ir.rvalue):
                                    return True
        
        return False
    
    def _function_includes_chainid(self, func) -> bool:
        """Check if a function's body references block.chainid."""
        if func is None:
            return False
        
        # Walk all nodes in function
        for node in func.nodes:
            for ir in node.irs:
                # Check all variables read by this IR
                for var in ir.read:
                    if self._is_block_chainid(var):
                        return True
        
        return False
