from detectors.sig01_zero_check import Sig01ZeroCheckDetector
from detectors.sig11_uninitialized_signer import Sig11UninitializedSignerDetector

def make_plugin():
    return [Sig01ZeroCheckDetector, Sig11UninitializedSignerDetector], []
