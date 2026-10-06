from setuptools import setup, find_packages

setup(
    name="bsc-sig-audit",
    version="0.1.0",
    packages=find_packages(),
    entry_points={
        "slither_analyzer.plugin": [
            "sig_audit = detectors.plugin:make_plugin"
        ]
    }
)
