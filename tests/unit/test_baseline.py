"""
Baseline environment test for SignChain package configuration.
"""
import signchain


def test_signchain_version():
    """Ensure signchain package version is defined."""
    assert signchain.__version__ == "0.1.0"
