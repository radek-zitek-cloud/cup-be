from app import __version__
import re

def test_version():
    """
    Test that the version string is present and formatted correctly (SemVer).
    """
    assert isinstance(__version__, str)
    # Simple SemVer regex (Major.Minor.Patch)
    pattern = r'^\d+\.\d+\.\d+$' 
    assert re.match(pattern, __version__)
