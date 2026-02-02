"""
Test error handling when hcatPath is misconfigured.
"""
import os
import sys
import tempfile
import json


def test_ensure_binary_error_message(monkeypatch, capsys):
    """Test that ensure_binary provides helpful error when build_dir doesn't exist."""
    # Import the function
    from hate_crack.main import ensure_binary
    
    # Test with non-existent build directory
    fake_binary = "/nonexistent/path/to/binary"
    fake_build_dir = "/opt/hate_crack/hashcat-utils"  # Simulate missing assets
    
    # Expect SystemExit when binary and build dir don't exist
    try:
        ensure_binary(fake_binary, build_dir=fake_build_dir, name="expander")
        assert False, "Should have exited with error"
    except SystemExit as e:
        assert e.code == 1
    
    # Check that the error message mentions the correct issue
    captured = capsys.readouterr()
    assert "Build directory" in captured.out or "does not exist" in captured.out
    assert "hate_crack" in captured.out.lower()  # Should mention hate_crack assets
    assert "HATE_CRACK_HOME" in captured.out or "repository" in captured.out


def test_ensure_binary_with_existing_binary():
    """Test that ensure_binary succeeds when binary exists."""
    from hate_crack.main import ensure_binary
    
    # Use a system binary that definitely exists
    python_path = sys.executable
    result = ensure_binary(python_path)
    assert result == python_path
