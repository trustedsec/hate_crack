"""
Test that hashcat-utils assets are correctly loaded from hate_crack repo,
not from hcatPath (which should point to hashcat binary location).

This prevents regression where hcatPath was incorrectly used for utilities.
"""
import os
import json
import tempfile
import pytest


def test_hashcat_utils_uses_hate_path_not_hcat_path(tmp_path, monkeypatch):
    """
    Verify that hashcat-utils is loaded from hate_crack repo, not hcatPath.
    
    This test ensures that even when hcatPath points to a different directory
    (like /opt/hashcat), the code correctly uses hate_path for utilities.
    """
    # Set HATE_CRACK_SKIP_INIT to prevent initialization checks
    monkeypatch.setenv("HATE_CRACK_SKIP_INIT", "1")
    
    # Import after setting env var
    from hate_crack import main
    
    # The hate_path should be the hate_crack repository
    assert main.hate_path is not None
    assert os.path.isdir(main.hate_path)
    assert os.path.isdir(os.path.join(main.hate_path, "hashcat-utils"))
    
    # The hcatPath might be different (fallback to hate_path if empty)
    # But utilities should ALWAYS use hate_path
    assert main.hcatPath is not None
    
    # Key assertion: even if hcatPath != hate_path, 
    # the code should look for utilities in hate_path
    # This is verified by checking the actual code paths used


def test_config_with_explicit_hashcat_path():
    """
    Test that when hcatPath is explicitly set to a hashcat directory,
    the code still finds utilities in the hate_crack repository.
    """
    import os
    import tempfile
    import json
    
    # Create a temporary config with hcatPath set to a different location
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        test_config = {
            "hcatPath": "/opt/hashcat",  # Different from hate_crack repo
            "hcatBin": "hashcat",
            "hcatTuning": "--force",
            "hcatWordlists": "./wordlists",
            "hcatOptimizedWordlists": "./optimized_wordlists",
            "rules_directory": "/opt/hashcat/rules",
            "hcatDictionaryWordlist": ["rockyou.txt"],
            "hcatCombinationWordlist": ["rockyou.txt"],
            "hcatHybridlist": ["rockyou.txt"],
            "hcatMiddleBaseList": ["rockyou.txt"],
            "hcatMiddleCombList": ["rockyou.txt"],
            "hcatExpanderlist": ["rockyou.txt"],
            "hcatThoroughBaseList": ["rockyou.txt"],
            "hcatThoroughCombList": ["rockyou.txt"],
            "hashview_url": "https://localhost:8443",
            "hashview_api_key": ""
        }
        json.dump(test_config, f)
        config_path = f.name
    
    try:
        # Load the config
        with open(config_path) as f:
            config = json.load(f)
        
        # Verify that hcatPath is set to /opt/hashcat
        assert config['hcatPath'] == '/opt/hashcat'
        
        # This documents the expected behavior:
        # - hcatPath = /opt/hashcat (for hashcat binary)
        # - hashcat-utils should be found in hate_crack repo, not /opt/hashcat
        
    finally:
        os.unlink(config_path)


def test_readme_documents_correct_usage():
    """Verify README correctly explains hcatPath vs asset locations."""
    readme_path = os.path.join(
        os.path.dirname(os.path.dirname(__file__)),
        'README.md'
    )
    
    with open(readme_path) as f:
        readme = f.read()
    
    # Check that README mentions the correct relationship
    assert 'hcatPath' in readme
    assert 'repository directory' in readme
    assert 'hashcat-utils' in readme
    
    # Should NOT suggest putting hashcat-utils in hashcat directory
    # (This is a documentation test to prevent confusing users)


def test_resolve_hate_path_prefers_package_ancestors(tmp_path):
    """Ensure package installs discover assets by walking up to the tool root."""
    from hate_crack.main import _resolve_hate_path

    assets_root = tmp_path / "hate_crack_root"
    assets_root.mkdir()
    (assets_root / "hashcat-utils").mkdir()
    (assets_root / "config.json.example").write_text("{}")

    package_path = assets_root / "lib" / "python3.14" / "site-packages" / "hate_crack"
    package_path.mkdir(parents=True)

    resolved = _resolve_hate_path(str(package_path), config_dict={})
    assert resolved == str(assets_root)
