import importlib


def test_import_hashview_module():
    module = importlib.import_module("hate_crack.hashview")
    assert hasattr(module, "HashviewAPI")


def test_import_hashmob_module():
    module = importlib.import_module("hate_crack.hashmob_wordlist")
    assert hasattr(module, "list_and_download_official_wordlists")


def test_import_weakpass_module():
    module = importlib.import_module("hate_crack.weakpass")
    assert hasattr(module, "weakpass_wordlist_menu")


def test_import_cli_module():
    module = importlib.import_module("hate_crack.cli")
    assert hasattr(module, "add_common_args")


def test_import_api_module():
    module = importlib.import_module("hate_crack.api")
    assert hasattr(module, "download_hashes_from_hashview")


def test_import_attacks_module():
    module = importlib.import_module("hate_crack.attacks")
    assert hasattr(module, "quick_crack")
