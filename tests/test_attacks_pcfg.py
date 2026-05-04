from unittest.mock import MagicMock

from hate_crack.attacks import pcfg_attack, prince_ling_attack


def _make_ctx(hash_type: str = "1000", hash_file: str = "/tmp/hashes.txt") -> MagicMock:
    ctx = MagicMock()
    ctx.hcatHashType = hash_type
    ctx.hcatHashFile = hash_file
    return ctx


def test_pcfg_attack_invokes_hcatPCFG():
    ctx = _make_ctx()
    pcfg_attack(ctx)
    ctx.hcatPCFG.assert_called_once_with("1000", "/tmp/hashes.txt")


def test_prince_ling_attack_invokes_hcatPrinceLing():
    ctx = _make_ctx()
    prince_ling_attack(ctx)
    ctx.hcatPrinceLing.assert_called_once_with("1000", "/tmp/hashes.txt")
