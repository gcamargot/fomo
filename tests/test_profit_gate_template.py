"""ProfitGateTemplate.t.sol stays a CI no-op unless FOMO_TARGET is set."""

from pathlib import Path

SOL = Path(__file__).resolve().parents[1] / "simulations" / "test" / "ProfitGateTemplate.t.sol"


def test_template_uses_envor_and_measures_attacker_eth():
    src = SOL.read_text(encoding="utf-8")
    assert "function testProfitPositive()" in src
    assert 'vm.envOr("FOMO_TARGET"' in src
    assert "attacker.balance" in src
    assert "FOMO_MIN_PROFIT_WEI" in src
    assert "if (target == address(0))" in src


def test_template_default_attack_is_virtual_hook():
    src = SOL.read_text(encoding="utf-8")
    assert "function _runAttack" in src
    assert "internal virtual" in src
