"""Triage markdown includes profit gate fields when an estimate is present."""


from profit_estimator import ProfitEstimate, profit_to_dict
from token_scanner_daemon import TriageReportGenerator


def _meta(**extra):
    data = {
        "address": "0x" + "e" * 40,
        "chain": "ethereum",
        "name": "Probe",
        "compiler": "0.8.20",
        "category": "ERC20_TOKEN",
        "eth_balance": 0.0,
        "dynamic_status": "PUBLIC_SWAPBACK_ACTIVE",
    }
    data.update(extra)
    return data


def _exploit(**extra):
    e = {
        "type": "PUBLIC_SWAPBACK_TRIGGER",
        "severity": "HIGH",
        "title": "swapBack público",
        "exploiter": "MEV",
        "victim": "Treasury",
        "payoff": "Sandwich",
        "snippet": "function swapBack() public {}",
        "onchain_evidence": "reachable",
    }
    e.update(extra)
    return e


def test_triage_card_includes_profit_section(tmp_path):
    est = ProfitEstimate(
        expected_profit_eth=0.42,
        pool_eth=12.0,
        treasury_token_raw=0,
        sell_fraction=0.25,
        gas_eth=0.002,
        method="xyk_spot",
        actionable=True,
    )
    meta = _meta(profit=profit_to_dict(est))
    path = TriageReportGenerator.generate_triage_file(
        meta, [_exploit()], output_dir=str(tmp_path)
    )
    text = open(path, encoding="utf-8").read()
    assert "## Profit Gate" in text
    assert "**Expected Profit (ETH):** `0.4200`" in text
    assert "**Pool ETH:** `12.0000`" in text
    assert "**Gate:** `PASS`" in text
    assert "**Method:** `xyk_spot`" in text


def test_triage_card_profit_from_exploit_payload(tmp_path):
    est = profit_to_dict(ProfitEstimate(
        expected_profit_eth=0.08,
        pool_eth=3.5,
        treasury_token_raw=1,
        sell_fraction=0.25,
        gas_eth=0.002,
        method="xyk_spot",
        actionable=True,
    ))
    path = TriageReportGenerator.generate_triage_file(
        _meta(), [_exploit(profit=est)], output_dir=str(tmp_path)
    )
    text = open(path, encoding="utf-8").read()
    assert "**Gate:** `PASS`" in text
    assert "0.0800" in text


def test_triage_card_without_profit_has_no_section(tmp_path):
    path = TriageReportGenerator.generate_triage_file(
        _meta(), [_exploit()], output_dir=str(tmp_path)
    )
    text = open(path, encoding="utf-8").read()
    assert "## Profit Gate" not in text


def test_triage_fail_gate_renders_fail(tmp_path):
    est = profit_to_dict(ProfitEstimate(
        expected_profit_eth=0.0,
        pool_eth=0.0006,
        treasury_token_raw=0,
        sell_fraction=0.25,
        gas_eth=0.002,
        method="xyk_spot",
        actionable=False,
    ))
    path = TriageReportGenerator.generate_triage_file(
        _meta(profit=est), [_exploit()], output_dir=str(tmp_path)
    )
    assert "**Gate:** `FAIL`" in open(path, encoding="utf-8").read()
