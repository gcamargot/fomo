"""Activation path: profit/liveness fail must not emit triage."""

from unittest.mock import MagicMock

import dormant_monitor_daemon as dmd


def test_activation_skipped_when_liveness_not_actionable(monkeypatch):
    target = {"address": "0x" + "c" * 40, "chain": "ethereum", "name": "X"}
    monkeypatch.setattr(dmd, "load_saved_source", lambda *a, **k: "contract Dummy {}")
    monkeypatch.setattr(
        dmd.StaticVulnerabilityAuditor,
        "audit_source",
        staticmethod(lambda src: ({}, [{"user_exploitable": True, "type": "BROKEN_ACCESS_CONTROL"}])),
    )
    monkeypatch.setattr(
        dmd.OnChainStateVerifier,
        "verify_onchain_liveness",
        staticmethod(lambda *a, **k: (False, "PROFIT_BELOW_THRESHOLD_NATIVE_0.0000ETH", 0.5, [], None)),
    )
    gen = MagicMock()
    monkeypatch.setattr(dmd.TriageReportGenerator, "generate_triage_file", gen)
    emit = MagicMock()
    monkeypatch.setattr(dmd.AlertDispatcher, "emit_triage_alert", emit)

    watcher = dmd.DormantBalanceWatcher.__new__(dmd.DormantBalanceWatcher)
    watcher.db = MagicMock()
    assert watcher.check_and_update_contract(target) is False
    gen.assert_not_called()
    emit.assert_not_called()
    watcher.db.update_token_flags.assert_not_called()


def test_activation_emits_once_when_profit_and_liveness_pass(monkeypatch):
    target = {"address": "0x" + "d" * 40, "chain": "ethereum", "name": "Y"}
    confirmed = [{"type": "BROKEN_ACCESS_CONTROL", "severity": "CRITICAL", "title": "x",
                  "exploiter": "e", "victim": "v", "payoff": "p", "snippet": ""}]
    monkeypatch.setattr(dmd, "load_saved_source", lambda *a, **k: "pragma solidity ^0.8.0; contract Y {}")
    monkeypatch.setattr(
        dmd.StaticVulnerabilityAuditor,
        "audit_source",
        staticmethod(lambda src: ({}, [{"user_exploitable": True, "type": "BROKEN_ACCESS_CONTROL"}])),
    )
    monkeypatch.setattr(
        dmd.OnChainStateVerifier,
        "verify_onchain_liveness",
        staticmethod(lambda *a, **k: (True, "BROKEN_ACCESS_CALLABLE", 1.5, confirmed, None)),
    )
    monkeypatch.setattr(
        dmd.TriageReportGenerator,
        "generate_triage_file",
        staticmethod(lambda *a, **k: "/tmp/triage.md"),
    )
    emit = MagicMock()
    monkeypatch.setattr(dmd.AlertDispatcher, "emit_triage_alert", emit)

    watcher = dmd.DormantBalanceWatcher.__new__(dmd.DormantBalanceWatcher)
    watcher.db = MagicMock()
    assert watcher.check_and_update_contract(target) is True
    emit.assert_called_once()
    watcher.db.update_token_flags.assert_called_once()
    args, kwargs = watcher.db.update_token_flags.call_args
    assert args[1]["is_user_exploitable"] == 1
    assert args[1]["eth_balance"] == 1.5
