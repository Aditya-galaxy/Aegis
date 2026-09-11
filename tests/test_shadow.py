"""
Shadow mode's agreement report — and the ways it must refuse to flatter itself.

The report is meant to become a published number from a customer's own
environment. A benchmark is only worth publishing with its losses, so most of
these tests pin what the report must NOT do: count unlabeled findings as
agreement, score inconclusive outcomes, credit the model for attacks the
severity floor rescued, or drop a disagreement from the list.
"""
# SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Aditya Kumar, trading as Kronagent · https://kronagent.com
# Source-available, not open source. Commercial use requires a licence —
# see LICENSE or contact licensing@kronagent.com

from __future__ import annotations

import asyncio
import json
import subprocess
import sys
from pathlib import Path

import pytest

from kronagent.audit import AuditLog
from kronagent.outcomes import AnalystOutcome, OutcomeStore
from kronagent.schemas import AuditRecord
from kronagent.shadow import (
    FALSE_ALARM,
    MIN_SCORED_FOR_PUBLICATION,
    MISSED_ATTACK,
    RESCUED_BY_FLOOR,
    TEAM_CONTAINED_KRONAGENT_WOULD_NOT,
    WOULD_CONTAIN_TEAM_DID_NOT,
    build_report,
    calls_from_audit,
    render_text,
)
from kronagent.stats import wilson_score_interval

REPO = Path(__file__).resolve().parent.parent


# --- helpers -----------------------------------------------------------------

def _triage(fid: str, actionable: bool, severity: float = 8.0, ts: str = "") -> dict:
    return {"ts": ts or f"2026-09-01T00:00:{int(abs(hash(fid)) % 60):02d}Z",
            "finding_id": fid, "stage": "triage",
            "payload": {"is_actionable_threat": actionable, "severity": severity}}


def _policy(fid: str, disposition: str, action_class: str = "isolate_pod") -> dict:
    return {"finding_id": fid, "stage": "policy",
            "payload": {"action": {"action_class": action_class, "target": "x"},
                        "decision": {"disposition": disposition}}}


def _override(fid: str) -> dict:
    return {"finding_id": fid, "stage": "triage_override", "payload": {}}


def _outcome(fid: str, verdict: str, action: str, **kw) -> AnalystOutcome:
    return AnalystOutcome(finding_id=fid, verdict=verdict, team_action=action,
                          recorded_by=kw.pop("by", "alice"), **kw)


# --- the shared interval -----------------------------------------------------

def test_wilson_matches_the_previous_implementation_at_95_percent():
    """Moved from run_eval.py. The old version hard-coded z=1.96; the derived z
    is 1.95996…, so results must agree to well within display precision."""
    import math

    def old(s, t):
        z = 1.96
        p = s / t
        d = 1 + z ** 2 / t
        c = p + z ** 2 / (2 * t)
        m = z * math.sqrt((p * (1 - p) + z ** 2 / (4 * t)) / t)
        return max(0.0, (c - m) / d), min(1.0, (c + m) / d)

    for s, t in [(8, 10), (10, 10), (0, 10), (27, 30), (1, 1)]:
        new = wilson_score_interval(s, t)
        assert all(abs(a - b) < 1e-4 for a, b in zip(new, old(s, t))), (s, t)


def test_the_confidence_argument_is_actually_used():
    """It used to be accepted and ignored — a 99% request got a 95% interval."""
    lo95, hi95 = wilson_score_interval(8, 10, 0.95)
    lo99, hi99 = wilson_score_interval(8, 10, 0.99)
    assert lo99 < lo95 and hi99 > hi95


@pytest.mark.parametrize("bad", [0.0, 1.0, 1.5, -0.1])
def test_an_impossible_confidence_is_rejected(bad):
    with pytest.raises(ValueError):
        wilson_score_interval(1, 2, bad)


def test_run_eval_still_exports_the_interval():
    """tests/test_eval_harness.py imports it from run_eval; the move must not
    break that, and there must be one implementation, not two."""
    import run_eval
    from kronagent import stats
    assert run_eval.wilson_score_interval is stats.wilson_score_interval


# --- reconstructing Kronagent's decisions ------------------------------------

def test_a_dismissed_finding_is_a_decision_too():
    """Triage-dismissed findings never reach an approval queue. A comparison
    built from approvals would never see them — and they are where missed
    attacks live."""
    calls = calls_from_audit([_triage("f1", actionable=False)])
    assert calls["f1"].model_actionable is False
    assert calls["f1"].would_contain is False


def test_policy_dispositions_set_would_contain():
    calls = calls_from_audit([_triage("f1", True), _policy("f1", "requires_approval"),
                              _triage("f2", True), _policy("f2", "auto_execute"),
                              _triage("f3", True), _policy("f3", "blocked")])
    assert calls["f1"].would_contain and not calls["f1"].would_auto_execute
    assert calls["f2"].would_contain and calls["f2"].would_auto_execute
    assert not calls["f3"].would_contain


def test_a_redelivered_finding_is_judged_on_its_latest_processing():
    """Delivery is at-least-once. A containment planned on an earlier attempt
    must not leak into a later processing that planned none."""
    calls = calls_from_audit([_triage("f1", True), _policy("f1", "requires_approval"),
                              _triage("f1", False)])
    assert calls["f1"].model_actionable is False
    assert calls["f1"].would_contain is False


def test_records_for_a_finding_with_no_triage_are_ignored():
    """No triage record means Kronagent made no call; inventing one would score
    something that did not happen."""
    assert calls_from_audit([_policy("ghost", "auto_execute")]) == {}


def test_the_floor_rescue_is_recorded():
    calls = calls_from_audit([_triage("f1", False), _override("f1"),
                              _policy("f1", "requires_approval")])
    assert calls["f1"].rescued_by_floor and calls["f1"].would_contain


# --- what the report refuses to do -------------------------------------------

def test_unlabeled_findings_are_never_counted_as_agreement():
    calls = calls_from_audit([_triage("f1", True), _triage("f2", False)])
    report = build_report(calls, [])
    assert report.scored == 0 and report.unlabeled == 2
    assert report.triage.rate is None
    assert any("not counted as agreement" in n for n in report.notes)


def test_inconclusive_outcomes_are_not_scored():
    calls = calls_from_audit([_triage("f1", True)])
    report = build_report(calls, [_outcome("f1", "inconclusive", "no_action")])
    assert report.scored == 0 and report.inconclusive == 1
    assert report.disagreements == []


def test_a_floor_rescue_is_not_credited_to_the_model():
    """The model dismissed a real attack and the safeguard caught it. That is a
    model miss — counted as a false negative — and reported as rescued."""
    calls = calls_from_audit([_triage("f1", False), _override("f1"),
                              _policy("f1", "requires_approval")])
    report = build_report(calls, [_outcome("f1", "malicious", "contained")])
    assert report.triage.false_negative == 1 and report.triage.agree == 0
    assert report.rescued_by_floor == 1
    assert report.disagreements[0].kinds == [RESCUED_BY_FLOOR]
    # ...while the containment decision itself did agree with the team.
    assert report.containment.agree == 1


def test_each_disagreement_kind_is_named():
    calls = calls_from_audit([
        _triage("missed", False),
        _triage("alarm", True), _policy("alarm", "requires_approval"),
        _triage("overcautious", True), _policy("overcautious", "requires_approval"),
        _triage("undercautious", True),
    ])
    report = build_report(calls, [
        _outcome("missed", "malicious", "no_action"),
        _outcome("alarm", "benign", "no_action"),
        _outcome("overcautious", "malicious", "no_action"),
        _outcome("undercautious", "malicious", "contained"),
    ])
    kinds = {d.finding_id: d.kinds for d in report.disagreements}
    assert kinds["missed"] == [MISSED_ATTACK]
    assert kinds["alarm"] == [FALSE_ALARM, WOULD_CONTAIN_TEAM_DID_NOT]
    assert kinds["overcautious"] == [WOULD_CONTAIN_TEAM_DID_NOT]
    assert kinds["undercautious"] == [TEAM_CONTAINED_KRONAGENT_WOULD_NOT]


def test_every_disagreement_is_listed_with_no_truncation():
    """A benchmark published without its losses is a sales sheet."""
    n = 250
    calls = calls_from_audit([_triage(f"f{i}", True) for i in range(n)])
    report = build_report(calls, [_outcome(f"f{i}", "benign", "no_action") for i in range(n)])
    assert len(report.disagreements) == n
    text = render_text(report)
    assert all(f"f{i} " in text for i in range(n))


def test_outcomes_for_unseen_findings_are_listed_not_scored():
    calls = calls_from_audit([_triage("f1", True)])
    report = build_report(calls, [_outcome("typo-id", "malicious", "contained")])
    assert report.outcomes_without_a_kronagent_call == ["typo-id"]
    assert report.scored == 0


def test_small_samples_are_marked_not_publishable():
    calls = calls_from_audit([_triage(f"f{i}", True) for i in range(MIN_SCORED_FOR_PUBLICATION)])
    few = build_report(calls, [_outcome(f"f{i}", "malicious", "no_action")
                               for i in range(MIN_SCORED_FOR_PUBLICATION - 1)])
    enough = build_report(calls, [_outcome(f"f{i}", "malicious", "no_action")
                                  for i in range(MIN_SCORED_FOR_PUBLICATION)])
    assert not few.publishable and any("not ready to publish" in n for n in few.notes)
    assert enough.publishable


def test_precision_and_recall_are_absent_rather_than_zero_without_data():
    """0% precision and "no positives predicted" are different facts."""
    calls = calls_from_audit([_triage("f1", False)])
    report = build_report(calls, [_outcome("f1", "benign", "no_action")])
    assert report.triage.precision is None and report.triage.recall is None
    assert report.triage.true_negative == 1


def test_revised_outcomes_are_surfaced():
    calls = calls_from_audit([_triage("f1", True)])
    report = build_report(calls, [_outcome("f1", "malicious", "contained", revision=2)])
    assert report.revised_outcomes == 1
    assert any("revised" in n for n in report.notes)


# --- the store ---------------------------------------------------------------

def test_recording_twice_increments_revision_and_returns_the_previous(tmp_path):
    store = OutcomeStore(str(tmp_path / "o.json"))
    first, prev = store.record(_outcome("f1", "benign", "no_action"))
    assert (first.revision, prev) == (1, None)
    second, prev = store.record(_outcome("f1", "malicious", "contained", revision=1))
    assert second.revision == 2, "a caller passing revision=1 must not reset history"
    assert prev.verdict == "benign"
    assert OutcomeStore(str(tmp_path / "o.json")).get("f1").verdict == "malicious"


def test_a_corrupt_store_raises_rather_than_reading_as_empty(tmp_path):
    """Empty would publish a benchmark over zero outcomes and call it a result."""
    path = tmp_path / "o.json"
    path.write_text("{not json", encoding="utf-8")
    with pytest.raises(ValueError):
        OutcomeStore(str(path)).list()


# --- the CLI -----------------------------------------------------------------

def _seed_audit(path: Path, records: list[AuditRecord]) -> None:
    log = AuditLog(str(path))
    for r in records:
        asyncio.run(log.record(r))


def _cli(tmp_path: Path, *args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "outcome.py", *args], cwd=REPO, capture_output=True, text=True,
        env={"PATH": "/usr/bin:/bin",
             "KRONAGENT_AUDIT_PATH": str(tmp_path / "audit.jsonl"),
             "KRONAGENT_OUTCOME_PATH": str(tmp_path / "outcomes.json")},
    )


def test_cli_records_audits_and_reports(tmp_path):
    _seed_audit(tmp_path / "audit.jsonl", [
        AuditRecord(finding_id="f1", stage="triage",
                    payload={"is_actionable_threat": False, "severity": 8.5}),
    ])
    res = _cli(tmp_path, "record", "f1", "--verdict", "malicious",
               "--action", "contained", "--by", "alice", "--note", "real C2 beacon")
    assert res.returncode == 0, res.stdout + res.stderr

    stages = [r["stage"] for r in AuditLog.read_records(str(tmp_path / "audit.jsonl"))]
    assert "analyst_outcome" in stages
    assert AuditLog.verify(str(tmp_path / "audit.jsonl"))[0], "recording broke the chain"

    report = _cli(tmp_path, "report")
    assert report.returncode == 0, report.stderr
    assert MISSED_ATTACK in report.stdout and "real C2 beacon" in report.stdout

    as_json = json.loads(_cli(tmp_path, "report", "--json").stdout)
    assert as_json["triage"]["false_negative"] == 1


def test_cli_refuses_an_unseen_finding_without_the_explicit_flag(tmp_path):
    """A typo'd id would otherwise create an outcome nothing can be scored
    against, silently."""
    _seed_audit(tmp_path / "audit.jsonl", [
        AuditRecord(finding_id="f1", stage="triage", payload={"is_actionable_threat": True}),
    ])
    res = _cli(tmp_path, "record", "f-typo", "--verdict", "benign",
               "--action", "no_action", "--by", "alice")
    assert res.returncode == 2 and "--allow-unseen" in res.stderr
    assert not (tmp_path / "outcomes.json").exists()

    ok = _cli(tmp_path, "record", "f-typo", "--verdict", "benign",
              "--action", "no_action", "--by", "alice", "--allow-unseen")
    assert ok.returncode == 0, ok.stderr


def test_a_revision_is_audited_with_what_it_replaced(tmp_path):
    _seed_audit(tmp_path / "audit.jsonl", [
        AuditRecord(finding_id="f1", stage="triage", payload={"is_actionable_threat": True}),
    ])
    _cli(tmp_path, "record", "f1", "--verdict", "benign", "--action", "no_action", "--by", "alice")
    _cli(tmp_path, "record", "f1", "--verdict", "malicious", "--action", "contained", "--by", "bob")
    revisions = [r for r in AuditLog.read_records(str(tmp_path / "audit.jsonl"))
                 if r["stage"] == "analyst_outcome"]
    assert revisions[-1]["payload"]["revision"] == 2
    assert revisions[-1]["payload"]["previous"]["verdict"] == "benign"
    # Unauthenticated --by names are labelled unverified by identity.py, and that
    # label is what the audit trail and every published disagreement carry.
    # Ground truth recorded without authentication must say so.
    assert revisions[-1]["payload"]["previous"]["recorded_by"] == "alice (unverified)"


# --- the API -----------------------------------------------------------------

def test_the_report_is_served_per_tenant(tmp_path, monkeypatch):
    from fastapi.testclient import TestClient
    from kronagent import web

    audit_path = tmp_path / "audit.jsonl"
    _seed_audit(audit_path, [
        AuditRecord(finding_id="f1", stage="triage", payload={"is_actionable_threat": True}),
    ])
    store = OutcomeStore(str(tmp_path / "outcomes.json"))
    store.record(_outcome("f1", "benign", "no_action"))

    monkeypatch.setattr(web, "get_audit_log", lambda tenant_id: AuditLog(str(audit_path)))
    monkeypatch.setattr(web, "get_outcome_store", lambda tenant_id: store)

    body = TestClient(web.app).get("/api/shadow/report").json()
    assert body["scored"] == 1
    assert body["disagreements"][0]["kinds"] == [FALSE_ALARM, ]
