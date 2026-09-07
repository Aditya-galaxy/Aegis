"""
The oversight metrics exist to catch a control that has quietly stopped being
one. These tests are mostly about the *negative* case: a queue that looks
healthy by every published metric (fast, high throughput, fully audited) and is
in fact a rubber stamp. If any warning branch here stops firing, Kronagent goes
on claiming human oversight it can no longer evidence.
"""
# SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Aditya Kumar, trading as Kronagent · https://kronagent.com

from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone

from kronagent.approvals import ApprovalRequest
from kronagent.oversight import (
    CONCENTRATION_LIMIT,
    HASTY_DECISION_SECONDS,
    LOW_DENY_RATE,
    MIN_DECISIONS_FOR_SIGNAL,
    compute_metrics,
)

BASE = datetime(2026, 3, 1, 12, 0, 0, tzinfo=timezone.utc)


def _req(
    *,
    status: str = "approved",
    by: str = "alice",
    took: float | None = 300.0,
    action_class: str = "terminate_instance",  # destructive + irreversible
    reversible: bool = False,
    n: int = 0,
) -> ApprovalRequest:
    created = BASE + timedelta(seconds=n)
    r = ApprovalRequest(
        finding_id=f"f-{n}",
        finding_type="Backdoor:EC2/C&CActivity.B",
        severity=8.0,
        action_class=action_class,
        target="i-abc",
        rationale="test",
        policy_reason="requires approval",
        reversible=reversible,
        blast_radius="single_resource",
        status=status,
        decided_by=None if status == "pending" else by,
    )
    r.created_at = created.isoformat()
    if status != "pending" and took is not None:
        r.decided_at = (created + timedelta(seconds=took)).isoformat()
    return r


def _many(count: int, **kw) -> list[ApprovalRequest]:
    return [_req(n=i, **kw) for i in range(count)]


# --- counting ---------------------------------------------------------------

def test_counts_and_deny_rate():
    reqs = _many(6) + _many(4, status="denied") + _many(3, status="pending")
    m = compute_metrics(reqs)
    assert (m.total, m.pending, m.decided) == (13, 3, 10)
    assert (m.approved, m.denied) == (6, 4)
    assert m.deny_rate == 0.4


def test_executed_and_failed_count_as_authorised():
    """A human said yes; whether the API call then failed is not their doing."""
    m = compute_metrics(_many(2, status="executed") + _many(2, status="failed"))
    assert m.approved == 4
    assert m.denied == 0


def test_empty_store_is_healthy_and_silent():
    m = compute_metrics([])
    assert m.healthy and m.warnings == [] and m.median_seconds_to_decide is None


# --- latency ----------------------------------------------------------------

def test_latency_percentiles():
    reqs = [_req(n=i, took=float(t)) for i, t in enumerate([10, 20, 30, 40, 1000])]
    m = compute_metrics(reqs)
    assert m.median_seconds_to_decide == 30.0
    assert m.p90_seconds_to_decide == 1000.0


def test_clock_skew_is_excluded_rather_than_dragging_the_median():
    m = compute_metrics([_req(n=0, took=-500.0), _req(n=1, took=60.0)])
    assert m.median_seconds_to_decide == 60.0


def test_missing_decided_at_does_not_break_counting():
    """Older records predate decided_at; they still count as decisions."""
    m = compute_metrics(_many(3, took=None))
    assert m.decided == 3
    assert m.median_seconds_to_decide is None


# --- the warnings, which are the actual product ------------------------------

def test_below_the_signal_floor_no_rate_is_asserted():
    """A brand-new deployment with 5 approvals is not evidence of anything."""
    m = compute_metrics(_many(MIN_DECISIONS_FOR_SIGNAL - 1))
    assert m.warnings == []
    assert m.healthy


def test_rubber_stamp_queue_is_flagged():
    """The whole point: fast, complete, audited — and never refuses anything."""
    m = compute_metrics(_many(MIN_DECISIONS_FOR_SIGNAL, took=600.0))
    assert m.deny_rate == 0.0
    assert not m.healthy
    assert any("DENY RATE" in w for w in m.warnings)


def test_a_queue_that_refuses_things_is_not_flagged_for_deny_rate():
    reqs = _many(15, took=600.0) + _many(5, status="denied", by="bob", took=600.0)
    m = compute_metrics(reqs)
    assert m.deny_rate > LOW_DENY_RATE
    assert not any("DENY RATE" in w for w in m.warnings)


def test_hasty_decisions_on_consequential_actions_are_flagged():
    reqs = _many(12, took=HASTY_DECISION_SECONDS - 1) + _many(
        8, status="denied", by="bob", took=600.0
    )
    m = compute_metrics(reqs)
    assert m.hasty_consequential == 12
    assert m.hasty_rate > 0.5
    assert any("under" in w and "cannot have been read" in w for w in m.warnings)


def test_fast_decisions_on_reversible_actions_are_not_hasty():
    """Approving a reversible IP block in five seconds is a fine thing to do."""
    reqs = [
        _req(n=i, action_class="block_ip", reversible=True, took=3.0)
        for i in range(15)
    ] + _many(5, status="denied", by="bob", took=600.0)
    m = compute_metrics(reqs)
    assert m.consequential_decided == 5      # only the denied irreversible ones
    assert m.hasty_consequential == 0
    assert not any("cannot have been read" in w for w in m.warnings)


def test_single_approver_concentration_is_flagged():
    reqs = _many(19, took=600.0) + [
        _req(n=99, status="denied", by="bob", took=600.0)
    ]
    m = compute_metrics(reqs)
    share = m.by_operator[0].decided / m.decided
    assert share > CONCENTRATION_LIMIT
    assert any("no second pair of eyes" in w for w in m.warnings)


def test_balanced_approvers_are_not_flagged_for_concentration():
    reqs = (
        _many(8, by="alice", took=600.0)
        + _many(8, by="bob", took=600.0)
        + _many(4, status="denied", by="carol", took=600.0)
    )
    m = compute_metrics(reqs)
    assert not any("no second pair of eyes" in w for w in m.warnings)


def test_an_individual_who_has_never_denied_is_named():
    """Aggregate deny rate can look fine while one person rubber-stamps."""
    reqs = _many(MIN_DECISIONS_FOR_SIGNAL, by="alice", took=600.0) + _many(
        20, status="denied", by="bob", took=600.0
    )
    m = compute_metrics(reqs)
    assert m.deny_rate == 0.5                     # aggregate looks healthy
    assert any("'alice' has approved" in w for w in m.warnings)


def test_operator_breakdown_is_ordered_by_volume():
    reqs = _many(3, by="alice") + _many(7, by="bob") + _many(1, by="carol")
    m = compute_metrics(reqs)
    assert [s.operator_id for s in m.by_operator] == ["bob", "alice", "carol"]
    assert m.by_operator[0].decided == 7


def test_decisions_without_an_operator_are_attributed_visibly():
    """Unauthenticated mode still records decisions; they must not vanish."""
    m = compute_metrics([_req(n=0, by=None) for _ in range(3)])
    assert m.by_operator[0].operator_id == "(unattributed)"
    assert m.by_operator[0].decided == 3


def test_pending_requests_are_never_counted_as_decisions():
    m = compute_metrics(_many(50, status="pending"))
    assert m.decided == 0 and m.pending == 50
    assert m.warnings == []


# --- the seam to the policy table -------------------------------------------

def test_consequential_follows_the_policy_table_not_a_local_copy():
    """`_is_consequential` must read the same table policy enforces against, so
    reclassifying an action cannot leave the oversight metric behind."""
    from kronagent import oversight

    reqs = [_req(n=i, action_class="block_ip", reversible=True, took=1.0)
            for i in range(5)]
    assert compute_metrics(reqs).consequential_decided == 0

    original = oversight.action_properties
    try:
        oversight.action_properties = lambda ac: {"destructive": True}
        assert compute_metrics(reqs).consequential_decided == 5
    finally:
        oversight.action_properties = original


def test_a_lone_operator_is_not_warned_about_being_alone():
    """A single-operator self-hosted deployment cannot fix being solo; warning
    on it every run would train the reader to ignore the whole report. The
    deny-rate and hasty checks still cover that person."""
    reqs = _many(15, by="solo", took=600.0) + _many(
        10, status="denied", by="solo", took=600.0
    )
    m = compute_metrics(reqs)
    assert len(m.by_operator) == 1
    assert m.healthy


# --- the CLI contract -------------------------------------------------------
#
# `approve.py stats` is meant to be runnable from cron. Its exit code is
# therefore an interface: 1 means "come and look at this queue". If it ever
# silently returns 0 on a degraded control, the check runs forever and reports
# nothing, which is worse than not having it.

import json          # noqa: E402
import subprocess    # noqa: E402
import sys           # noqa: E402
from pathlib import Path   # noqa: E402

REPO_ROOT = Path(__file__).resolve().parent.parent


def _write_store(path: Path, reqs: list[ApprovalRequest]) -> None:
    path.write_text(
        json.dumps({r.request_id: r.model_dump(mode="json") for r in reqs}),
        encoding="utf-8",
    )


def _run_stats(store_path: Path) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "approve.py", "stats"],
        cwd=REPO_ROOT,
        env={**os.environ, "KRONAGENT_APPROVAL_PATH": str(store_path)},
        capture_output=True,
        text=True,
    )


def test_stats_cli_exits_nonzero_on_a_degraded_control(tmp_path):
    _write_store(tmp_path / "a.json", _many(MIN_DECISIONS_FOR_SIGNAL + 5, took=3.0))
    res = _run_stats(tmp_path / "a.json")
    assert res.returncode == 1, res.stdout + res.stderr
    assert "THE CONTROL MAY BE DEGRADING" in res.stdout
    assert "DENY RATE" in res.stdout


def test_stats_cli_exits_zero_on_a_working_queue(tmp_path):
    reqs = _many(15, took=600.0) + _many(10, status="denied", by="bob", took=600.0)
    _write_store(tmp_path / "b.json", reqs)
    res = _run_stats(tmp_path / "b.json")
    assert res.returncode == 0, res.stdout + res.stderr
    assert "No degradation signals." in res.stdout
    assert "deny rate            40.0%" in res.stdout
