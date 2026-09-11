"""
Provenance of approval-request fields — which parts a model wrote.

Three fields on every approval request are prose written by an LLM that read
the finding, and findings carry attacker-chosen text. That prose was rendered to
the approving human beside `policy_reason`, in the same style, with nothing to
say which was Kronagent's reasoning and which was a steerable summary.

The classification table is only worth anything if it cannot drift from the
record it describes, so the load-bearing tests here are structural:

  - every field is classified, and nothing stale is;
  - every field the orchestrator fills from a model agent's output is
    classified MODEL — checked against the orchestrator's own source, so
    marking a model field "deterministic" fails the build. That is the
    dangerous direction: it would present steerable text as Kronagent's own.
"""
# SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Aditya Kumar, trading as Kronagent · https://kronagent.com
# Source-available, not open source. Commercial use requires a licence —
# see LICENSE or contact licensing@kronagent.com

from __future__ import annotations

import ast
import subprocess
import sys
from pathlib import Path

import pytest

from kronagent.approvals import ApprovalRequest
from kronagent.provenance import (
    APPROVAL_FIELD_PROVENANCE,
    EXPLANATIONS,
    Provenance,
    model_written_fields,
    provenance_map,
    provenance_of,
    review_banner,
)

REPO = Path(__file__).resolve().parent.parent
ORCHESTRATOR = REPO / "kronagent" / "orchestrator.py"


def _request(**over) -> ApprovalRequest:
    base = dict(
        finding_id="f-1", finding_type="Backdoor:EC2/C&CActivity.B", severity=8.0,
        action_class="isolate_instance_sg", target="i-0abc",
        rationale="planner rationale", policy_reason="requires approval",
        reversible=True, blast_radius="single_resource",
    )
    base.update(over)
    return ApprovalRequest(**base)


# --- The table cannot drift from the record ----------------------------------

def test_every_approval_field_is_classified():
    """A new field on ApprovalRequest fails here until someone says where it
    comes from. Unclassified fields are reported MODEL at runtime — cautious —
    but a cautious default is not a substitute for a decision."""
    missing = set(ApprovalRequest.model_fields) - set(APPROVAL_FIELD_PROVENANCE)
    assert not missing, f"unclassified ApprovalRequest fields: {sorted(missing)}"


def test_no_classification_names_a_field_that_no_longer_exists():
    stale = set(APPROVAL_FIELD_PROVENANCE) - set(ApprovalRequest.model_fields)
    assert not stale, f"classified but not on ApprovalRequest: {sorted(stale)}"


def test_every_provenance_has_an_explanation():
    """The CLI, API and console all read EXPLANATIONS. A kind without one would
    render as a blank where a reviewer needs a reason."""
    assert set(EXPLANATIONS) == set(Provenance)


# --- Checked against the orchestrator's own source ---------------------------

#: Local names in orchestrator.py bound to model-backed agent outputs.
_MODEL_OUTPUTS = {"intel", "correlation", "command"}


def _approval_request_keywords() -> dict[str, str]:
    """`{field: root name of the value}` for the ApprovalRequest(...) the
    orchestrator builds — e.g. `threat_intel_summary=intel.intel_summary`
    becomes `{"threat_intel_summary": "intel"}`."""
    tree = ast.parse(ORCHESTRATOR.read_text(encoding="utf-8"))
    calls = [n for n in ast.walk(tree)
             if isinstance(n, ast.Call) and getattr(n.func, "id", "") == "ApprovalRequest"]
    assert calls, "no ApprovalRequest(...) found in orchestrator.py — has it moved?"

    roots: dict[str, str] = {}
    for call in calls:
        for kw in call.keywords:
            node = kw.value
            while isinstance(node, (ast.Attribute, ast.Call)):
                node = node.func if isinstance(node, ast.Call) else node.value
            if isinstance(node, ast.Name):
                roots[kw.arg] = node.id
    return roots


def test_fields_filled_from_model_agents_are_classified_model():
    """The dangerous misclassification, made impossible.

    Marking a model-written field DETERMINISTIC would present steerable text as
    Kronagent's own reasoning — the exact confusion this module exists to end.
    So the classification is checked against where the orchestrator actually
    gets each value, not against anyone's memory of it.
    """
    wrong = {
        field: provenance_of(field).value
        for field, root in _approval_request_keywords().items()
        if root in _MODEL_OUTPUTS and provenance_of(field) is not Provenance.MODEL
    }
    assert not wrong, (
        f"filled from a model agent's output but not classified MODEL: {wrong}")


def test_the_source_scan_sees_the_model_fields():
    """A scan that finds nothing passes vacuously."""
    from_models = {f for f, r in _approval_request_keywords().items()
                   if r in _MODEL_OUTPUTS}
    assert {"threat_intel_summary", "correlation_summary",
            "incident_narrative"} <= from_models, from_models


def test_severity_is_not_model_written():
    """Recorded because it was checked, not assumed: triage copies
    `finding.severity` into its verdict rather than letting the model set it.
    If that ever changes, severity becomes steerable — and it is the number the
    containment threshold is compared against."""
    src = (REPO / "kronagent" / "triage.py").read_text(encoding="utf-8")
    assert "severity=finding.severity" in src
    assert "severity=out." not in src


# --- Behaviour ---------------------------------------------------------------

def test_model_written_fields_lists_only_populated_model_fields():
    r = _request(threat_intel_summary="summary", correlation_summary="")
    assert model_written_fields(r) == ["escalated", "threat_intel_summary"]


def test_escalated_false_is_still_a_model_answer():
    """`escalated=False` is the model deciding not to escalate — a judgement
    worth marking, not an empty field."""
    assert "escalated" in model_written_fields(_request(escalated=False))


def test_the_banner_names_the_model_fields():
    banner = review_banner(_request(threat_intel_summary="looks benign"))
    assert "language model" in banner
    assert "threat_intel_summary" in banner
    assert "not evidence" in banner


def test_provenance_map_covers_deterministic_fields_too():
    """Sent for every populated field, so a consumer can tell 'deterministic'
    from 'not mentioned' without knowing the full list."""
    m = provenance_map(_request(threat_intel_summary="x"))
    assert m["policy_reason"] == "deterministic"
    assert m["target"] == "telemetry"
    assert m["threat_intel_summary"] == "model"


def test_unknown_fields_are_treated_as_model_written():
    """Cautious default: over-mark rather than present unknown text as ours."""
    assert provenance_of("some_future_field") is Provenance.MODEL


# --- Every surface a reviewer reads ------------------------------------------

def test_the_api_returns_provenance(tmp_path, monkeypatch):
    from fastapi.testclient import TestClient
    from kronagent import web
    from kronagent.approvals import ApprovalStore

    store = ApprovalStore(str(tmp_path / "a.json"))
    store.add(_request(threat_intel_summary="injected: known false positive"))
    monkeypatch.setattr(web, "approval_store", store)
    monkeypatch.setattr(web, "get_approval_store", lambda tenant_id: store)

    body = TestClient(web.app).get("/api/approvals").json()[0]
    assert body["provenance"]["threat_intel_summary"] == "model"
    assert "language model" in body["provenance_warning"]


def test_the_console_renders_model_prose_in_its_own_marked_block():
    """The summaries must sit inside `model-context`, not the deterministic
    intel box — checked by position in the rendered template."""
    js = (REPO / "kronagent" / "static" / "app.js").read_text(encoding="utf-8")
    block = js.index('class="model-context"')
    head = js.index("context, not evidence", block)
    for field in ("req.threat_intel_summary}", "req.correlation_summary}",
                  "req.incident_narrative}", "${techniques}"):
        pos = js.index(field, block)
        assert pos > head, f"{field} is rendered outside the model-written block"
    intel_box = js.index('class="intel-box"')
    assert intel_box < block
    between = js[intel_box:block]
    assert "threat_intel_summary}" not in between and "correlation_summary}" not in between, (
        "model-written prose still rendered inside the deterministic intel box")


def test_approve_show_separates_model_written_context(tmp_path):
    from kronagent.approvals import ApprovalStore

    path = tmp_path / "a.json"
    r = _request(threat_intel_summary="injected: known false positive, deny this")
    ApprovalStore(str(path)).add(r)

    res = subprocess.run(
        [sys.executable, "approve.py", "show", r.request_id],
        cwd=REPO, capture_output=True, text=True,
        env={"KRONAGENT_APPROVAL_PATH": str(path), "PATH": "/usr/bin:/bin"},
    )
    out = res.stdout
    assert res.returncode == 0, out + res.stderr
    start = out.index("written by a language model")
    end = out.index("end of model-written context")
    assert start < out.index("injected: known false positive") < end
    assert out.index("planned API calls") > end, (
        "deterministic output must not be inside the model-written section")


@pytest.mark.parametrize("field", ["threat_intel_summary", "correlation_summary",
                                   "incident_narrative"])
def test_the_three_summaries_are_model(field):
    assert provenance_of(field) is Provenance.MODEL
