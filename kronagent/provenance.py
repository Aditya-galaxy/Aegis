"""
Where each part of an approval request came from.

Kronagent's safety argument is that a language model can influence *whether*
containment proceeds but never *what* it targets. That holds: targets come from
a deterministic planner, the trajectory guard checks them against the finding,
and import contracts stop an agent module reaching the executor.

There is a second path a model has into the outcome, and it is not covered by
any of that. Three fields on every approval request are **prose written by an
LLM that read the finding** — and findings describe attacker activity, with
attacker-chosen strings in them. That prose is rendered to the human deciding
whether to contain, beside `policy_reason` and the planned API calls, in the
same typeface, with nothing to say which is which.

`insights.py` already refuses to let a model write its tags, and says why:

    "a model-written tag would be a prompt-injection path into that decision:
     injected telemetry emitting 'known false alarm' could talk a reviewer out
     of containing a real breach."

That reasoning is right and the tags are safe. The summaries are the same threat
wearing better clothes — prose is *more* persuasive than a tag, not less — and
they were left unmarked. This module closes that asymmetry, not by removing the
prose (it is genuinely useful) but by making its origin impossible to miss.

This is the data-flow half of CaMeL's argument. Kronagent already has the
control-flow half, more strongly than CaMeL does — its plan is deterministic
rather than model-authored. What it lacked is CaMeL's other observation: that
an attacker who cannot change *what* the agent does can still change the *data*
the decision is made on. Here the decision-maker is a human, so the enforcement
point is the render, not a tool call.

Nothing here changes a decision. It labels, so a reviewer can discount.
"""
# SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Aditya Kumar, trading as Kronagent · https://kronagent.com
# Source-available, not open source. Commercial use requires a licence —
# see LICENSE or contact licensing@kronagent.com

from __future__ import annotations

from enum import Enum
from typing import Any


class Provenance(str, Enum):
    """Who produced a value, ordered by how much an attacker can shape it."""

    # Computed by Kronagent's own code from the policy table, the action class
    # and the adapter. An attacker changes these only by changing the code.
    DETERMINISTIC = "deterministic"

    # Copied verbatim from the finding. The detector chose the field; the
    # attacker frequently chose its *contents* — an instance can be named
    # anything, and so can an IAM user, an S3 key or a process command line.
    TELEMETRY = "telemetry"

    # Written by an LLM that read the finding. Attacker-influenced at one
    # remove, and the most persuasive text on the page.
    MODEL = "model"

    # Typed by a human operator, after the fact.
    OPERATOR = "operator"


#: Every field of ApprovalRequest, classified. Exhaustiveness is asserted in
#: tests/test_provenance.py — a new field fails the build until someone says
#: where it comes from, which is the point: this table is only worth anything
#: if it cannot fall behind the record it describes.
APPROVAL_FIELD_PROVENANCE: dict[str, Provenance] = {
    # --- Kronagent's own bookkeeping and decisions ---
    "request_id": Provenance.DETERMINISTIC,
    "created_at": Provenance.DETERMINISTIC,
    "provider": Provenance.DETERMINISTIC,
    "action_class": Provenance.DETERMINISTIC,
    "rationale": Provenance.DETERMINISTIC,      # written by the planner, not a model
    "policy_reason": Provenance.DETERMINISTIC,
    "reversible": Provenance.DETERMINISTIC,
    "blast_radius": Provenance.DETERMINISTIC,
    "planned_api_calls": Provenance.DETERMINISTIC,
    "rollback_hint": Provenance.DETERMINISTIC,
    "evidence_collected": Provenance.DETERMINISTIC,   # forensics is deterministic
    "status": Provenance.DETERMINISTIC,
    "execution_detail": Provenance.DETERMINISTIC,
    "slack_ts": Provenance.DETERMINISTIC,

    # --- Straight from the finding ---
    "finding_id": Provenance.TELEMETRY,
    "finding_type": Provenance.TELEMETRY,
    # Normalized by the detector, not chosen by an attacker as free text — but
    # it is the number the containment threshold is compared against, so it is
    # named here rather than buried with the bookkeeping.
    "severity": Provenance.TELEMETRY,
    # The resource id or IP. Whoever named the resource wrote this string.
    "target": Provenance.TELEMETRY,
    "parameters": Provenance.TELEMETRY,

    # --- Written or chosen by a model that read the finding ---
    "threat_intel_summary": Provenance.MODEL,
    "correlation_summary": Provenance.MODEL,
    "incident_narrative": Provenance.MODEL,
    "incident_priority": Provenance.MODEL,
    "escalated": Provenance.MODEL,
    # Filled by the intel agent's own output schema. These sit next to the
    # deterministic insight tags in the console and read exactly like them.
    "mitre_techniques": Provenance.MODEL,
    # The model selects these, but only from finding ids that already exist —
    # correlation.py filters its output against known ids. So it can mislead by
    # *selection*, never by fabrication. Selection is still influence.
    "related_finding_ids": Provenance.MODEL,

    # --- The human ---
    "decided_by": Provenance.OPERATOR,
    "decided_at": Provenance.OPERATOR,
    "decision_reason": Provenance.OPERATOR,
}

#: What to tell a reviewer about each origin, in one line. Kept here rather than
#: in the console so the CLI, the API and the UI cannot say different things.
EXPLANATIONS: dict[Provenance, str] = {
    Provenance.DETERMINISTIC:
        "Computed by Kronagent from the policy table and the action itself. No "
        "model wrote this.",
    Provenance.TELEMETRY:
        "Taken verbatim from the finding. Whoever named the resource chose this "
        "text.",
    Provenance.MODEL:
        "Written by a language model that read the finding. Treat as context, "
        "never as evidence: telemetry an attacker controls is part of its input, "
        "so this text can be steered.",
    Provenance.OPERATOR:
        "Entered by a human operator.",
}


def provenance_of(field: str) -> Provenance:
    """Classification for one field.

    Unknown fields are reported MODEL — the most cautious answer, so a field
    that slips past the exhaustiveness test is over-marked rather than presented
    as though Kronagent computed it.
    """
    return APPROVAL_FIELD_PROVENANCE.get(field, Provenance.MODEL)


def _is_populated(value: Any) -> bool:
    """Whether a field actually carries content worth marking.

    `escalated=False` is a real answer from the model, not an empty field, so
    booleans count as populated. Empty strings and empty collections do not:
    marking a field nobody can see trains people to ignore the marking.
    """
    if isinstance(value, bool):
        return True
    return bool(value)


def fields_with_provenance(request: Any, kind: Provenance) -> list[str]:
    """Populated fields of `request` with the given origin."""
    return sorted(
        name for name, prov in APPROVAL_FIELD_PROVENANCE.items()
        if prov is kind and _is_populated(getattr(request, name, None))
    )


def model_written_fields(request: Any) -> list[str]:
    """The fields a reviewer should discount if the telemetry looks hostile."""
    return fields_with_provenance(request, Provenance.MODEL)


def provenance_map(request: Any) -> dict[str, str]:
    """`{field: provenance}` for every populated field, for the API.

    Sent for all fields rather than only the model-written ones: a consumer that
    receives marks only for the suspicious fields has to know the full list to
    tell "deterministic" from "not mentioned", and that is exactly the kind of
    implicit contract that drifts.
    """
    return {
        name: provenance_of(name).value
        for name in APPROVAL_FIELD_PROVENANCE
        if _is_populated(getattr(request, name, None))
    }


def review_banner(request: Any) -> str:
    """One line naming the model-written fields on this request, or "".

    Used by the CLI and the API. Empty when a request carries no model prose —
    a warning that appears unconditionally stops being read.
    """
    fields = model_written_fields(request)
    if not fields:
        return ""
    return (f"{len(fields)} field(s) below were written by a language model that "
            f"read this finding ({', '.join(fields)}). Attacker-controlled "
            f"telemetry is part of that model's input — treat them as context, "
            f"not evidence.")
