"""
Oversight metrics — is the human-in-the-loop control still a control?

Kronagent's central claim to a regulator, and to a buyer, is that a human
authorises every consequential action. That claim is about a *process*, and
processes decay. The access-governance literature is blunt about how:

    "Every elevation routed to a human approver produces a queue, and queues
     produce rubber-stamping. If approvals are not automated against policy for
     routine, low-risk elevation, the control degrades into a formality within
     weeks."

Automation-bias research finds the same effect in SOCs specifically — it affects
roughly half of analysts, and higher automation induces "excessive reliance and
less alertness." So an approval queue that is never measured will, on the
evidence, stop being an oversight mechanism while continuing to look exactly
like one. Every record still says a human approved it.

**A control that never says no is not a control.** That is the load-bearing
metric here, and it is why deny rate leads rather than throughput. Speed is the
industry's published number — a competitor advertises reviews in "2 minutes or
less" — but on this evidence speed alone is as consistent with a degraded
control as with an efficient one. The two are only distinguishable by looking at
whether anything is ever refused, and how the fast decisions are distributed.

Nothing here changes a decision. It measures decisions already made, from data
already stored, so it cannot itself become a thing that needs oversight.
"""
# SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Aditya Kumar, trading as Kronagent · https://kronagent.com
# Source-available, not open source. Commercial use requires a licence —
# see LICENSE or contact licensing@kronagent.com

from __future__ import annotations

import statistics
from datetime import datetime
from typing import Optional

from pydantic import BaseModel, Field

from .policy import action_properties

# --- Thresholds -------------------------------------------------------------
#
# Deliberately conservative, and each one is a *prompt to look*, never an
# automatic judgement: a genuinely clean estate can produce a low deny rate
# honestly. The warnings below say "this looks like a formality", not "this is
# one", because the difference needs a human who knows the environment.

# Below this many decisions, any rate is noise. Roughly the point at which a
# deny rate of zero stops being unremarkable.
MIN_DECISIONS_FOR_SIGNAL = 20

# A queue that refuses less than this is behaving like a rubber stamp.
LOW_DENY_RATE = 0.05

# A destructive, irreversible action decided faster than this was not read. The
# floor is generous on purpose — the claim is "nobody could have reviewed the
# planned API calls and rollback plan in under this", not "good reviews take
# longer".
HASTY_DECISION_SECONDS = 30.0

# One person deciding more than this share means there is no second pair of
# eyes, whatever the process document says.
CONCENTRATION_LIMIT = 0.8

_DECIDED = {"approved", "denied", "executed", "failed"}
_APPROVED = {"approved", "executed", "failed"}   # all of these were authorised


class OperatorStats(BaseModel):
    operator_id: str
    decided: int = 0
    denied: int = 0
    hasty: int = 0          # consequential actions decided faster than the floor

    @property
    def deny_rate(self) -> float:
        return self.denied / self.decided if self.decided else 0.0


class OversightMetrics(BaseModel):
    """What the approval queue actually did, as opposed to what it exists to do."""

    total: int = 0
    pending: int = 0
    decided: int = 0
    approved: int = 0
    denied: int = 0

    deny_rate: float = 0.0
    median_seconds_to_decide: Optional[float] = None
    p90_seconds_to_decide: Optional[float] = None

    # Decisions on irreversible or destructive actions taken faster than a human
    # could have read the plan. Counted separately from all fast decisions:
    # approving a reversible IP block in five seconds is fine.
    consequential_decided: int = 0
    hasty_consequential: int = 0
    hasty_rate: float = 0.0

    by_operator: list[OperatorStats] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)

    @property
    def healthy(self) -> bool:
        return not self.warnings


def _seconds_between(created: str, decided: Optional[str]) -> Optional[float]:
    if not decided:
        return None
    try:
        a = datetime.fromisoformat(created.replace("Z", "+00:00"))
        b = datetime.fromisoformat(decided.replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        return None
    delta = (b - a).total_seconds()
    # A negative delta means clock skew or a hand-edited store; excluding it is
    # better than letting it drag a median somewhere misleading.
    return delta if delta >= 0 else None


def _is_consequential(request) -> bool:
    """Whether reading this one carefully actually mattered."""
    props = action_properties(request.action_class)
    return bool(props.get("destructive")) or not request.reversible


def compute_metrics(requests: list) -> OversightMetrics:
    m = OversightMetrics(total=len(requests))
    latencies: list[float] = []
    operators: dict[str, OperatorStats] = {}

    for r in requests:
        if r.status == "pending":
            m.pending += 1
            continue
        if r.status not in _DECIDED:
            continue

        m.decided += 1
        denied = r.status == "denied"
        m.denied += int(denied)
        m.approved += int(r.status in _APPROVED)

        who = r.decided_by or "(unattributed)"
        stats = operators.setdefault(who, OperatorStats(operator_id=who))
        stats.decided += 1
        stats.denied += int(denied)

        seconds = _seconds_between(r.created_at, r.decided_at)
        if seconds is not None:
            latencies.append(seconds)

        if _is_consequential(r):
            m.consequential_decided += 1
            if seconds is not None and seconds < HASTY_DECISION_SECONDS:
                m.hasty_consequential += 1
                stats.hasty += 1

    if m.decided:
        m.deny_rate = m.denied / m.decided
    if m.consequential_decided:
        m.hasty_rate = m.hasty_consequential / m.consequential_decided
    if latencies:
        m.median_seconds_to_decide = statistics.median(latencies)
        latencies.sort()
        m.p90_seconds_to_decide = latencies[min(int(len(latencies) * 0.9),
                                                len(latencies) - 1)]

    m.by_operator = sorted(operators.values(), key=lambda s: -s.decided)
    m.warnings = _warnings(m)
    return m


def _warnings(m: OversightMetrics) -> list[str]:
    """The point of the whole module: turn the numbers into the sentence a
    reviewer would otherwise never say out loud."""
    out: list[str] = []

    if m.decided < MIN_DECISIONS_FOR_SIGNAL:
        return out  # too few decisions for any rate to mean anything

    if m.deny_rate < LOW_DENY_RATE:
        out.append(
            f"DENY RATE {m.deny_rate:.1%} over {m.decided} decisions — the queue has "
            f"refused almost nothing. A control that never says no is not a control. "
            f"Either the pipeline is unusually accurate, or approval has become a "
            f"formality; only someone who knows the estate can say which."
        )

    if m.hasty_consequential and m.hasty_rate > 0.5:
        out.append(
            f"{m.hasty_consequential} of {m.consequential_decided} destructive or "
            f"irreversible actions were decided in under {HASTY_DECISION_SECONDS:.0f}s. "
            f"The planned API calls and rollback plan cannot have been read in that "
            f"time."
        )

    if m.by_operator:
        top = m.by_operator[0]
        share = top.decided / m.decided
        # Deliberately silent when there is only one operator on record: a
        # single-operator self-hosted deployment would otherwise warn forever
        # about a fact it cannot change. The deny-rate and hasty checks still
        # apply to that person, so a solo reviewer who stops reading is caught —
        # just not for being solo.
        if share > CONCENTRATION_LIMIT and len(m.by_operator) > 1:
            out.append(
                f"'{top.operator_id}' made {share:.0%} of all decisions — there is "
                f"effectively no second pair of eyes."
            )
        for stats in m.by_operator:
            if stats.decided >= MIN_DECISIONS_FOR_SIGNAL and stats.denied == 0:
                out.append(
                    f"'{stats.operator_id}' has approved {stats.decided} of "
                    f"{stats.decided} and denied none."
                )

    return out
