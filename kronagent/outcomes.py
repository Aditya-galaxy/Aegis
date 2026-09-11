"""
What the team actually decided about a finding.

Shadow mode runs Kronagent in dry-run against a customer's real environment:
every finding is triaged and every containment action planned, and nothing
executes. That produces Kronagent's side of a comparison. This module holds the
other side — the analyst's verdict and what the team really did — so the two
can be scored against each other.

Those scores are meant to become a published number, from the customer's own
environment, that Kronagent did not choose. That makes the ground truth
security-relevant in its own right: whoever can write outcomes can move the
benchmark. So recording one requires APPROVE — the same trust as authorising
containment — every write is audited, and a revision never overwrites silently;
it increments a counter the report surfaces.
"""
# SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Aditya Kumar, trading as Kronagent · https://kronagent.com
# Source-available, not open source. Commercial use requires a licence —
# see LICENSE or contact licensing@kronagent.com

from __future__ import annotations

import json
import os
import tempfile
from typing import Literal, Optional

from pydantic import BaseModel, Field

from .approvals import now_iso

#: The analyst's judgement of the finding itself.
#:   malicious    — a real threat
#:   benign       — not a threat (a false positive, or expected activity)
#:   inconclusive — the team could not tell; recorded, listed, never scored
Verdict = Literal["malicious", "benign", "inconclusive"]

#: What the team actually did, independent of the verdict. A team may contain
#: something benign out of caution, or leave something malicious alone.
TeamAction = Literal["contained", "no_action"]


class AnalystOutcome(BaseModel):
    finding_id: str
    verdict: Verdict
    team_action: TeamAction
    recorded_by: str
    recorded_at: str = Field(default_factory=now_iso)
    note: str = ""
    # 1 for the first recording. Incremented on every change, so a benchmark
    # built on relabelled findings says so rather than quietly looking cleaner.
    revision: int = 1


class OutcomeStore:
    """JSON store of analyst outcomes, one per finding, with atomic writes.

    One file per tenant, via `get_tenant_path`, exactly like the approval and
    allowlist stores — one tenant's ground truth must never score another's.
    """

    def __init__(self, path: str) -> None:
        self._path = path

    def _read_all(self) -> dict[str, dict]:
        if not self._path or not os.path.exists(self._path):
            return {}
        with open(self._path, "r", encoding="utf-8") as fh:
            try:
                return json.load(fh)
            except json.JSONDecodeError as exc:
                # Not {}: an unreadable store silently read as empty would
                # publish a benchmark over zero outcomes and call it a result.
                raise ValueError(f"outcome store {self._path} is not valid JSON: {exc}") from exc

    def _write_all(self, data: dict[str, dict]) -> None:
        directory = os.path.dirname(os.path.abspath(self._path)) or "."
        fd, tmp = tempfile.mkstemp(dir=directory, suffix=".tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump(data, fh, indent=2)
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(tmp, self._path)
        finally:
            if os.path.exists(tmp):
                os.remove(tmp)

    def get(self, finding_id: str) -> Optional[AnalystOutcome]:
        raw = self._read_all().get(finding_id)
        return AnalystOutcome(**raw) if raw else None

    def list(self) -> list[AnalystOutcome]:
        return [AnalystOutcome(**raw) for raw in self._read_all().values()]

    def record(self, outcome: AnalystOutcome) -> tuple[AnalystOutcome, Optional[AnalystOutcome]]:
        """Store `outcome`; returns (stored, previous-or-None).

        The previous outcome is returned so the caller can audit exactly what
        changed. Revision numbering is the store's job, not the caller's, so it
        cannot be reset by passing revision=1 again.
        """
        data = self._read_all()
        previous = AnalystOutcome(**data[outcome.finding_id]) if outcome.finding_id in data else None
        stored = outcome.model_copy(update={
            "revision": (previous.revision + 1) if previous else 1,
        })
        data[stored.finding_id] = stored.model_dump()
        self._write_all(data)
        return stored, previous
