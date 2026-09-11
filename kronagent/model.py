"""
Provider-neutral finding model.

Everything above the provider boundary — triage, policy, containment dispatch,
approval, audit, governance — operates on `Finding`, never on a vendor's wire
schema. A provider adapter (kronagent/providers/*.py) does exactly two things:

  1. normalize its native events (GuardDuty finding, Kubernetes audit event,
     Falco alert, an in-house syslog line, ...) into a `Finding`, and
  2. implement containment for the action classes it owns.

Adding AWS was the first data point; adding Kubernetes is what forces this
boundary to be real rather than assumed. The severity scale is normalized to
0-10 across providers so the single `min_severity_for_containment` threshold and
the policy engine mean the same thing everywhere.
"""
# SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Aditya Kumar, trading as Kronagent · https://kronagent.com
# Source-available, not open source. Commercial use requires a licence —
# see LICENSE or contact licensing@kronagent.com

from __future__ import annotations

from typing import Any, Optional

from pydantic import BaseModel, ConfigDict, Field


class ResourceRef(BaseModel):
    """A concrete resource a finding implicates and containment can target.

    `kind` is a namespaced type the provider's planner dispatches on, e.g.
    'aws.iam.access_key', 'aws.ec2.instance', 'k8s.pod', 'k8s.node'. `id` is the
    concrete identifier; `attributes` carries whatever the planner/containment
    needs (IAM user name, k8s namespace, owning node, ...).
    """

    model_config = ConfigDict(frozen=True)

    kind: str
    id: str
    attributes: dict[str, Any] = Field(default_factory=dict)


def severity_band(score: float) -> str:
    """The band a 0-10 normalized severity falls in.

    One definition, used by `Finding.severity_band` and by anything that only
    has the number — the weekly digest bands findings from audit records, which
    carry a severity but no Finding. Two copies of these thresholds would let the
    digest and the console report different counts of "high" findings for the
    same week.
    """
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    return "low"


class Finding(BaseModel):
    """Normalized, provider-neutral security finding."""

    model_config = ConfigDict(frozen=True)

    provider: str                 # "aws" | "kubernetes" | ...
    finding_id: str
    finding_type: str             # provider-native type string, kept for context
    severity: float               # normalized 0-10 (higher = worse)
    tenant_id: str = "default"    # tenant partition for multi-tenancy
    title: str = ""
    description: str = ""
    resources: list[ResourceRef] = Field(default_factory=list)
    remote_ip: Optional[str] = None
    raw: dict[str, Any] = Field(default_factory=dict)  # original payload, for audit

    @property
    def severity_band(self) -> str:
        return severity_band(self.severity)
