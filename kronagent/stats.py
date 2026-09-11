"""
Small statistics shared by the evaluation harness and the shadow-mode report.

Both publish rates computed from small samples, and a rate from ten findings
read as a point estimate implies far more certainty than ten findings contain.
Every rate either surface reports travels with an interval, and the interval is
computed here once so the two cannot disagree about what "95%" means.
"""
# SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Aditya Kumar, trading as Kronagent · https://kronagent.com
# Source-available, not open source. Commercial use requires a licence —
# see LICENSE or contact licensing@kronagent.com

from __future__ import annotations

import math
from statistics import NormalDist


def wilson_score_interval(successes: int, total: int,
                          confidence: float = 0.95) -> tuple[float, float]:
    """Wilson score interval for a binomial proportion.

    Chosen over the normal approximation because it behaves at the edges that
    small corpora live at: 10/10 yields an interval reaching well below 100%
    instead of the degenerate [1.0, 1.0].

    This previously lived in run_eval.py, where it accepted `confidence` and
    then hard-coded z = 1.96 — so asking for a 99% interval silently returned a
    95% one. z is derived from `confidence` now.
    """
    if total <= 0:
        return 0.0, 0.0
    if not 0.0 < confidence < 1.0:
        raise ValueError(f"confidence must be strictly between 0 and 1, got {confidence}")
    if not 0 <= successes <= total:
        raise ValueError(f"successes must be within [0, {total}], got {successes}")

    z = NormalDist().inv_cdf(1 - (1 - confidence) / 2)
    p = successes / total
    denominator = 1 + z ** 2 / total
    centre = p + z ** 2 / (2 * total)
    margin = z * math.sqrt((p * (1 - p) + z ** 2 / (4 * total)) / total)
    return max(0.0, (centre - margin) / denominator), min(1.0, (centre + margin) / denominator)
