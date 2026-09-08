"""
The cloud drill arms deliberately, and covers what the adapter implements.

`run_cloud_drill.py` creates and deletes real IAM users, roles, network ACLs and
EC2 instances. It used to decide whether to do that by *sniffing for
credentials*: if `sts:GetCallerIdentity` succeeded, it went live. A developer's
shell almost always has credentials, and they are frequently pointed at
production, so `kronagent-cloud-drill` — a command whose name suggests a
rehearsal — would create IAM users in whatever account happened to be current.

Having credentials is not consenting to have resources created with them.

The drill also matters for a second reason. `tests/test_grant_sufficiency.py`
compares IAM *action names* and says plainly that it cannot see whether a
`Resource` ARN is wide enough. `ec2:ModifyInstanceAttribute` is the live
example: AWS evaluates it against the security group named in `Groups=` as well
as the instance. This drill is the only thing that settles that, so a drill
that has quietly fallen behind the adapter is worth failing a build over.
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

REPO = Path(__file__).resolve().parent.parent
DRILL = REPO / "run_cloud_drill.py"


def _installed(mod: str) -> bool:
    import importlib.util
    return importlib.util.find_spec(mod) is not None


# The drill is an AWS tool and imports boto3 at module scope, so RUNNING it
# needs the [aws] extra and moto. Only the behavioural tests are gated on that.
#
# The structural tests below deliberately are NOT: they parse the source and
# assert the arming property, which is a claim about our own code that must hold
# in the core CI job too. Gating the whole file would have switched off the
# safety guard in the job most likely to run without cloud SDKs.
needs_aws = pytest.mark.skipif(
    not (_installed("boto3") and _installed("moto")),
    reason="running the drill needs boto3 and moto ([aws] and [dev] extras)")


def _source() -> str:
    return DRILL.read_text(encoding="utf-8")


# --- Arming ------------------------------------------------------------------

@needs_aws
def test_live_mode_requires_an_explicit_environment_variable():
    """`--live` alone must not be enough, and neither must credentials."""
    res = subprocess.run(
        [sys.executable, str(DRILL), "--live"],
        cwd=REPO, capture_output=True, text=True,
        env={"PATH": "/usr/bin:/bin", "HOME": "/tmp"},
    )
    assert res.returncode == 2, res.stdout + res.stderr
    assert "KRONAGENT_CLOUD_DRILL_ARM" in res.stdout
    assert "CREATES AND DELETES real" in res.stdout


@needs_aws
def test_the_refusal_names_the_account_it_would_have_touched():
    """"Set this variable" is not enough on its own. The question the old
    behaviour never let anyone ask is *which account*, so the refusal answers
    it before they arm anything."""
    res = subprocess.run(
        [sys.executable, str(DRILL), "--live"],
        cwd=REPO, capture_output=True, text=True,
        env={"PATH": "/usr/bin:/bin", "HOME": "/tmp"},
    )
    assert "Credentials currently reach account:" in res.stdout


def test_no_path_from_credential_presence_alone_to_a_live_run():
    """Structural, because the behavioural test above can only prove that one
    entry point refuses. Nothing anywhere may branch to a live drill on the
    result of a credential check.
    """
    tree = ast.parse(_source(), filename=str(DRILL))

    live_calls = [
        node for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and getattr(node.func, "id", "") == "run_drill"
        for kw in node.keywords
        if kw.arg == "mock_mode" and getattr(kw.value, "value", None) is False
    ]
    assert live_calls, "no live run_drill call found — has the drill moved?"

    # Every live call must sit under a branch testing _armed(...).
    for call in live_calls:
        guarded = any(
            isinstance(n, ast.If)
            and any(getattr(c.func, "id", "") == "_armed"
                    for c in ast.walk(n.test) if isinstance(c, ast.Call))
            and call in list(ast.walk(n))
            for n in ast.walk(tree)
        )
        assert guarded, (
            "a live drill is reachable without passing through _armed(). "
            "Credential presence is not consent.")


@needs_aws
def test_simulation_is_the_default():
    """Running it with no arguments must touch nothing real."""
    res = subprocess.run(
        [sys.executable, str(DRILL)],
        cwd=REPO, capture_output=True, text=True)
    assert res.returncode == 0, res.stdout + res.stderr
    assert "SIMULATION mode" in res.stdout
    assert "Nothing real is touched" in res.stdout


# --- Coverage ----------------------------------------------------------------

def _drilled_action_classes() -> set[str]:
    """Every ActionClass the drill actually performs."""
    tree = ast.parse(_source(), filename=str(DRILL))
    return {
        node.attr
        for call in ast.walk(tree)
        if isinstance(call, ast.Call)
        and getattr(call.func, "id", "") == "ProposedAction"
        for kw in call.keywords if kw.arg == "action_class"
        for node in ast.walk(kw.value)
        if isinstance(node, ast.Attribute)
        and getattr(node.value, "id", "") == "ActionClass"
    }


# Exempt by name, with the reason, so adding a seventh action class forces a
# decision rather than silently inheriting an exemption.
_NOT_DRILLED = {
    "TERMINATE_INSTANCE":
        "Irreversible, so there is no rollback to verify — the drill's whole "
        "shape is execute/verify/roll back/verify. The contain policy also "
        "omits ec2:TerminateInstances deliberately, so under --tenant this "
        "would correctly be denied and the drill would be asserting the "
        "opposite of what it looks like it asserts.",
}


def test_the_drill_covers_every_action_the_adapter_implements():
    """A drill that has fallen behind the adapter proves less than it claims.

    Keyed off the same AST scan of `_perform_sync` that
    `test_grant_sufficiency.py` uses, so a new containment action fails here
    until it is either drilled or exempted with a reason.
    """
    import importlib.util

    spec = importlib.util.spec_from_file_location(
        "_grant_sufficiency", Path(__file__).parent / "test_grant_sufficiency.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)

    implemented = {ac.name for ac in mod._action_classes_in_perform_sync()}
    undrilled = implemented - _drilled_action_classes() - set(_NOT_DRILLED)
    assert not undrilled, (
        f"the adapter implements {sorted(undrilled)} but the drill never "
        f"performs them, so nothing checks whether the granted Resource ARNs "
        f"and Conditions actually permit them against a real account. Add a "
        f"drill, or an entry to _NOT_DRILLED saying why not.")


def test_every_drill_exemption_still_names_a_real_action():
    """A stale exemption is a hole that widens what the coverage check allows."""
    from kronagent.schemas import ActionClass

    unknown = set(_NOT_DRILLED) - set(ActionClass.__members__)
    assert not unknown, f"exempted but no longer an ActionClass: {sorted(unknown)}"


@needs_aws
def test_drill_results_are_machine_readable(tmp_path):
    """So a future CI job can assert on outcomes rather than grepping stdout."""
    import json

    out = tmp_path / "results.json"
    res = subprocess.run(
        [sys.executable, str(DRILL), "--json", str(out)],
        cwd=REPO, capture_output=True, text=True)
    assert res.returncode == 0, res.stdout + res.stderr

    results = json.loads(out.read_text(encoding="utf-8"))
    assert results, "no results recorded"
    for action, detail in results.items():
        assert detail["ok"] is True, f"{action}: {detail}"
        # Executing is not the claim. Verifying by an independent read, rolling
        # back, and verifying the rollback is the claim.
        for key in ("executed", "verified", "rolled_back", "rollback_verified"):
            assert detail[key] is True, f"{action} did not record {key}"


@needs_aws
@pytest.mark.parametrize("action", [
    "attach_deny_all_to_principal",
    "disable_access_key",
    "block_ip",
    "revoke_role_sessions",
])
def test_each_drill_verifies_and_rolls_back(action, tmp_path):
    import json

    out = tmp_path / "r.json"
    subprocess.run([sys.executable, str(DRILL), "--json", str(out)],
                   cwd=REPO, capture_output=True, text=True, check=True)
    assert json.loads(out.read_text(encoding="utf-8"))[action]["ok"] is True
