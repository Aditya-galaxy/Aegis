"""
Does the role the customer granted actually permit what Kronagent will do?

Nothing checked. The AWS containment adapter calls `ec2:DescribeInstances` and
`ec2:DescribeNetworkAcls` to capture rollback state *before* it mutates
anything, and the containment policy granted neither. Both actions would have
AccessDenied on their first read — and `ContainmentExecutor` catches that into
`executed=False, error=...`, so containment fails quietly during an incident,
which is the worst possible moment to discover it.

A mocked integration test could never have caught this: `moto` does not enforce
IAM, so `test_provider_containment_moto.py` passes today *despite* the gap. Only
a static comparison between what the adapter calls and what the policy grants
can. That is what this file is.

Two invariants, deliberately separate:

  **A — `plan()` names every API `perform()` will call.** `plan()`'s output is
  what the approval queue shows the human and what `containment.py` writes into
  the hash-chained audit log. When they disagree, the operator authorised a
  narrower action than the one that ran and the signed record understates it —
  the same family of defect `test_provider_execution_honesty.py` exists to
  prevent.

  **B — the contain policy grants every API `perform()` calls.**

A is not redundant with B. My first design derived the required IAM actions from
`plan()` alone; because `plan()`'s `BLOCK_IP` branch omitted
`describe_network_acls`, that would have caught `ec2:DescribeInstances` and
silently missed `ec2:DescribeNetworkAcls` — half the original defect, through
the very test meant to prevent it. **`_perform_sync` is the source of truth.**

WHAT THIS CANNOT CATCH, stated plainly so nobody trusts it further than it goes:
it compares *action names*. It says nothing about whether the `Resource` ARNs
are wide enough or the `Condition` blocks are satisfiable. Two live examples:
`ec2:ModifyInstanceAttribute` is granted on `instance/*` only, and AWS may also
evaluate the security-group ARN when `Groups=` is passed; and the `iam:PolicyName`
conditions are string-equality against names the adapter hardcodes. The second
is cheap to check and is checked below. The first can only be settled by a real
assumed-role drill against a live account.
"""
# SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Aditya Kumar, trading as Kronagent · https://kronagent.com
# Source-available, not open source. Commercial use requires a licence —
# see LICENSE or contact licensing@kronagent.com

from __future__ import annotations

import ast
import re
from pathlib import Path

import pytest

from kronagent.connect import _contain_policy, _observe_policy
from kronagent.policy import action_properties
from kronagent.providers.aws import AwsContainmentAdapter
from kronagent.schemas import ActionClass, ProposedAction

AWS_SOURCE = Path(__file__).resolve().parent.parent / "kronagent" / "providers" / "aws.py"

# The `snake_case` boto3 method → `Service:PascalCase` IAM action rule holds for
# all 15 APIs this adapter and the observe probes use. It is a convention, not a
# law, and AWS breaks it elsewhere: s3.list_objects_v2 → s3:ListBucket,
# s3.list_buckets → s3:ListAllMyBuckets, apigateway.get_rest_api → apigateway:GET.
# Some permissions (iam:PassRole) have no API of their own at all.
#
# Empty today, and that is the point: it records that the derivation below is a
# convention with known counterexamples, so the next person to hit one adds an
# entry here instead of weakening the rule for everyone.
_IAM_ACTION_OVERRIDES: dict[str, str] = {}


def _iam_action(boto3_method: str) -> str:
    """`ec2.describe_network_acls` -> `ec2:DescribeNetworkAcls`."""
    if boto3_method in _IAM_ACTION_OVERRIDES:
        return _IAM_ACTION_OVERRIDES[boto3_method]
    service, _, method = boto3_method.partition(".")
    return f"{service}:" + "".join(p.title() for p in method.split("_"))


def _granted(policy: dict) -> set[str]:
    out: set[str] = set()
    for stmt in policy["Statement"]:
        actions = stmt["Action"]
        out.update([actions] if isinstance(actions, str) else actions)
    return out


# --- What perform() actually calls -------------------------------------------

class _Recorder:
    """One fake boto3 client per service, recording the methods called.

    Returns the minimum response shape `_perform_sync` destructures — anything
    less and the branch raises before reaching its later calls, which would
    silently under-record exactly the reads this file exists to find.
    """

    _RESPONSES = {
        "describe_instances": {
            "Reservations": [{"Instances": [{"SecurityGroups": [{"GroupId": "sg-orig"}]}]}]
        },
        "describe_network_acls": {
            "NetworkAcls": [{"Entries": [{"RuleNumber": 100, "Egress": False},
                                         {"RuleNumber": 100, "Egress": True}]}]
        },
    }

    def __init__(self) -> None:
        self.calls: list[str] = []

    def for_service(self, service: str) -> "_ServiceStub":
        return _ServiceStub(self, service)


class _ServiceStub:
    def __init__(self, rec: _Recorder, service: str) -> None:
        self._rec, self._service = rec, service

    def __getattr__(self, method: str):
        def _call(**kwargs):
            self._rec.calls.append(f"{self._service}.{method}")
            return _Recorder._RESPONSES.get(method, {})
        return _call


# Minimum viable inputs per action class. Kept as data so the coverage guard
# below can assert this table has not fallen behind the adapter.
_CONTAIN_ACTIONS: dict[ActionClass, dict] = {
    ActionClass.DISABLE_ACCESS_KEY: {"target": "AKIAEXAMPLE",
                                     "parameters": {"user_name": "alice"}},
    ActionClass.ATTACH_DENY_ALL_TO_PRINCIPAL: {"target": "alice"},
    ActionClass.ISOLATE_INSTANCE_SG: {"target": "i-0abc"},
    ActionClass.BLOCK_IP: {"target": "203.0.113.7"},
    ActionClass.REVOKE_ROLE_SESSIONS: {"target": "AppRole"},
    ActionClass.TERMINATE_INSTANCE: {"target": "i-0abc"},
}


def _adapter() -> AwsContainmentAdapter:
    return AwsContainmentAdapter(
        region="us-east-1",
        quarantine_security_group_id="sg-quarantine",
        quarantine_nacl_id="acl-quarantine",
    )


def _action(ac: ActionClass) -> ProposedAction:
    spec = _CONTAIN_ACTIONS[ac]
    return ProposedAction(provider="aws", action_class=ac, target=spec["target"],
                          rationale="invariant test",
                          parameters=spec.get("parameters", {}))


def _recorded_calls(ac: ActionClass) -> list[str]:
    """Every boto3 method `_perform_sync` calls for one action class.

    `_aws_call` is patched out as well as `_client`: it does
    `from botocore.exceptions import ClientError`, and the core CI job installs
    no cloud SDK on purpose. Patching both means this invariant runs in BOTH CI
    jobs. It is a pure-data property about our own source and must never skip —
    an `importorskip` here would turn the guard off in the very job that proves
    the package works without AWS installed.
    """
    adapter, rec = _adapter(), _Recorder()
    adapter._client = lambda service, tenant_id="default": rec.for_service(service)
    adapter._aws_call = lambda fn, *a, **kw: fn(*a, **kw)
    adapter._perform_sync(_action(ac))
    return rec.calls


def _api_names(text: str) -> set[str]:
    """Pull `service.method` out of plan()'s human-readable call strings."""
    return set(re.findall(r"\b([a-z0-9]+\.[a-z_]+)\(", text))


def _planned_calls(ac: ActionClass) -> set[str]:
    calls, rollback, _ = _adapter().plan(_action(ac))
    # The rollback runs under the same role and needs the same grant.
    # iam.delete_user_policy and ec2.delete_network_acl_entry appear ONLY there.
    return _api_names(" ".join(calls) + " " + rollback)


# --- Coverage guard ----------------------------------------------------------

def _action_classes_in_perform_sync() -> set[ActionClass]:
    """Parse `_perform_sync` with `ast` for the classes it handles.

    AST rather than a regex on purpose: this repo has already had a string-match
    invariant that a mutation test proved worthless because the import line
    alone satisfied it.
    """
    tree = ast.parse(AWS_SOURCE.read_text(encoding="utf-8"), filename=str(AWS_SOURCE))
    fn = next(n for n in ast.walk(tree)
              if isinstance(n, ast.FunctionDef) and n.name == "_perform_sync")
    return {
        ActionClass[node.attr]
        for node in ast.walk(fn)
        if isinstance(node, ast.Attribute)
        and isinstance(node.value, ast.Name)
        and node.value.id == "ActionClass"
        and node.attr in ActionClass.__members__
    }


def test_contain_action_table_covers_every_implemented_action():
    """Mirrors `test_probe_table_covers_every_registered_provider`.

    An action implemented in `_perform_sync` but missing from `_CONTAIN_ACTIONS`
    would skip both invariants below — a new containment action could ship with
    no grant at all and nothing would say so.
    """
    assert set(_CONTAIN_ACTIONS) == _action_classes_in_perform_sync()


# --- Invariant A: plan() tells the truth -------------------------------------

@pytest.mark.parametrize("ac", sorted(_CONTAIN_ACTIONS, key=lambda a: a.value))
def test_plan_names_every_api_perform_will_call(ac: ActionClass):
    """What the human approves must be what runs.

    `plan()`'s `api_calls` are shown in the approval queue and written into the
    hash-chained audit log. An API called but never planned means the operator
    authorised a narrower action than the one performed, and the signed record
    understates what Kronagent did to the customer's account.
    """
    missing = set(_recorded_calls(ac)) - _planned_calls(ac)
    assert not missing, (
        f"{ac.value}: perform() calls {sorted(missing)}, which plan() never "
        f"mentions. Add it to the planned api_calls — the operator and the "
        f"audit record are entitled to the whole list."
    )


# --- Invariant B: the grant is sufficient ------------------------------------

_DELIBERATELY_UNGRANTED: dict[ActionClass, str] = {
    ActionClass.TERMINATE_INSTANCE:
        "The contain policy omits ec2:TerminateInstances on purpose: the point "
        "of a separate stack is that the customer reads what they are granting, "
        "and most will not want an irreversible action in it at all. That is "
        "only safe because the policy engine classifies terminate destructive, "
        "so it can never auto-execute — asserted below rather than assumed.",
}


def test_every_exemption_is_backed_by_the_destructive_classification():
    """An exemption tied to a real guarantee, not a free pass.

    If anyone ever reclassifies TERMINATE_INSTANCE as non-destructive, the
    reason this action may go ungranted evaporates — and this fires alongside
    `test_policy_consistency.py`, which is exactly right.
    """
    for ac in _DELIBERATELY_UNGRANTED:
        assert action_properties(ac)["destructive"] is True, (
            f"{ac.value} is exempt from the grant check because it is "
            f"destructive and therefore can never auto-execute. It is no longer "
            f"classified destructive, so the exemption is no longer safe."
        )


@pytest.mark.parametrize("ac", sorted(_CONTAIN_ACTIONS, key=lambda a: a.value))
def test_contain_policy_grants_every_api_the_adapter_calls(ac: ActionClass):
    granted = _granted(_contain_policy("123456789012", "us-east-1", "acl-quarantine"))
    needed = {_iam_action(c) for c in _recorded_calls(ac)}

    if ac in _DELIBERATELY_UNGRANTED:
        pytest.skip(_DELIBERATELY_UNGRANTED[ac])

    missing = needed - granted
    assert not missing, (
        f"{ac.value}: the contain policy does not grant {sorted(missing)}, so "
        f"this action AccessDenies against a role installed from our own "
        f"template — and ContainmentExecutor swallows that into "
        f"executed=False, so it fails quietly mid-incident."
    )


@pytest.mark.parametrize("grant_name", ["observe", "contain"])
def test_each_policy_grants_every_permission_its_own_preflight_probes(grant_name):
    """A probe the role cannot make reports as a missing permission forever.

    Preflight used the observe probe table for BOTH grants. Since the contain
    policy granted none of those, a correctly installed contain role reported
    three missing permissions and DEGRADED — permanently, and with no way for
    the customer to fix it.
    """
    from kronagent.connect import _CONTAIN_PROBES, _OBSERVE_PROBES

    probes, policy = (
        (_OBSERVE_PROBES, _observe_policy())
        if grant_name == "observe"
        else (_CONTAIN_PROBES,
              _contain_policy("123456789012", "us-east-1", "acl-1", "sg-1"))
    )
    missing = {perm for perm, _, _ in probes} - _granted(policy)
    assert not missing, (
        f"the {grant_name} policy does not grant {sorted(missing)}, which its "
        f"own preflight probes. Every such probe fails, so the connection can "
        f"never report healthy."
    )


def test_the_account_mismatch_guard_has_an_oracle_under_every_grant():
    """The check that containment can only touch the account whose finding
    produced it reads the account back with sts:GetCallerIdentity. A grant that
    does not permit it leaves that check with nothing to compare — dead, while
    still appearing in the source."""
    for name, policy in (
        ("observe", _observe_policy()),
        ("contain", _contain_policy("123456789012", "us-east-1", "acl-1", "sg-1")),
    ):
        assert "sts:GetCallerIdentity" in _granted(policy), (
            f"the {name} policy does not grant sts:GetCallerIdentity, so "
            f"preflight cannot read back an account id and the mismatch guard "
            f"silently has nothing to compare."
        )


# --- The value mismatch a name check cannot see ------------------------------

def _inline_policy_names_written() -> set[str]:
    """Every `PolicyName="..."` literal `_perform_sync` writes."""
    tree = ast.parse(AWS_SOURCE.read_text(encoding="utf-8"), filename=str(AWS_SOURCE))
    fn = next(n for n in ast.walk(tree)
              if isinstance(n, ast.FunctionDef) and n.name == "_perform_sync")
    return {
        kw.value.value
        for node in ast.walk(fn) if isinstance(node, ast.Call)
        for kw in node.keywords
        if kw.arg == "PolicyName" and isinstance(kw.value, ast.Constant)
    }


def test_inline_policy_names_match_the_condition_that_gates_them():
    """Invariant B compares action names and would pass with a wrong value here.

    The iam:PutUserPolicy / iam:PutRolePolicy grants are scoped by a
    StringEquals condition on the inline policy's *name*. Write a different name
    than the condition pins and the call is denied — with the action granted, so
    every name-level check still reports the policy complete.
    """
    policy = _contain_policy("123456789012", "us-east-1", "acl-quarantine")
    pinned = {
        stmt["Condition"]["StringEquals"]["iam:PolicyName"]
        for stmt in policy["Statement"]
        if "Condition" in stmt
        and "iam:PolicyName" in stmt.get("Condition", {}).get("StringEquals", {})
    }
    written = _inline_policy_names_written()
    assert written, "no PolicyName literals found — has _perform_sync moved?"
    assert written <= pinned, (
        f"the adapter writes inline policies named {sorted(written - pinned)}, "
        f"but the contain policy only permits {sorted(pinned)}. These calls are "
        f"denied even though the action itself is granted."
    )


# --- The same property, against the template the customer actually installs ---
#
# Everything above tests `_contain_policy()`. That is the policy rendered for
# the download + `aws cloudformation deploy` path. It is NOT the file in
# deploy/cloudformation/, which is a second, hand-maintained copy — and the two
# had already drifted: the committed template pinned the revoke-sessions inline
# policy to a name the adapter never writes, so that action was denied for
# anyone who installed it, with the IAM action itself correctly granted.
#
# These tests apply the invariants to the committed artifact. Collapsing the two
# sources into one renderer is separate work; until then this is what stops the
# hosted grant and the CLI grant from meaning different things.

CFN_CONTAIN = (Path(__file__).resolve().parent.parent
               / "deploy" / "cloudformation" / "kronagent-contain-role.json")


def _committed_contain_policy() -> dict:
    import json
    doc = json.loads(CFN_CONTAIN.read_text(encoding="utf-8"))
    role = doc["Resources"]["KronagentContainRole"]["Properties"]
    return role["Policies"][0]["PolicyDocument"]


@pytest.mark.parametrize("ac", sorted(_CONTAIN_ACTIONS, key=lambda a: a.value))
def test_committed_template_grants_every_api_the_adapter_calls(ac: ActionClass):
    """A customer who installs our published template must get a working role."""
    if ac in _DELIBERATELY_UNGRANTED:
        pytest.skip(_DELIBERATELY_UNGRANTED[ac])

    missing = {_iam_action(c) for c in _recorded_calls(ac)} - _granted(
        _committed_contain_policy())
    assert not missing, (
        f"{ac.value}: deploy/cloudformation/kronagent-contain-role.json does not "
        f"grant {sorted(missing)}. A customer installing our own template gets a "
        f"role that cannot perform this action."
    )


def test_committed_template_pins_the_policy_names_the_adapter_writes():
    """D4, as a test. The template pinned 'kronagent-revoke-sessions-deny-all';
    the adapter writes 'kronagent-revoke-sessions'. Denied, silently, with the
    action granted — invisible to every action-name check."""
    pinned = {
        stmt["Condition"]["StringEquals"]["iam:PolicyName"]
        for stmt in _committed_contain_policy()["Statement"]
        if "iam:PolicyName" in stmt.get("Condition", {}).get("StringEquals", {})
    }
    unwritable = _inline_policy_names_written() - pinned
    assert not unwritable, (
        f"the adapter writes inline policies named {sorted(unwritable)}, which "
        f"the committed template does not permit: {sorted(pinned)}."
    )


def test_the_two_contain_policies_grant_the_same_actions():
    """The disease behind D3, D4 and the NACL-scope drift, named directly.

    One IAM grant maintained as two hand-written copies will diverge; these two
    already had, three separate ways. Until they render from one source, assert
    they at least mean the same thing.
    """
    rendered = _granted(_contain_policy("123456789012", "us-east-1", "acl-quarantine"))
    committed = _granted(_committed_contain_policy())
    assert rendered == committed, (
        f"only in the rendered policy: {sorted(rendered - committed)}; "
        f"only in the committed template: {sorted(committed - rendered)}"
    )


def test_the_committed_template_scopes_what_can_be_scoped():
    """`Resource: "*"` on a mutation is how a least-privilege claim quietly stops
    being true.

    The NACL statement granted `"*"` — every network ACL in the customer's
    account — while `deploy/README.md` told the reader it was "pinned by ARN to
    the single quarantine NACL. Kronagent cannot modify any other NACL." The
    parameter needed to pin it was already declared and simply never referenced.

    EC2 `Describe*` genuinely does not support resource-level permissions, so
    that one statement is exempt by name rather than by pattern.
    """
    # Exempt by Sid, never by pattern. Both are read-only actions AWS genuinely
    # does not support resource-level permissions for; a pattern-based exemption
    # would quietly cover the next mutation someone grants on "*".
    wildcard_ok = {"ReadStateForRollbackCapture", "ConfirmOwnIdentity"}
    offenders = [
        stmt["Sid"] for stmt in _committed_contain_policy()["Statement"]
        if stmt.get("Resource") == "*" and stmt["Sid"] not in wildcard_ok
    ]
    assert not offenders, (
        f"these statements grant a mutation across the whole account: "
        f"{offenders}. Scope them to the specific resource, or add the Sid to "
        f"wildcard_ok with the AWS documentation showing resource-level "
        f"permissions are unsupported for that action."
    )


def test_every_declared_template_parameter_is_referenced():
    """A parameter the template never uses asks the customer for a value that
    changes nothing — and reads, to anyone reviewing the grant, as a scope that
    is being applied when it is not."""
    import json

    doc = json.loads(CFN_CONTAIN.read_text(encoding="utf-8"))
    declared = set(doc.get("Parameters", {}))
    body = json.dumps(doc["Resources"])
    unused = {p for p in declared if p not in body}
    assert not unused, (
        f"declared but never referenced: {sorted(unused)}. Wire them into the "
        f"policy or remove them — an ignored parameter looks like a constraint."
    )


# --- The third copy ----------------------------------------------------------
#
# deploy/kronagent-iam-policy.json is a third hand-maintained copy of the same
# grant, attached directly by operators following deploy/README.md §3. It had
# both of the original gaps too. Any consolidation that merges only two of the
# three leaves the drift alive, so all three are checked here until they render
# from one source.

STANDALONE_POLICY = (Path(__file__).resolve().parent.parent
                     / "deploy" / "kronagent-iam-policy.json")


@pytest.mark.parametrize("ac", sorted(_CONTAIN_ACTIONS, key=lambda a: a.value))
def test_standalone_iam_policy_grants_every_api_the_adapter_calls(ac: ActionClass):
    import json

    granted = _granted(json.loads(STANDALONE_POLICY.read_text(encoding="utf-8")))
    missing = {_iam_action(c) for c in _recorded_calls(ac)} - granted
    # Unlike the two role templates, this one is documented as including
    # terminate, so there is no exemption here.
    assert not missing, (
        f"{ac.value}: deploy/kronagent-iam-policy.json does not grant "
        f"{sorted(missing)}. An operator attaching it per deploy/README.md gets "
        f"a role that cannot perform this action."
    )


def test_modify_instance_attribute_names_the_quarantine_security_group():
    """AWS evaluates ModifyInstanceAttribute against the security group named in
    `Groups=` as well as the instance, so an instance-only Resource denies the
    call while every action-name check still reports the grant complete.

    This is the class of gap the invariants above explicitly cannot see — it is
    a resource-ARN omission, not a missing action — so it is asserted directly
    in all three policy copies.
    """
    import json

    def _resources(policy: dict, sid_contains: str) -> str:
        for stmt in policy["Statement"]:
            if sid_contains in stmt["Sid"]:
                return json.dumps(stmt.get("Resource"))
        raise AssertionError(f"no statement matching {sid_contains!r}")

    sources = {
        "rendered": _contain_policy("123456789012", "us-east-1", "acl-1", "sg-1"),
        "cloudformation": _committed_contain_policy(),
        "standalone": json.loads(STANDALONE_POLICY.read_text(encoding="utf-8")),
    }
    for name, policy in sources.items():
        resources = _resources(policy, "IsolateEc2Instance"
                               if name == "cloudformation"
                               else "IsolateInstanceIntoQuarantineSG")
        assert "security-group" in resources, (
            f"{name}: ec2:ModifyInstanceAttribute is granted on the instance "
            f"only. AWS also evaluates the security-group ARN, so isolation "
            f"AccessDenies with the action apparently granted."
        )
