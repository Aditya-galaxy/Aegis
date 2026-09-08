"""
Tests for tenant cloud connection: External ID, CloudFormation rendering,
role assumption and preflight.

The load-bearing test in here is `test_observe_policy_contains_no_write_actions`.
The product's central claim — "it cannot touch anything until you decide it has
earned that" — is only true if the read-only grant really is read-only. That is
an invariant, not a code comment, so it is asserted.
"""
# SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Aditya Kumar, trading as Kronagent · https://kronagent.com
# Source-available, not open source. Commercial use requires a licence —
# see LICENSE or contact licensing@kronagent.com

from __future__ import annotations

import importlib.util
import json
import os
import stat
import urllib.parse
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock

import pytest

from kronagent.connect import (
    AwsConnection,
    ConnectionState,
    ConnectionStore,
    CredentialBroker,
    Grant,
    PreflightResult,
    _observe_policy,
    launch_stack_url,
    new_external_id,
    preflight,
    render_template,
    template_json,
)

def _installed(module: str) -> bool:
    try:
        return importlib.util.find_spec(module) is not None
    except (ModuleNotFoundError, ImportError, ValueError):
        return False


# These monkeypatch boto3.client, which means importing boto3 first. The core
# install ships without it by design; the all-extras CI job is where they run.
requires_boto3 = pytest.mark.skipif(not _installed("boto3"), reason="needs the [aws] extra")

KRONAGENT_ACCOUNT = "999988887777"
CUSTOMER_ACCOUNT = "123456789012"


def _conn(**over) -> AwsConnection:
    base = dict(
        tenant_id="acme",
        account_id=CUSTOMER_ACCOUNT,
        region="us-east-1",
        external_id=new_external_id(),
        observe_role_arn=f"arn:aws:iam::{CUSTOMER_ACCOUNT}:role/KronagentObserveRole",
    )
    base.update(over)
    return AwsConnection(**base)


# --------------------------------------------------------------------------- #
# External ID
# --------------------------------------------------------------------------- #

def test_external_ids_are_unique_and_unguessable() -> None:
    ids = {new_external_id() for _ in range(500)}
    assert len(ids) == 500
    assert all(len(i) >= 32 for i in ids)


def test_external_id_is_validated() -> None:
    with pytest.raises(ValueError, match="external_id"):
        _conn(external_id="short")


@pytest.mark.parametrize("bad", ["1234", "12345678901234", "abcdefghijkl", ""])
def test_account_id_must_be_twelve_digits(bad) -> None:
    with pytest.raises(ValueError, match="12 digits"):
        _conn(account_id=bad)


@pytest.mark.parametrize("bad", ["useast1", "US-EAST-1", "somewhere", ""])
def test_region_is_validated(bad) -> None:
    # Interpolated into ARNs and into a console URL handed to a browser.
    with pytest.raises(ValueError, match="region"):
        _conn(region=bad)


# --------------------------------------------------------------------------- #
# The separation of read from write — the product's central claim
# --------------------------------------------------------------------------- #

_WRITE_VERB_PREFIXES = (
    "Create", "Delete", "Modify", "Update", "Put", "Attach", "Detach",
    "Terminate", "Stop", "Start", "Revoke", "Disable", "Enable", "Remove",
    "Set", "Associate", "Disassociate", "Run", "Reboot", "Replace",
)


def test_observe_policy_contains_no_write_actions() -> None:
    """The whole onboarding pitch rests on this being true.

    If a write action ever appears in the observe grant, "this grant cannot
    alter your account" becomes a false statement made to a customer during a
    security review.
    """
    actions: list[str] = []
    for stmt in _observe_policy()["Statement"]:
        a = stmt["Action"]
        actions.extend(a if isinstance(a, list) else [a])

    offenders = [
        act for act in actions
        if act.split(":", 1)[1].startswith(_WRITE_VERB_PREFIXES)
    ]
    assert not offenders, f"write actions found in the read-only grant: {offenders}"

    # Positive form: every action must be a read verb.
    assert all(
        act.split(":", 1)[1].startswith(("Get", "List", "Describe"))
        for act in actions
    ), actions


def test_observe_policy_effect_is_always_allow_never_wildcard_action() -> None:
    for stmt in _observe_policy()["Statement"]:
        assert stmt["Effect"] == "Allow"
        acts = stmt["Action"] if isinstance(stmt["Action"], list) else [stmt["Action"]]
        assert "*" not in acts, "a bare wildcard action defeats the point of the grant"


def test_containment_grant_omits_terminate_by_default() -> None:
    """Terminate is irreversible. It can never auto-execute, but the customer
    should not have to grant it merely to use containment at all."""
    tpl = render_template(_conn(), Grant.CONTAIN, kronagent_account_id=KRONAGENT_ACCOUNT)
    body = json.dumps(tpl)
    assert "TerminateInstances" not in body


def test_can_contain_is_false_until_the_second_stack_is_installed() -> None:
    c = _conn()
    assert c.can_contain is False
    with pytest.raises(ValueError, match="has not granted containment"):
        c.role_arn(Grant.CONTAIN)

    c2 = _conn(contain_role_arn=f"arn:aws:iam::{CUSTOMER_ACCOUNT}:role/KronagentContainRole")
    assert c2.can_contain is True


# --------------------------------------------------------------------------- #
# Trust policy — the confused-deputy defence
# --------------------------------------------------------------------------- #

def test_trust_policy_pins_the_external_id() -> None:
    conn = _conn()
    tpl = render_template(conn, Grant.OBSERVE, kronagent_account_id=KRONAGENT_ACCOUNT)
    trust = tpl["Resources"]["KronagentRole"]["Properties"]["AssumeRolePolicyDocument"]
    stmt = trust["Statement"][0]

    assert stmt["Principal"]["AWS"] == f"arn:aws:iam::{KRONAGENT_ACCOUNT}:root"
    assert stmt["Condition"]["StringEquals"]["sts:ExternalId"] == conn.external_id


def test_two_tenants_get_different_external_ids_in_their_templates() -> None:
    """Without this, any Kronagent customer could assume any other's role."""
    a, b = _conn(tenant_id="a"), _conn(tenant_id="b")
    ta = render_template(a, Grant.OBSERVE, kronagent_account_id=KRONAGENT_ACCOUNT)
    tb = render_template(b, Grant.OBSERVE, kronagent_account_id=KRONAGENT_ACCOUNT)
    cond = lambda t: (t["Resources"]["KronagentRole"]["Properties"]
                       ["AssumeRolePolicyDocument"]["Statement"][0]
                       ["Condition"]["StringEquals"]["sts:ExternalId"])
    assert cond(ta) != cond(tb)


def test_containment_policy_is_scoped_to_the_customer_account_and_region() -> None:
    conn = _conn(region="eu-west-2")
    tpl = render_template(conn, Grant.CONTAIN, kronagent_account_id=KRONAGENT_ACCOUNT,
                          quarantine_nacl_id="acl-0abc", quarantine_sg_id="sg-0def")
    doc = tpl["Resources"]["KronagentRole"]["Properties"]["Policies"][0]["PolicyDocument"]

    # A statement's Resource may be a string or a list; every ARN in either must
    # name the customer's account. Read-only Describe* is the one exemption, and
    # it is exempt by Sid rather than by pattern: EC2 Describe* genuinely has no
    # resource-level permissions, and a pattern-based exemption would quietly
    # cover the next mutation someone grants on "*".
    read_only = {"ReadStateForRollbackCapture"}
    mutations = [s for s in doc["Statement"] if s["Sid"] not in read_only]
    arns = [a for s in mutations
            for a in ([s["Resource"]] if isinstance(s["Resource"], str)
                      else s["Resource"])]

    assert arns, "no mutating statements found — has the policy moved?"
    assert all(CUSTOMER_ACCOUNT in a for a in arns), arns
    assert all("*" != a for a in arns), f"unscoped mutation: {arns}"
    assert any("eu-west-2" in a for a in arns)

    # The NACL statement must be pinned to one ACL, not every ACL in the account.
    nacl = [a for a in arns if "network-acl" in a][0]
    assert nacl.endswith("acl-0abc")

    # ...and the isolate statement to one security group, for the same reason:
    # AWS evaluates ModifyInstanceAttribute against the SG named in Groups=, so
    # this ARN is both required for the call to work and the thing that stops
    # the role moving an instance into any group it likes.
    sg = [a for a in arns if "security-group" in a][0]
    assert sg.endswith("sg-0def")


def test_template_is_valid_json_and_readable() -> None:
    body = template_json(_conn(), Grant.OBSERVE, kronagent_account_id=KRONAGENT_ACCOUNT)
    parsed = json.loads(body)
    assert parsed["AWSTemplateFormatVersion"] == "2010-09-09"
    assert "\n  " in body, "template should be indented — the customer has to read it"


# --------------------------------------------------------------------------- #
# Launch URL
# --------------------------------------------------------------------------- #

def _console_params(url: str) -> dict[str, list[str]]:
    """The CloudFormation console is a single-page app, so its parameters live
    *inside* the fragment rather than in the query string. Parsing `.query`
    finds only `region=` and misses everything that matters."""
    fragment = urllib.parse.urlparse(url).fragment
    _, _, qs = fragment.partition("?")
    return urllib.parse.parse_qs(qs)


def test_launch_url_targets_the_connection_region_and_prefills_the_template() -> None:
    conn = _conn(region="ap-south-1")
    url = launch_stack_url(conn, Grant.OBSERVE,
                           template_url="https://s3.amazonaws.com/kronagent/observe.json")
    assert "ap-south-1.console.aws.amazon.com" in url

    q = _console_params(url)
    assert q["templateURL"] == ["https://s3.amazonaws.com/kronagent/observe.json"]
    assert q["stackName"] == ["kronagent-observe"]


def test_launch_url_puts_params_in_the_fragment_not_the_query_string() -> None:
    """Regression guard. Params in the real query string produce a link that
    opens an empty stack wizard — indistinguishable from working until the
    customer wonders what to paste."""
    url = launch_stack_url(_conn(), Grant.CONTAIN,
                           template_url="https://s3.amazonaws.com/kronagent/contain.json")
    parsed = urllib.parse.urlparse(url)
    assert "templateURL" not in parsed.query
    assert "templateURL" in parsed.fragment
    assert _console_params(url)["stackName"] == ["kronagent-contain"]


@pytest.mark.parametrize("bad", [
    "http://s3.amazonaws.com/t.json",
    "file:///tmp/t.json",
    "s3://bucket/t.json",
])
def test_launch_url_rejects_non_https_templates(bad) -> None:
    """The console fetches this from the customer's browser; anything but https
    either fails to load or is a downgrade."""
    with pytest.raises(ValueError, match="https"):
        launch_stack_url(_conn(), Grant.OBSERVE, template_url=bad)


# --------------------------------------------------------------------------- #
# Credential broker
# --------------------------------------------------------------------------- #

def _sts_response(expires_in_minutes: int = 60) -> dict:
    return {"Credentials": {
        "AccessKeyId": "ASIAEXAMPLE",
        "SecretAccessKey": "secret",
        "SessionToken": "token",
        "Expiration": datetime.now(timezone.utc) + timedelta(minutes=expires_in_minutes),
    }}


def test_assume_role_passes_the_external_id_and_names_the_session() -> None:
    broker = CredentialBroker()
    sts = MagicMock()
    sts.assume_role.return_value = _sts_response()
    broker._sts = sts

    conn = _conn()
    broker.credentials(conn, Grant.OBSERVE)

    kwargs = sts.assume_role.call_args.kwargs
    assert kwargs["ExternalId"] == conn.external_id
    assert kwargs["RoleArn"] == conn.observe_role_arn
    # The session name lands in the customer's CloudTrail — it should identify
    # the tenant and the grant without them having to ask us.
    assert "acme" in kwargs["RoleSessionName"]
    assert "observe" in kwargs["RoleSessionName"]


def test_credentials_are_cached_not_reassumed_every_call() -> None:
    broker = CredentialBroker()
    sts = MagicMock()
    sts.assume_role.return_value = _sts_response()
    broker._sts = sts

    conn = _conn()
    for _ in range(10):
        broker.credentials(conn, Grant.OBSERVE)
    assert sts.assume_role.call_count == 1


def test_credentials_are_refreshed_before_they_expire() -> None:
    """A credential that dies mid-containment is worse than a slightly early
    refresh, so anything inside the margin counts as stale."""
    broker = CredentialBroker()
    sts = MagicMock()
    sts.assume_role.return_value = _sts_response(expires_in_minutes=2)
    broker._sts = sts

    conn = _conn()
    broker.credentials(conn, Grant.OBSERVE)
    broker.credentials(conn, Grant.OBSERVE)
    assert sts.assume_role.call_count == 2


def test_observe_and_contain_are_cached_separately() -> None:
    broker = CredentialBroker()
    sts = MagicMock()
    sts.assume_role.return_value = _sts_response()
    broker._sts = sts

    conn = _conn(contain_role_arn=f"arn:aws:iam::{CUSTOMER_ACCOUNT}:role/KronagentContainRole")
    broker.credentials(conn, Grant.OBSERVE)
    broker.credentials(conn, Grant.CONTAIN)
    assert sts.assume_role.call_count == 2
    assert {c.kwargs["RoleArn"] for c in sts.assume_role.call_args_list} == {
        conn.observe_role_arn, conn.contain_role_arn
    }


def test_invalidate_forces_a_fresh_assume() -> None:
    broker = CredentialBroker()
    sts = MagicMock()
    sts.assume_role.return_value = _sts_response()
    broker._sts = sts

    conn = _conn()
    broker.credentials(conn, Grant.OBSERVE)
    broker.invalidate(conn.tenant_id)
    broker.credentials(conn, Grant.OBSERVE)
    assert sts.assume_role.call_count == 2


def test_requesting_containment_without_the_role_raises_rather_than_falling_back() -> None:
    """Falling back to ambient credentials here would run containment against
    Kronagent's own account instead of the customer's, and look like success."""
    broker = CredentialBroker()
    broker._sts = MagicMock()
    with pytest.raises(ValueError, match="has not granted containment"):
        broker.credentials(_conn(), Grant.CONTAIN)


# --------------------------------------------------------------------------- #
# Preflight
# --------------------------------------------------------------------------- #

def test_preflight_reports_failure_when_the_role_cannot_be_assumed() -> None:
    broker = CredentialBroker()
    sts = MagicMock()
    sts.assume_role.side_effect = RuntimeError("AccessDenied")
    broker._sts = sts

    result = preflight(_conn(), broker)
    assert result.ok is False
    assert "AccessDenied" in result.error
    assert result.as_state() is ConnectionState.FAILED


@requires_boto3
def test_preflight_catches_a_role_belonging_to_the_wrong_account(monkeypatch) -> None:
    """A role ARN recorded against the wrong account means our record and the
    customer's reality disagree — report it rather than silently protecting
    someone else's account."""
    broker = CredentialBroker()
    sts = MagicMock()
    sts.assume_role.return_value = _sts_response()
    broker._sts = sts

    import boto3
    client = MagicMock()
    client.get_caller_identity.return_value = {"Account": "111122223333"}
    monkeypatch.setattr(boto3, "client", lambda *a, **k: client)

    result = preflight(_conn(), broker)
    assert result.ok is False
    assert "111122223333" in result.error
    assert CUSTOMER_ACCOUNT in result.error


@requires_boto3
def test_preflight_names_the_specific_missing_permissions(monkeypatch) -> None:
    """"Something went wrong" is not actionable; "you are missing
    guardduty:ListDetectors" is."""
    broker = CredentialBroker()
    sts = MagicMock()
    sts.assume_role.return_value = _sts_response()
    broker._sts = sts

    import boto3

    def fake_client(service, **kwargs):
        c = MagicMock()
        if service == "sts":
            c.get_caller_identity.return_value = {"Account": CUSTOMER_ACCOUNT}
        elif service == "guardduty":
            c.list_detectors.side_effect = RuntimeError("AccessDenied")
        return c

    monkeypatch.setattr(boto3, "client", fake_client)

    result = preflight(_conn(), broker)
    assert result.ok is True                    # the role works…
    assert result.missing == ["guardduty:ListDetectors"]   # …but not completely
    assert result.as_state() is ConnectionState.DEGRADED


@requires_boto3
def test_preflight_healthy_when_every_probe_passes(monkeypatch) -> None:
    broker = CredentialBroker()
    sts = MagicMock()
    sts.assume_role.return_value = _sts_response()
    broker._sts = sts

    import boto3
    client = MagicMock()
    client.get_caller_identity.return_value = {"Account": CUSTOMER_ACCOUNT}
    monkeypatch.setattr(boto3, "client", lambda *a, **k: client)

    result = preflight(_conn(), broker)
    assert result.ok is True
    assert result.missing == []
    assert result.as_state() is ConnectionState.HEALTHY
    assert result.account_id == CUSTOMER_ACCOUNT


def test_preflight_result_state_mapping() -> None:
    assert PreflightResult(ok=False).as_state() is ConnectionState.FAILED
    assert PreflightResult(ok=True).as_state() is ConnectionState.HEALTHY
    assert PreflightResult(ok=True, missing=["x"]).as_state() is ConnectionState.DEGRADED


# --------------------------------------------------------------------------- #
# Tenant isolation in the containment adapter
#
# The connection model in this module is only worth anything if containment
# actually uses it. These assert the wiring: an action carries a tenant, the
# adapter resolves credentials for exactly that tenant, and two tenants never
# share a client.
# --------------------------------------------------------------------------- #

@requires_boto3
def test_action_runs_with_its_own_tenants_credentials(monkeypatch) -> None:
    from kronagent.providers.aws import AwsContainmentAdapter
    from kronagent.schemas import ActionClass, ProposedAction

    creds = {
        "acme":  {"aws_access_key_id": "ACME", "aws_secret_access_key": "s", "aws_session_token": "t"},
        "globex": {"aws_access_key_id": "GLOBEX", "aws_secret_access_key": "s", "aws_session_token": "t"},
    }
    seen: list[tuple[str, str]] = []

    import boto3

    def fake_client(service, region_name=None, **kw):
        seen.append((service, kw.get("aws_access_key_id", "AMBIENT")))
        return MagicMock()

    monkeypatch.setattr(boto3, "client", fake_client)

    adapter = AwsContainmentAdapter(region="us-east-1",
                                    credentials_for=lambda t: creds.get(t))

    for tenant in ("acme", "globex"):
        adapter._perform_sync(ProposedAction(
            provider="aws", tenant_id=tenant,
            action_class=ActionClass.DISABLE_ACCESS_KEY,
            target="AKIAEXAMPLE", rationale="test",
            parameters={"user_name": "victim"},
        ))

    assert ("iam", "ACME") in seen
    assert ("iam", "GLOBEX") in seen


@requires_boto3
def test_clients_are_never_shared_between_tenants(monkeypatch) -> None:
    """A boto3 client carries its credentials. One shared client would silently
    apply the first tenant's role to every tenant after it — containment
    executing in the wrong customer's account, reported as success."""
    from kronagent.providers.aws import AwsContainmentAdapter

    import boto3
    monkeypatch.setattr(boto3, "client", lambda *a, **k: MagicMock())

    adapter = AwsContainmentAdapter(
        region="us-east-1",
        credentials_for=lambda t: {"aws_access_key_id": t.upper(),
                                   "aws_secret_access_key": "s",
                                   "aws_session_token": "t"},
    )
    a = adapter._iam_client("acme")
    b = adapter._iam_client("globex")
    again = adapter._iam_client("acme")

    assert a is not b, "two tenants must not share a client"
    assert a is again, "the same tenant should reuse its cached client"


@requires_boto3
def test_invalidate_forces_credential_refresh(monkeypatch) -> None:
    """Assumed-role credentials expire. Without invalidation a cached client
    keeps using the dead ones until it fails mid-containment."""
    from kronagent.providers.aws import AwsContainmentAdapter

    import boto3
    monkeypatch.setattr(boto3, "client", lambda *a, **k: MagicMock())

    adapter = AwsContainmentAdapter(region="us-east-1",
                                    credentials_for=lambda t: None)
    first = adapter._iam_client("acme")
    adapter.invalidate("acme")
    assert adapter._iam_client("acme") is not first


@requires_boto3
def test_without_a_resolver_the_adapter_uses_ambient_credentials(monkeypatch) -> None:
    """Local development and single-tenant installs must keep working
    unchanged — the resolver is additive, not required."""
    from kronagent.providers.aws import AwsContainmentAdapter

    captured: dict = {}
    import boto3

    def fake_client(service, region_name=None, **kw):
        captured.update(kw)
        return MagicMock()

    monkeypatch.setattr(boto3, "client", fake_client)
    AwsContainmentAdapter(region="us-east-1")._iam_client()
    assert captured == {}, "no credentials should be passed when no resolver is set"


def test_planner_stamps_the_findings_tenant_onto_every_action() -> None:
    """22 places construct actions across five providers. Stamping centrally is
    what stops a future provider from forgetting and inheriting 'default'."""
    from kronagent.model import Finding, ResourceRef
    from kronagent.providers import plan_actions

    finding = Finding(
        provider="aws", finding_id="f-1", finding_type="UnauthorizedAccess",
        severity=8.0, tenant_id="acme",
        resources=[ResourceRef(kind="aws.ec2.instance", id="i-0abc", attributes={})],
        remote_ip="185.220.101.7",
    )
    actions = plan_actions(finding)
    assert actions, "expected the AWS planner to propose something"
    assert all(a.tenant_id == "acme" for a in actions), [a.tenant_id for a in actions]


def test_actions_default_to_the_default_tenant() -> None:
    from kronagent.schemas import ActionClass, ProposedAction
    a = ProposedAction(provider="aws", action_class=ActionClass.BLOCK_IP,
                       target="1.2.3.4", rationale="r")
    assert a.tenant_id == "default"


# --------------------------------------------------------------------------- #
# ConnectionStore
# --------------------------------------------------------------------------- #


@pytest.fixture()
def store(tmp_path):
    return ConnectionStore(str(tmp_path / "connections.json"))


def test_create_mints_a_pending_connection(store) -> None:
    c = store.create(tenant_id="acme", account_id=CUSTOMER_ACCOUNT, region="us-east-1")
    assert c.state is ConnectionState.PENDING
    assert c.external_id.startswith("kronagent-")
    assert c.can_contain is False
    assert store.get("acme") == c


def test_round_trips_through_disk(store) -> None:
    created = store.create(tenant_id="acme", account_id=CUSTOMER_ACCOUNT, region="eu-west-1")
    reopened = ConnectionStore(store._path).get("acme")
    assert reopened == created


def test_the_file_holding_external_ids_is_not_world_readable(store) -> None:
    """The External ID is the credential that lets Kronagent assume a customer's
    role. A role ARN is not secret — it appears in the customer's own CloudTrail
    — so this file being readable is most of what an attacker needs."""
    store.create(tenant_id="acme", account_id=CUSTOMER_ACCOUNT, region="us-east-1")
    mode = stat.S_IMODE(os.stat(store._path).st_mode)
    assert mode == 0o600, f"expected 0600, got {oct(mode)}"


def test_permissions_survive_a_rewrite(store) -> None:
    """os.replace() takes the temp file's mode, not the replaced file's — so a
    careless second write is exactly where 0600 would silently become 0644."""
    store.create(tenant_id="acme", account_id=CUSTOMER_ACCOUNT, region="us-east-1")
    store.record_role("acme", Grant.OBSERVE,
                      f"arn:aws:iam::{CUSTOMER_ACCOUNT}:role/KronagentObserveRole")
    assert stat.S_IMODE(os.stat(store._path).st_mode) == 0o600


def test_create_refuses_to_overwrite_an_existing_tenant(store) -> None:
    """Re-minting an External ID silently invalidates the trust policy the
    customer already installed; the only symptom is containment failing during
    an incident."""
    store.create(tenant_id="acme", account_id=CUSTOMER_ACCOUNT, region="us-east-1")
    with pytest.raises(ValueError, match="already connected"):
        store.create(tenant_id="acme", account_id=CUSTOMER_ACCOUNT, region="us-east-1")


def test_record_role_attaches_each_grant_independently(store) -> None:
    store.create(tenant_id="acme", account_id=CUSTOMER_ACCOUNT, region="us-east-1")
    observe = f"arn:aws:iam::{CUSTOMER_ACCOUNT}:role/KronagentObserveRole"
    contain = f"arn:aws:iam::{CUSTOMER_ACCOUNT}:role/KronagentContainRole"

    c = store.record_role("acme", Grant.OBSERVE, observe)
    assert c.observe_role_arn == observe
    assert c.can_contain is False, "observing must not imply containing"

    c = store.record_role("acme", Grant.CONTAIN, contain)
    assert c.can_contain is True
    assert c.observe_role_arn == observe, "attaching one grant must not clear the other"


def test_record_preflight_updates_state_and_timestamp(store) -> None:
    store.create(tenant_id="acme", account_id=CUSTOMER_ACCOUNT, region="us-east-1")
    c = store.record_preflight("acme", PreflightResult(ok=True, missing=["guardduty:ListDetectors"]))
    assert c.state is ConnectionState.DEGRADED
    assert c.missing_permissions == ("guardduty:ListDetectors",)
    assert c.last_verified is not None

    c = store.record_preflight("acme", PreflightResult(ok=True))
    assert c.state is ConnectionState.HEALTHY
    assert c.missing_permissions == ()


def test_record_role_on_unknown_tenant_raises(store) -> None:
    with pytest.raises(KeyError):
        store.record_role("ghost", Grant.OBSERVE, "arn:aws:iam::123456789012:role/X")


def test_delete_forgets_the_tenant(store) -> None:
    store.create(tenant_id="acme", account_id=CUSTOMER_ACCOUNT, region="us-east-1")
    assert store.delete("acme") is True
    assert store.get("acme") is None
    assert store.delete("acme") is False


def test_list_is_stable_and_covers_every_tenant(store) -> None:
    for t in ("zeta", "alpha", "mid"):
        store.create(tenant_id=t, account_id=CUSTOMER_ACCOUNT, region="us-east-1")
    assert [c.tenant_id for c in store.list()] == ["alpha", "mid", "zeta"]


def test_tenants_get_distinct_external_ids(store) -> None:
    a = store.create(tenant_id="a", account_id=CUSTOMER_ACCOUNT, region="us-east-1")
    b = store.create(tenant_id="b", account_id=CUSTOMER_ACCOUNT, region="us-east-1")
    assert a.external_id != b.external_id


def test_a_corrupt_store_fails_loudly(tmp_path) -> None:
    """An unreadable connection file means we cannot prove which account we are
    entitled to touch. Behaving as though nobody had connected would be a quiet
    outage; behaving as though the file were empty would be worse."""
    path = tmp_path / "connections.json"
    path.write_text("{not json")
    with pytest.raises(RuntimeError, match="corrupt"):
        ConnectionStore(str(path)).get("acme")


def test_missing_store_reads_as_empty_not_an_error(tmp_path) -> None:
    s = ConnectionStore(str(tmp_path / "nope.json"))
    assert s.list() == []
    assert s.get("acme") is None


# --- the resolver the containment adapters consume --------------------------- #

def test_resolver_returns_none_for_an_unknown_tenant(store) -> None:
    broker = CredentialBroker()
    resolve = store.credentials_resolver(broker, Grant.CONTAIN)
    assert resolve("nobody") is None


def test_resolver_refuses_containment_without_the_second_grant(store) -> None:
    """The customer installed the observe stack only. Containment credentials
    must not be conjured from the observe role."""
    store.create(tenant_id="acme", account_id=CUSTOMER_ACCOUNT, region="us-east-1")
    store.record_role("acme", Grant.OBSERVE,
                      f"arn:aws:iam::{CUSTOMER_ACCOUNT}:role/KronagentObserveRole")

    broker = CredentialBroker()
    broker._sts = MagicMock()
    assert store.credentials_resolver(broker, Grant.CONTAIN)("acme") is None
    broker._sts.assume_role.assert_not_called()


def test_resolver_returns_credentials_once_containment_is_granted(store) -> None:
    store.create(tenant_id="acme", account_id=CUSTOMER_ACCOUNT, region="us-east-1")
    store.record_role("acme", Grant.CONTAIN,
                      f"arn:aws:iam::{CUSTOMER_ACCOUNT}:role/KronagentContainRole")

    broker = CredentialBroker()
    sts = MagicMock()
    sts.assume_role.return_value = _sts_response()
    broker._sts = sts

    creds = store.credentials_resolver(broker, Grant.CONTAIN)("acme")
    assert creds["aws_access_key_id"] == "ASIAEXAMPLE"
    assert sts.assume_role.call_args.kwargs["ExternalId"] == store.get("acme").external_id


# --------------------------------------------------------------------------- #
# End to end: store -> broker -> adapter
#
# Each piece is tested above. This asserts they compose — that a connection on
# disk actually causes containment to run under that customer's role, which is
# the only thing any of it is for.
# --------------------------------------------------------------------------- #

@requires_boto3
def test_store_drives_containment_under_the_right_role(tmp_path, monkeypatch) -> None:
    from kronagent.providers.aws import AwsContainmentAdapter
    from kronagent.schemas import ActionClass, ProposedAction

    store = ConnectionStore(str(tmp_path / "connections.json"))
    for tenant, acct in (("acme", "111111111111"), ("globex", "222222222222")):
        store.create(tenant_id=tenant, account_id=acct, region="us-east-1")
        store.record_role(tenant, Grant.CONTAIN,
                          f"arn:aws:iam::{acct}:role/KronagentContainRole")

    # STS hands back a credential that identifies which role was assumed, so the
    # assertion below can tell the two tenants apart.
    broker = CredentialBroker()
    sts = MagicMock()

    def assume(**kw):
        acct = kw["RoleArn"].split(":")[4]
        return {"Credentials": {
            "AccessKeyId": f"ASIA-{acct}",
            "SecretAccessKey": "s",
            "SessionToken": "t",
            "Expiration": datetime.now(timezone.utc) + timedelta(minutes=60),
        }}

    sts.assume_role.side_effect = assume
    broker._sts = sts

    used: list[str] = []
    import boto3

    def fake_client(service, region_name=None, **kw):
        used.append(kw.get("aws_access_key_id", "AMBIENT"))
        return MagicMock()

    monkeypatch.setattr(boto3, "client", fake_client)

    adapter = AwsContainmentAdapter(
        region="us-east-1",
        credentials_for=store.credentials_resolver(broker, Grant.CONTAIN),
    )

    for tenant in ("acme", "globex"):
        adapter._perform_sync(ProposedAction(
            provider="aws", tenant_id=tenant,
            action_class=ActionClass.DISABLE_ACCESS_KEY,
            target="AKIAEXAMPLE", rationale="test",
            parameters={"user_name": "victim"},
        ))

    assert "ASIA-111111111111" in used
    assert "ASIA-222222222222" in used
    assert "AMBIENT" not in used, "no action may fall back to our own credentials"

    # And each assume_role carried that tenant's own External ID.
    sent = {c.kwargs["ExternalId"] for c in sts.assume_role.call_args_list}
    assert sent == {store.get("acme").external_id, store.get("globex").external_id}


@requires_boto3
def test_a_tenant_without_the_containment_stack_never_reaches_aws(tmp_path, monkeypatch) -> None:
    """Observe-only tenant. The resolver returns None, so the adapter falls back
    to ambient credentials — which is why callers must check can_contain before
    planning containment. This test documents that boundary rather than
    pretending the resolver enforces it."""
    from kronagent.providers.aws import AwsContainmentAdapter

    store = ConnectionStore(str(tmp_path / "c.json"))
    store.create(tenant_id="acme", account_id=CUSTOMER_ACCOUNT, region="us-east-1")
    store.record_role("acme", Grant.OBSERVE,
                      f"arn:aws:iam::{CUSTOMER_ACCOUNT}:role/KronagentObserveRole")

    broker = CredentialBroker()
    broker._sts = MagicMock()

    import boto3
    monkeypatch.setattr(boto3, "client", lambda *a, **k: MagicMock())

    adapter = AwsContainmentAdapter(
        region="us-east-1",
        credentials_for=store.credentials_resolver(broker, Grant.CONTAIN),
    )
    adapter._iam_client("acme")

    broker._sts.assume_role.assert_not_called()
    assert store.get("acme").can_contain is False
