"""
Tests for the cloud-connection REST API.

Two things here matter more than the CRUD:

  * `test_external_id_never_leaves_a_read_endpoint` — the External ID is the
    credential that lets Kronagent assume a customer's role. A role ARN is not
    secret; it appears in the customer's own CloudTrail. Leaking the External ID
    from a list endpoint hands over the pair.

  * the audit assertions — granting containment is the moment this platform
    becomes able to change a customer's infrastructure, and that has to be as
    traceable as promoting an action class to auto-execute.
"""
# SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Aditya Kumar, trading as Kronagent · https://kronagent.com
# Source-available, not open source. Commercial use requires a licence —
# see LICENSE or contact licensing@kronagent.com

from __future__ import annotations

import json
import pathlib

import pytest
from fastapi.testclient import TestClient

import kronagent.web as web
from kronagent.connect import ConnectionStore, CredentialBroker

CUSTOMER_ACCOUNT = "123456789012"
KRONAGENT_ACCOUNT = "999988887777"


def _settings(tmp_path, registry_path: str = ""):
    """Settings is a frozen dataclass, so it is replaced wholesale rather than
    mutated — the same approach test_web.py takes."""
    from kronagent.config import Settings
    return Settings(
        dry_run=True,
        audit_log_path=str(tmp_path / "audit.jsonl"),
        connection_store_path=str(tmp_path / "connections.json"),
        operator_registry_path=registry_path,
    )


@pytest.fixture()
def client(tmp_path, monkeypatch):
    """A web app pointed at throwaway stores.

    The operator registry stays unset, which puts identity in unauthenticated
    mode — resolve_actor accepts any caller. Authorisation *wiring* is asserted
    separately in test_registry_gates_connection_changes; these tests are about
    behaviour, not about re-testing identity.py.
    """
    monkeypatch.setattr(web, "settings", _settings(tmp_path))
    monkeypatch.setattr(web, "connection_store",
                        ConnectionStore(str(tmp_path / "connections.json")))
    monkeypatch.setattr(web, "credential_broker", CredentialBroker())
    monkeypatch.setattr(web, "audit_log", web.AuditLog(str(tmp_path / "audit.jsonl")))
    monkeypatch.setenv("KRONAGENT_AWS_ACCOUNT_ID", KRONAGENT_ACCOUNT)
    return TestClient(web.app)


def _create(client, tenant="acme", account=CUSTOMER_ACCOUNT, region="us-east-1"):
    return client.post("/api/connections", json={
        "tenant_id": tenant, "account_id": account, "region": region,
        "operator_id": "alice", "token": "t",
    })


def _audit_path(tmp_path, tenant: str = "acme"):
    """Audit logs are partitioned per tenant — get_tenant_path turns
    audit.jsonl into audit_acme.jsonl. Reading the unsuffixed file finds
    nothing and looks exactly like "nothing was audited"."""
    from kronagent.orchestrator import get_tenant_path
    return pathlib.Path(get_tenant_path(str(tmp_path / "audit.jsonl"), tenant))


def _audit_stages(tmp_path, tenant: str = "acme") -> list[str]:
    path = _audit_path(tmp_path, tenant)
    if not path.exists():
        return []
    return [json.loads(line)["record"]["stage"]
            for line in path.read_text().splitlines() if line.strip()]


# --------------------------------------------------------------------------- #
# The secret must not leak
# --------------------------------------------------------------------------- #

def test_external_id_never_leaves_a_read_endpoint(client) -> None:
    created = _create(client)
    assert created.status_code == 201
    full_external_id = web.connection_store.get("acme").external_id

    for resp in (client.get("/api/connections"),
                 client.get("/api/connections/acme"),
                 created):
        body = resp.text
        assert full_external_id not in body, f"External ID leaked from {resp.url}"
        assert "external_id" not in resp.json() if isinstance(resp.json(), dict) else True


def test_a_hint_is_returned_so_an_operator_can_confirm_the_paste(client) -> None:
    _create(client)
    stored = web.connection_store.get("acme").external_id
    hint = client.get("/api/connections/acme").json()["external_id_hint"]
    assert hint == stored[-6:]
    assert len(hint) == 6, "a hint long enough to be useful is short enough not to be a credential"


def test_the_template_does_contain_the_external_id(client) -> None:
    """The one legitimate place: the customer's trust policy is built from it."""
    _create(client)
    stored = web.connection_store.get("acme").external_id
    body = client.get("/api/connections/acme/template/observe").json()

    trust = (body["template"]["Resources"]["KronagentRole"]["Properties"]
             ["AssumeRolePolicyDocument"]["Statement"][0])
    assert trust["Condition"]["StringEquals"]["sts:ExternalId"] == stored


def test_external_id_is_not_written_to_the_audit_log(client, tmp_path) -> None:
    """Audit logs get exported to a customer's SIEM. A credential in one is a
    credential in their log pipeline, their backups and their vendor's index."""
    _create(client)
    stored = web.connection_store.get("acme").external_id
    audit = _audit_path(tmp_path).read_text()
    assert stored not in audit
    assert stored[-6:] in audit, "the hint should still be there for correlation"


# --------------------------------------------------------------------------- #
# Lifecycle
# --------------------------------------------------------------------------- #

def test_create_returns_a_pending_connection_that_cannot_contain(client) -> None:
    body = _create(client).json()
    assert body["state"] == "pending"
    assert body["can_contain"] is False
    assert body["observe_role_arn"] == ""
    assert "next_step" in body


def test_creating_the_same_tenant_twice_conflicts(client) -> None:
    _create(client)
    dup = _create(client)
    assert dup.status_code == 409
    assert "already connected" in dup.json()["detail"]


def test_observe_grant_does_not_confer_containment(client) -> None:
    _create(client)
    r = client.post("/api/connections/acme/role", json={
        "grant": "observe",
        "role_arn": f"arn:aws:iam::{CUSTOMER_ACCOUNT}:role/KronagentObserveRole",
        "operator_id": "alice", "token": "t",
    })
    assert r.status_code == 200
    assert r.json()["can_contain"] is False

    r = client.post("/api/connections/acme/role", json={
        "grant": "contain",
        "role_arn": f"arn:aws:iam::{CUSTOMER_ACCOUNT}:role/KronagentContainRole",
        "operator_id": "alice", "token": "t",
    })
    assert r.json()["can_contain"] is True
    assert r.json()["observe_role_arn"].endswith("KronagentObserveRole"), \
        "granting containment must not clear the observe grant"


def test_unknown_tenant_is_404_everywhere(client) -> None:
    assert client.get("/api/connections/ghost").status_code == 404
    assert client.get("/api/connections/ghost/template/observe").status_code == 404
    assert client.post("/api/connections/ghost/role", json={
        "grant": "observe", "role_arn": "arn:aws:iam::123456789012:role/X",
        "operator_id": "a", "token": "t"}).status_code == 404
    assert client.request("DELETE", "/api/connections/ghost", json={
        "operator_id": "a", "token": "t"}).status_code == 404


def test_invalid_grant_is_rejected(client) -> None:
    _create(client)
    assert client.get("/api/connections/acme/template/sudo").status_code == 400


def test_invalid_account_id_is_rejected(client) -> None:
    r = _create(client, account="not-an-account")
    assert r.status_code == 400, "a malformed account id is bad input, not a conflict"
    assert "12 digits" in r.json()["detail"]
    assert web.connection_store.get("acme") is None


def test_delete_forgets_the_tenant_and_says_what_it_did_not_do(client, tmp_path) -> None:
    _create(client)
    r = client.request("DELETE", "/api/connections/acme",
                       json={"operator_id": "alice", "token": "t"})
    assert r.status_code == 200
    assert web.connection_store.get("acme") is None

    audit = _audit_path(tmp_path).read_text()
    # "Disconnected" and "revoked" are different claims; the record must not
    # imply the customer's role was removed.
    assert "CloudFormation stack is unaffected" in audit


def test_template_requires_our_own_account_id_to_be_configured(client, monkeypatch) -> None:
    """A template without it produces a role whose trust policy points nowhere —
    the customer would install it and nothing would work, with no clue why."""
    _create(client)
    monkeypatch.delenv("KRONAGENT_AWS_ACCOUNT_ID", raising=False)
    r = client.get("/api/connections/acme/template/observe")
    assert r.status_code == 503
    assert "KRONAGENT_AWS_ACCOUNT_ID" in r.json()["detail"]


# --------------------------------------------------------------------------- #
# Audit
# --------------------------------------------------------------------------- #

def test_every_mutation_is_audited(client, tmp_path) -> None:
    _create(client)
    client.post("/api/connections/acme/role", json={
        "grant": "contain",
        "role_arn": f"arn:aws:iam::{CUSTOMER_ACCOUNT}:role/KronagentContainRole",
        "operator_id": "alice", "token": "t"})
    client.request("DELETE", "/api/connections/acme",
                   json={"operator_id": "alice", "token": "t"})

    stages = _audit_stages(tmp_path)
    assert "connection_created" in stages
    assert "containment_granted" in stages
    assert "connection_deleted" in stages


def test_granting_containment_gets_its_own_audit_stage(client, tmp_path) -> None:
    """Greppable in an export: "when did this vendor become able to change our
    infrastructure?" should be one query, not a scan of payloads."""
    _create(client)
    client.post("/api/connections/acme/role", json={
        "grant": "observe", "role_arn": f"arn:aws:iam::{CUSTOMER_ACCOUNT}:role/O",
        "operator_id": "alice", "token": "t"})
    assert "observe_granted" in _audit_stages(tmp_path)
    assert "containment_granted" not in _audit_stages(tmp_path)

    client.post("/api/connections/acme/role", json={
        "grant": "contain", "role_arn": f"arn:aws:iam::{CUSTOMER_ACCOUNT}:role/C",
        "operator_id": "alice", "token": "t"})
    assert "containment_granted" in _audit_stages(tmp_path)


def test_read_endpoints_do_not_pollute_the_audit_log(client, tmp_path) -> None:
    _create(client)
    before = len(_audit_stages(tmp_path))
    client.get("/api/connections")
    client.get("/api/connections/acme")
    client.get("/api/connections/acme/template/observe")
    assert len(_audit_stages(tmp_path)) == before


# --------------------------------------------------------------------------- #
# Authorisation
# --------------------------------------------------------------------------- #

def test_registry_gates_connection_changes(client, tmp_path, monkeypatch) -> None:
    """With an operator registry configured, a caller without PROMOTE is refused
    — and the refusal is itself audited, because a denied attempt to connect a
    cloud account is exactly what an incident review looks for."""
    from kronagent.identity import hash_token

    registry = tmp_path / "ops.json"
    registry.write_text(json.dumps({
        "viewer": {"display_name": "V", "roles": ["viewer"],
                   "token_sha256": hash_token("viewer-tok"), "active": True,
                   "tenants": ["acme"]},
        # Scoped to the tenant it manages. Permissions say what an operator may
        # do; `tenants` says whose account they may do it to, and both are now
        # required — an admin of one tenant could previously repoint or delete
        # another tenant's cloud connection.
        "admin": {"display_name": "A", "roles": ["admin"],
                  "token_sha256": hash_token("admin-tok"), "active": True,
                  "tenants": ["acme"]},
    }))
    monkeypatch.setattr(web, "settings", _settings(tmp_path, str(registry)))

    denied = client.post("/api/connections", json={
        "tenant_id": "acme", "account_id": CUSTOMER_ACCOUNT, "region": "us-east-1",
        "operator_id": "viewer", "token": "viewer-tok"})
    assert denied.status_code == 403
    assert "access_denied" in _audit_stages(tmp_path)
    assert web.connection_store.get("acme") is None

    allowed = client.post("/api/connections", json={
        "tenant_id": "acme", "account_id": CUSTOMER_ACCOUNT, "region": "us-east-1",
        "operator_id": "admin", "token": "admin-tok"})
    assert allowed.status_code == 201


def test_connecting_requires_promote_not_merely_approve(client, tmp_path, monkeypatch) -> None:
    """An approver can authorise one containment action. Connecting an account
    decides what this platform may touch at all — that is governance."""
    from kronagent.identity import hash_token

    registry = tmp_path / "ops.json"
    registry.write_text(json.dumps({
        "bob": {"display_name": "B", "roles": ["approver"],
                "token_sha256": hash_token("bob-tok"), "active": True},
    }))
    monkeypatch.setattr(web, "settings", _settings(tmp_path, str(registry)))

    r = client.post("/api/connections", json={
        "tenant_id": "acme", "account_id": CUSTOMER_ACCOUNT, "region": "us-east-1",
        "operator_id": "bob", "token": "bob-tok"})
    assert r.status_code == 403


# --------------------------------------------------------------------------- #
# Install instructions: the download path is primary, and the launch link only
# exists when it can actually work.
# --------------------------------------------------------------------------- #

def test_the_download_path_is_named_as_primary(client) -> None:
    """Machine-readable, so the console cannot recommend differently from the
    docs. Download is primary whether or not a bucket is ever published: the
    baked template cannot be mistyped, and the External ID never leaves the
    customer's terminal."""
    _create(client)
    install = client.get("/api/connections/acme/template/observe").json()["install"]

    assert install["primary"] == "download"
    assert install["filename"] == "kronagent-observe.json"
    assert "aws cloudformation deploy" in install["command"]
    assert "CAPABILITY_NAMED_IAM" in install["command"], (
        "the template creates a named IAM role; without this the deploy fails")


def test_no_launch_link_is_offered_when_no_bucket_is_published(client) -> None:
    """The endpoint this replaced returned a link to a bucket that does not
    exist, so a customer's very first click hit a CloudFormation error. Absent
    and explained beats present and broken."""
    _create(client)
    install = client.get("/api/connections/acme/template/observe").json()["install"]

    assert install["launch_url"] is None
    assert "not set" in install["launch_url_unavailable_reason"]
    assert "S3" in install["launch_url_unavailable_reason"]


def _with_settings(monkeypatch, **over) -> None:
    """Settings is frozen — swap the object rather than mutating it.

    Frozen on purpose: configuration that can change under a running process is
    configuration whose audited value may not be the one that was in force.
    """
    import dataclasses
    monkeypatch.setattr(web, "settings", dataclasses.replace(web.settings, **over))


def test_a_configured_bucket_produces_a_prefilled_link(client, monkeypatch) -> None:
    _create(client)
    _with_settings(monkeypatch,
                   aws_template_base_url="https://s3.amazonaws.com/kronagent-templates")
    body = client.get("/api/connections/acme/template/observe").json()
    install = body["install"]

    assert install["launch_url_unavailable_reason"] is None
    assert "console.aws.amazon.com/cloudformation" in install["launch_url"]
    assert "kronagent-observe-role.json" in install["launch_url"]
    assert "param_ExternalId" in install["launch_url"]
    # ...and the download is still what we recommend.
    assert install["primary"] == "download"


def test_no_contain_link_while_the_quarantine_ids_are_unset(client, monkeypatch) -> None:
    """The hosted contain template needs both quarantine ids. Empty renders a
    syntactically valid ARN that matches nothing — a role that installs cleanly
    and fails only at containment time, during an incident."""
    _create(client)
    client.post("/api/connections/acme/role", json={
        "grant": "contain",
        "role_arn": "arn:aws:iam::123456789012:role/KronagentContainRole",
        "operator_id": "alice", "token": "t"})
    _with_settings(monkeypatch,
                   aws_template_base_url="https://s3.amazonaws.com/kronagent-templates",
                   quarantine_security_group_id="", quarantine_nacl_id="")

    install = client.get("/api/connections/acme/template/contain").json()["install"]
    assert install["launch_url"] is None
    assert "QuarantineNaclId" in install["launch_url_unavailable_reason"]


def test_a_bad_base_url_yields_no_link_rather_than_an_unvetted_one(client, monkeypatch) -> None:
    """Settings.validate() catches this at boot. This is the second layer, for a
    value that reached the setting some other way — refuse rather than emit a
    link to a host nobody checked."""
    _create(client)
    _with_settings(monkeypatch, aws_template_base_url="https://evil.example/t")

    install = client.get("/api/connections/acme/template/observe").json()["install"]
    assert install["launch_url"] is None
    assert "not an S3 endpoint" in install["launch_url_unavailable_reason"]
