"""
The shape of brokered AWS credentials, and the single place they become a client.

`CredentialBroker.credentials()` returns **boto3 keyword arguments** —
`aws_access_key_id` / `aws_secret_access_key` / `aws_session_token`. STS's own
response uses `AccessKeyId` / `SecretAccessKey` / `SessionToken`. The two are
one glance apart and the failure mode is silent: `GuardDutyPollingSource` read
the STS names, raised `KeyError` on the first poll and every poll after it, and
had that swallowed by the broad handler in `stream()` — so it retried forever
behind a 5s->300s backoff. **Live GuardDuty ingestion through a connection had
never once worked**, and the symptom was a connected tenant that looked exactly
like a quiet account.

Every existing ingestion test injects `client_factory`
(`tests/test_connection_ingestion.py`), so the real credential path had zero
coverage. That is the specific gap these tests close, in three layers:

  1. **Behaviour** — the polling source accepts what the broker actually
     returns. This one would have caught the defect with no refactor at all.
  2. **Shape** — both of `credentials()`'s return paths emit boto3 kwargs. Two
     tests, because the cached branch is what runs 59 minutes out of 60 and a
     single test would have exercised only the other one.
  3. **Structure** — an AST scan asserting there is still only *one* place that
     turns brokered credentials into a client, so the next consumer cannot
     reintroduce the same mismatch somewhere new.
"""
# SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Aditya Kumar, trading as Kronagent · https://kronagent.com
# Source-available, not open source. Commercial use requires a licence —
# see LICENSE or contact licensing@kronagent.com

from __future__ import annotations

import ast
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from kronagent import connect as connect_mod
from kronagent.connect import (
    _BOTO3_CREDENTIAL_KWARGS,
    AwsConnection,
    CredentialBroker,
    Grant,
    boto3_client,
    new_external_id,
)
from kronagent.ingestion import GuardDutyPollingSource
from kronagent.providers.aws import normalize_guardduty

PKG = Path(__file__).resolve().parent.parent / "kronagent"

BROKER_SHAPED = {
    "aws_access_key_id": "ASIAEXAMPLE",
    "aws_secret_access_key": "secret",
    "aws_session_token": "token",
}
STS_SHAPED = {
    "AccessKeyId": "ASIAEXAMPLE",
    "SecretAccessKey": "secret",
    "SessionToken": "token",
}


def _conn() -> AwsConnection:
    return AwsConnection(
        tenant_id="acme",
        account_id="123456789012",
        region="us-east-1",
        external_id=new_external_id(),
        observe_role_arn="arn:aws:iam::123456789012:role/KronagentObserveRole",
        contain_role_arn="arn:aws:iam::123456789012:role/KronagentContainRole",
    )


# --- 1. Behaviour: the seam that was never tested ----------------------------

def test_guardduty_polling_accepts_the_brokers_credential_shape(monkeypatch):
    """The defect, stated as a test.

    Constructed the way `run_slice.py` constructs it — a `credentials` callable
    and NO `client_factory` — because injecting a factory is precisely what hid
    this for the source's entire lifetime.
    """
    seen: dict = {}

    def _fake(service, *, region, credentials=None):
        seen.update(service=service, region=region, credentials=credentials)
        return object()

    monkeypatch.setattr(connect_mod, "boto3_client", _fake)

    src = GuardDutyPollingSource(
        normalize_guardduty,
        region="us-east-1",
        tenant_id="acme",
        credentials=lambda: dict(BROKER_SHAPED),
    )
    src._client()          # must not raise

    assert seen["service"] == "guardduty"
    assert seen["region"] == "us-east-1"
    assert seen["credentials"] == BROKER_SHAPED


def test_sts_shaped_credentials_are_rejected_loudly(monkeypatch):
    """A raw STS response reaching a client must fail immediately and say why.

    Passing it through would produce a TypeError from deep inside botocore at
    the first API call — a stack trace that names neither the broker nor the
    consumer, on a code path already wrapped in a swallow-everything handler.
    """
    monkeypatch.setattr("boto3.client", lambda *a, **kw: object(), raising=False)
    with pytest.raises(ValueError, match="AccessKeyId"):
        boto3_client("guardduty", region="us-east-1", credentials=STS_SHAPED)


def test_ambient_credentials_are_still_allowed(monkeypatch):
    """`None` means the process's own credentials — correct for a local
    single-account run, and the default `run_slice.py` falls back to."""
    captured: dict = {}
    monkeypatch.setattr(
        "boto3.client",
        lambda service, **kw: captured.update(service=service, **kw) or object(),
        raising=False,
    )
    boto3_client("ec2", region="eu-west-1", credentials=None)
    assert captured == {"service": "ec2", "region_name": "eu-west-1"}


# --- 2. Shape: both return paths of credentials() ----------------------------

class _FakeSts:
    """Minimal STS stub. Returns the shape STS really returns, so a test that
    passes here proves the broker does the translation rather than the caller."""

    def __init__(self) -> None:
        self.calls = 0

    def assume_role(self, **kwargs):
        self.calls += 1
        return {
            "Credentials": {
                "AccessKeyId": "ASIAEXAMPLE",
                "SecretAccessKey": "secret",
                "SessionToken": "token",
                "Expiration": datetime.now(timezone.utc) + timedelta(hours=1),
            }
        }


def _broker_with_fake_sts() -> tuple[CredentialBroker, _FakeSts]:
    broker = CredentialBroker()
    sts = _FakeSts()
    broker._sts = sts
    return broker, sts


def test_broker_returns_boto3_kwargs_on_the_fresh_path():
    broker, sts = _broker_with_fake_sts()
    creds = broker.credentials(_conn(), Grant.OBSERVE)
    assert sts.calls == 1
    assert set(creds) == set(_BOTO3_CREDENTIAL_KWARGS)


def test_broker_returns_boto3_kwargs_on_the_cached_path():
    """Deliberately separate from the fresh-path test.

    The cached branch is a second, independently-written dict literal, and it is
    what serves roughly 59 of every 60 minutes. One test covering only the
    assume-role path would leave the branch that almost always runs unasserted.
    """
    broker, sts = _broker_with_fake_sts()
    conn = _conn()
    broker.credentials(conn, Grant.OBSERVE)          # populate
    creds = broker.credentials(conn, Grant.OBSERVE)  # cached
    assert sts.calls == 1, "second call should have been served from cache"
    assert set(creds) == set(_BOTO3_CREDENTIAL_KWARGS)


def test_both_broker_paths_return_identical_keys():
    broker, _ = _broker_with_fake_sts()
    conn = _conn()
    assert set(broker.credentials(conn, Grant.OBSERVE)) == set(
        broker.credentials(conn, Grant.OBSERVE)
    )


def test_broker_output_is_directly_splattable():
    """`providers/aws.py` splats this straight into boto3. That splat is the
    load-bearing reason the return type is a kwargs dict and not an object."""
    broker, _ = _broker_with_fake_sts()
    creds = broker.credentials(_conn(), Grant.CONTAIN)
    captured: dict = {}

    def _boto3_client(service, **kw):
        captured.update(kw)
        return object()

    _boto3_client("ec2", region_name="us-east-1", **creds)
    assert set(captured) == {"region_name", *_BOTO3_CREDENTIAL_KWARGS}


# --- 3. Structure: only one construction site --------------------------------
#
# Ambient clients are exempt by name, not by pattern. Each entry is a place that
# deliberately uses the process's own credentials rather than a tenant's, and
# the reason is recorded here so that adding a fourth requires justifying it.

# Keyed by CLASS as well as function on purpose. `ingestion.py` has two
# `_client` methods — SqsFindingSource's (legitimately ambient) and
# GuardDutyPollingSource's (the one that carried the defect). A (file, function)
# key would have exempted the second along with the first, so the guard would
# have gone quiet on exactly the regression it exists to catch.

_AMBIENT_CREDENTIAL_CLIENTS = {
    # Assumes the customer's role — it is the thing that PRODUCES brokered
    # credentials, so by definition it cannot consume them.
    ("connect.py", "CredentialBroker", "_sts_client"),
    # Reads OUR SQS queue in OUR account. Nothing tenant-scoped passes through.
    ("ingestion.py", "SqsFindingSource", "_client"),
    # Signs audit records with OUR KMS key. A tenant's role has no access to it,
    # and must not: the chain is evidence *about* the customer, signed by us.
    ("crypto.py", "KmsSigner", "__init__"),
}


def _is_boto3_client_call(node: ast.AST) -> bool:
    return (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "client"
        and isinstance(node.func.value, ast.Name)
        and node.func.value.id == "boto3"
    )


def _boto3_client_sites() -> list[tuple[str, str, str, int]]:
    """Every `boto3.client(...)` in the package as (file, class, func, line).

    Class is `""` for a module-level function. Walking the tree top-down and
    tracking the enclosing class is what lets two same-named methods in one
    module be exempted independently.
    """
    sites: list[tuple[str, str, str, int]] = []

    def visit(node: ast.AST, cls: str, fn: str, path: Path) -> None:
        for child in ast.iter_child_nodes(node):
            if isinstance(child, ast.ClassDef):
                visit(child, child.name, fn, path)
            elif isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                visit(child, cls, child.name, path)
            else:
                if _is_boto3_client_call(child):
                    sites.append((path.name, cls, fn, child.lineno))
                visit(child, cls, fn, path)

    for path in sorted(PKG.rglob("*.py")):
        visit(ast.parse(path.read_text(encoding="utf-8"), filename=str(path)),
              "", "", path)
    return sites


def test_only_one_place_turns_broker_credentials_into_a_client():
    """Structural guard on the fix.

    Three consumers splatted brokered credentials into boto3 independently;
    one of them got the key names wrong and nothing noticed for a whole
    feature's lifetime. Collapsing them to a single construction site is the
    fix, and this asserts it stays collapsed.
    """
    unexpected = [
        s for s in _boto3_client_sites()
        if (s[0], s[1], s[2]) not in _AMBIENT_CREDENTIAL_CLIENTS
        and s[2] != "boto3_client"
    ]
    assert not unexpected, (
        "boto3.client() constructed outside connect.boto3_client at "
        + ", ".join(f"{f}:{ln} in {c or '<module>'}.{fn}()"
                    for f, c, fn, ln in unexpected)
        + ". Route brokered credentials through connect.boto3_client, or add an "
          "entry to _AMBIENT_CREDENTIAL_CLIENTS explaining why this client "
          "legitimately uses ambient credentials."
    )


def test_the_ambient_allowlist_does_not_name_functions_that_vanished():
    """A stale exemption is a hole. If an allowlisted function is renamed or
    deleted, this fails rather than silently widening what the scan permits."""
    actual = {(f, c, fn) for f, c, fn, _ in _boto3_client_sites()}
    stale = _AMBIENT_CREDENTIAL_CLIENTS - actual
    assert not stale, f"allowlisted but no longer present: {sorted(stale)}"


# --- 4. A wiring bug must not read as a transient ----------------------------
#
# This is why D2 survived. The poll loop's blanket handler treated a KeyError
# exactly like a throttle: print a line, back off, retry, forever. Over hours
# that is thousands of identical lines nobody reads, describing a condition that
# will never resolve, while the tenant simply appears to have no findings.

async def _run_stream_briefly(source, seconds: float = 0.15) -> None:
    import asyncio
    source._POLL_BASE_BACKOFF = 0.01
    queue: asyncio.Queue = asyncio.Queue()
    stop = asyncio.Event()
    task = asyncio.create_task(source.stream(queue, stop))
    await asyncio.sleep(seconds)
    alive = not task.done()
    stop.set()
    await asyncio.wait_for(task, timeout=5.0)
    assert alive, "ingestion died instead of backing off"


def _broken_source(exc: Exception) -> GuardDutyPollingSource:
    class Broken:
        def list_detectors(self):
            raise exc

    return GuardDutyPollingSource(
        normalize_guardduty, region="us-east-1", tenant_id="acme",
        poll_interval=0.01, client_factory=lambda: Broken(),
    )


async def test_a_repeated_configuration_error_is_named_as_one(capsys):
    """A KeyError on every poll is a wiring bug, and the log must say so."""
    await _run_stream_briefly(_broken_source(KeyError("AccessKeyId")))
    out = capsys.readouterr().out
    assert "CONFIGURATION ERROR" in out
    assert "producing NO findings" in out


async def test_a_transient_error_is_never_called_a_configuration_error(capsys):
    """Throttling is exactly what the backoff is for. Crying configuration
    error at it would make the escalation worthless the first time GuardDuty
    rate-limits a busy account."""
    await _run_stream_briefly(_broken_source(RuntimeError("Throttling")))
    out = capsys.readouterr().out
    assert "GuardDuty poll failed" in out
    assert "CONFIGURATION ERROR" not in out


async def test_ingestion_still_survives_a_configuration_error(capsys):
    """Naming it must not turn it fatal. One tenant's broken wiring cannot be
    allowed to end ingestion for every other tenant in the process."""
    await _run_stream_briefly(_broken_source(TypeError("bad kwargs")))
    # _run_stream_briefly asserts the task was still alive.
    assert "CONFIGURATION ERROR" in capsys.readouterr().out
