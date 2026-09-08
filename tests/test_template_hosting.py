"""
The one-click launch link: only offered when it can actually work.

`/api/connect/aws/link` used to return a CloudFormation console URL pointing at
`kronagent-templates-{region}` — a bucket that does not exist. A customer's very
first click landed on a console that could not load the template. That endpoint
is gone; this is what replaces it, and the shape is deliberate:

  - **The link is a feature that does not exist unless configured.** No bucket,
    no `launch_url` — and a `launch_url_unavailable_reason` saying so, rather
    than a broken link or a silent omission the caller has to interpret.
  - **`primary: "download"` is machine-readable**, so the console cannot decide
    the recommendation differently from the documentation.
  - **The link is validated, not merely well-formed.** Only the scheme was
    checked before, so `https://evil.example/t.json` passed. A template URL
    decides what role the customer creates and who may assume it.
  - **It prefills every parameter.** The hosted template is the parameterized
    form; without prefill the customer lands on a review screen with
    `ExternalId` blank and no way to discover it. The link was unusable
    independently of whether the bucket existed.
"""
# SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Aditya Kumar, trading as Kronagent · https://kronagent.com
# Source-available, not open source. Commercial use requires a licence —
# see LICENSE or contact licensing@kronagent.com

from __future__ import annotations

import urllib.parse

import pytest

from kronagent.config import Settings
from kronagent.connect import (
    AwsConnection,
    Grant,
    is_cfn_template_url,
    launch_stack_url,
    new_external_id,
    render_template,
)

CUSTOMER_ACCOUNT = "123456789012"
KRONAGENT_ACCOUNT = "999988887777"
GOOD_URL = "https://s3.amazonaws.com/kronagent-templates/kronagent-observe-role.json"


def _conn(**over) -> AwsConnection:
    base = dict(
        tenant_id="acme", account_id=CUSTOMER_ACCOUNT, region="us-east-1",
        external_id=new_external_id(),
        observe_role_arn=f"arn:aws:iam::{CUSTOMER_ACCOUNT}:role/KronagentObserveRole",
    )
    base.update(over)
    return AwsConnection(**base)


def _console_params(url: str) -> dict[str, list[str]]:
    """The console is a single-page app: its parameters live after the `#`."""
    _, _, qs = urllib.parse.urlparse(url).fragment.partition("?")
    return urllib.parse.parse_qs(qs)


# --- Host validation ---------------------------------------------------------

@pytest.mark.parametrize("url", [
    "https://s3.amazonaws.com/kronagent-templates/t.json",
    "https://s3.us-east-1.amazonaws.com/kronagent-templates/t.json",
    "https://kronagent-templates.s3.amazonaws.com/t.json",
    "https://kronagent-templates.s3.us-east-1.amazonaws.com/t.json",
    "https://s3-us-west-2.amazonaws.com/kronagent-templates/t.json",
])
def test_every_documented_s3_url_form_is_accepted(url):
    """AWS documents four shapes plus a legacy one. Rejecting a valid form would
    push an operator toward disabling the check rather than fixing their URL."""
    assert is_cfn_template_url(url) == ""


@pytest.mark.parametrize("url,because", [
    ("https://evil.example/t.json", "an arbitrary host"),
    ("https://s3.amazonaws.com.evil.example/t.json", "a suffix-confusion domain"),
    ("https://user@s3.amazonaws.com/t.json", "userinfo, a phishing shape"),
    ("http://s3.amazonaws.com/t.json", "plaintext"),
    ("s3://bucket/t.json", "not a fetchable URL"),
    ("file:///tmp/t.json", "a local file"),
    ("https://s3.amazonaws.com/t.json?x=1", "a query string"),
])
def test_launch_stack_url_rejects_a_template_it_cannot_vouch_for(url, because):
    """Only the scheme was checked before, so the first three of these passed.

    A template URL decides what role the customer creates and which principal
    may assume it. An attacker-chosen one is a complete account takeover wearing
    an onboarding link's clothes.
    """
    with pytest.raises(ValueError):
        launch_stack_url(_conn(), Grant.OBSERVE, template_url=url)


# --- Parameter prefill -------------------------------------------------------

@pytest.mark.parametrize("grant", list(Grant))
def test_launch_url_prefills_every_template_parameter(grant):
    """The test that makes the link *work*, as opposed to merely exist.

    The hosted template is parameterized. Every parameter without a default must
    arrive prefilled, or the customer reaches a review screen with blanks only
    Kronagent knows how to fill.
    """
    conn = _conn(contain_role_arn=f"arn:aws:iam::{CUSTOMER_ACCOUNT}:role/C")
    tpl = render_template(conn, grant, kronagent_account_id=KRONAGENT_ACCOUNT,
                          parameterized=True)
    required = {name for name, spec in tpl["Parameters"].items()
                if "Default" not in spec}

    params = {"KronagentAccountId": KRONAGENT_ACCOUNT, "ExternalId": conn.external_id}
    if grant is Grant.CONTAIN:
        params |= {"QuarantineSecurityGroupId": "sg-1", "QuarantineNaclId": "acl-1"}

    url = launch_stack_url(conn, grant, template_url=GOOD_URL, parameters=params)
    supplied = {k[len("param_"):] for k in _console_params(url) if k.startswith("param_")}

    assert required <= supplied, (
        f"{grant.value}: no prefill for {sorted(required - supplied)} — the "
        f"customer cannot know these values")


def test_launch_url_still_puts_everything_in_the_fragment():
    """The console reads its parameters after the `#`. In the query string they
    are ignored and the customer gets an empty wizard that looks like it worked."""
    url = launch_stack_url(_conn(), Grant.OBSERVE, template_url=GOOD_URL,
                           parameters={"ExternalId": "x" * 20})
    parsed = urllib.parse.urlparse(url)
    assert "templateURL" not in parsed.query
    assert "param_ExternalId" not in parsed.query
    assert "param_ExternalId" in parsed.fragment


def test_launch_url_targets_the_connections_own_region():
    url = launch_stack_url(_conn(region="ap-south-1"), Grant.OBSERVE,
                           template_url=GOOD_URL)
    assert "ap-south-1.console.aws.amazon.com" in url


# --- The setting -------------------------------------------------------------

def test_no_template_bucket_is_configured_by_default():
    """The only supported state today. Nothing is published."""
    assert Settings().aws_template_base_url == ""
    assert Settings().validate() == [] or "TEMPLATE_BASE_URL" not in " ".join(
        Settings().validate())


def test_settings_reject_a_non_s3_template_base_url():
    """Fail at boot, not at a customer's first click.

    A misconfigured base URL hands a customer a template that grants a role to
    somebody else's AWS account. That is not an error to discover during
    onboarding.
    """
    errors = Settings(aws_template_base_url="https://evil.example/templates").validate()
    assert any("TEMPLATE_BASE_URL" in e for e in errors), errors


def test_settings_accept_a_real_s3_base_url():
    assert not any(
        "TEMPLATE_BASE_URL" in e for e in
        Settings(aws_template_base_url="https://s3.amazonaws.com/kronagent-templates"
                 ).validate())
