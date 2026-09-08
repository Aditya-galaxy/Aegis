"""
Tenant cloud connection: how a customer grants Kronagent access to their own
account, and how that grant is verified before anything relies on it.

Until now Kronagent read AWS credentials from its own process environment, which
only works when the platform runs inside the account it defends. That is a
developer setup. A customer cannot hand over an access key, and should not be
asked to.

The mechanism here is the one every serious cloud security vendor converged on:
a **cross-account IAM role, assumed with an External ID, created from a
CloudFormation template the customer launches from a pre-filled console link.**
No key ever changes hands, nothing long-lived is copied anywhere, and the
customer can read the exact permissions before granting them.

Two properties are load-bearing:

  1. **Read and write are separate grants.** Onboarding installs the *observe*
     role only: Kronagent ingests, triages, investigates and writes a full
     incident record while being structurally incapable of containment, because
     it does not hold the permissions. Containment is a second, deliberate stack
     the customer installs later. This is the product's whole thesis expressed
     as an IAM boundary rather than a claim — and it is the answer to the first
     objection every buyer raises.

  2. **The External ID is per tenant and secret.** It defends against the
     confused-deputy problem: without it, anyone who learns a customer's role
     ARN could ask *our* platform to assume it. AWS's guidance is explicit that
     the vendor generates it and the customer pins their trust policy to it.
"""
# SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Aditya Kumar, trading as Kronagent · https://kronagent.com
# Source-available, not open source. Commercial use requires a licence —
# see LICENSE or contact licensing@kronagent.com

from __future__ import annotations

import json
import logging
import os
import re
import secrets
import threading
import urllib.parse
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any, Optional

_log = logging.getLogger("kronagent.connect")

# Where the customer's browser is sent to install the stack. Region matters:
# CloudFormation is regional, and the console must open in the same region the
# customer intends to protect.
_CONSOLE_URL = "https://{region}.console.aws.amazon.com/cloudformation/home?region={region}#/stacks/create/review"

# Refresh assumed credentials this long before they actually expire. STS
# sessions are typically an hour; renewing early means a long-running
# containment call never starts with a credential that dies mid-flight.
_REFRESH_MARGIN = timedelta(minutes=5)

# AWS account ids are exactly twelve digits. Validated rather than trusted
# because it is interpolated into ARNs and into a URL handed to a browser.
_ACCOUNT_RE = re.compile(r"^\d{12}$")
_REGION_RE = re.compile(r"^[a-z]{2}(-gov)?-[a-z]+-\d$")
_EXTERNAL_ID_RE = re.compile(r"^[A-Za-z0-9+=,.@:/_-]{16,1224}$")


class Grant(str, Enum):
    """The two halves of access, granted separately and always in this order."""

    OBSERVE = "observe"      # read-only: ingest, triage, investigate
    CONTAIN = "contain"      # write: execute containment actions


class ConnectionState(str, Enum):
    PENDING = "pending"      # template issued, stack not yet detected
    HEALTHY = "healthy"      # role assumed and permissions verified
    DEGRADED = "degraded"    # role assumed but some expected permissions absent
    FAILED = "failed"        # role could not be assumed


def new_external_id() -> str:
    """A fresh External ID for a tenant.

    Must be unguessable: it is the only thing standing between a leaked role ARN
    and a third party persuading Kronagent to assume it. 32 bytes of urlsafe
    randomness, well inside the 1224-character ceiling AWS allows.
    """
    return f"kronagent-{secrets.token_urlsafe(32)}"


@dataclass(frozen=True)
class AwsConnection:
    """One tenant's grant of access to one AWS account.

    Frozen: a connection's identity (account, region, external id) is fixed at
    creation. Rotating the External ID means issuing a new connection and a new
    template, not mutating this one — otherwise the trust policy in the
    customer's account and our record of it drift apart silently.
    """

    tenant_id: str
    account_id: str
    region: str
    external_id: str
    observe_role_arn: str = ""
    contain_role_arn: str = ""
    state: ConnectionState = ConnectionState.PENDING
    missing_permissions: tuple[str, ...] = ()
    last_verified: Optional[datetime] = None

    def __post_init__(self) -> None:
        if not _ACCOUNT_RE.match(self.account_id):
            raise ValueError(f"account_id must be 12 digits, got {self.account_id!r}")
        if not _REGION_RE.match(self.region):
            raise ValueError(f"region does not look like an AWS region: {self.region!r}")
        if not _EXTERNAL_ID_RE.match(self.external_id):
            raise ValueError("external_id must be 16-1224 chars of [A-Za-z0-9+=,.@:/_-]")

    @property
    def can_contain(self) -> bool:
        """True only when the customer has installed the second stack.

        Read this before planning any containment: the absence of a containment
        role is a deliberate customer choice, not an error to route around.
        """
        return bool(self.contain_role_arn)

    def role_arn(self, grant: Grant) -> str:
        arn = self.observe_role_arn if grant is Grant.OBSERVE else self.contain_role_arn
        if not arn:
            raise ValueError(
                f"tenant {self.tenant_id!r} has no {grant.value} role installed"
                + ("" if grant is Grant.OBSERVE else
                   " — the customer has not granted containment permissions")
            )
        return arn


# --------------------------------------------------------------------------- #
# CloudFormation templates
#
# Rendered rather than hand-written so the External ID and the platform's own
# account id are baked in, and the customer cannot accidentally install a stack
# that trusts the wrong principal.
# --------------------------------------------------------------------------- #

def partition_for(region: str) -> str:
    """The ARN partition a region belongs to.

    `_REGION_RE` accepts GovCloud regions, so the code already claims to support
    them — but every ARN here hardcoded `arn:aws:`, which is the commercial
    partition only. A GovCloud customer's stack would have created a role whose
    policy referenced resources that cannot exist, and China regions are the
    same story under `aws-cn`. cfn-lint flags exactly this (I3042).
    """
    if region.startswith("us-gov-"):
        return "aws-us-gov"
    if region.startswith("cn-"):
        return "aws-cn"
    return "aws"


def _trust_policy(kronagent_account_id: str, external_id: str,
                  partition: str = "aws") -> dict:
    """Who may assume this role, and under what condition.

    The sts:ExternalId condition is the whole point. Without it the trust policy
    would say "any principal in Kronagent's account may assume this", and every
    Kronagent customer could reach every other customer's role.
    """
    return {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"AWS": f"arn:{partition}:iam::{kronagent_account_id}:root"},
            "Action": "sts:AssumeRole",
            "Condition": {"StringEquals": {"sts:ExternalId": external_id}},
        }],
    }


def _observe_policy() -> dict:
    """Read-only. Enough to ingest findings and to describe the resources a
    finding implicates — and nothing that can change state anywhere.

    Every action here is a Get/List/Describe. That is worth preserving as an
    invariant: it is what lets the onboarding conversation say "this grant
    cannot alter your account", and there is a test asserting it.
    """
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "ReadGuardDutyFindings",
                "Effect": "Allow",
                "Action": [
                    "guardduty:GetFindings",
                    "guardduty:ListFindings",
                    "guardduty:ListDetectors",
                    "guardduty:GetDetector",
                ],
                "Resource": "*",
            },
            {
                "Sid": "DescribeImplicatedResources",
                "Effect": "Allow",
                "Action": [
                    "ec2:DescribeInstances",
                    "ec2:DescribeSecurityGroups",
                    "ec2:DescribeNetworkAcls",
                    "ec2:DescribeVpcs",
                ],
                "Resource": "*",
            },
            {
                "Sid": "DescribeImplicatedPrincipals",
                "Effect": "Allow",
                "Action": [
                    "iam:GetUser",
                    "iam:ListAccessKeys",
                    "iam:GetRole",
                    "iam:ListAttachedUserPolicies",
                ],
                "Resource": "*",
            },
            {
                "Sid": "ConfirmOwnIdentity",
                "Effect": "Allow",
                "Action": "sts:GetCallerIdentity",
                "Resource": "*",
            },
        ],
    }


def _contain_policy(account_id: str, region: str, quarantine_nacl_id: str,
                    quarantine_sg_id: str = "QUARANTINE_SG_ID",
                    include_terminate: bool = False,
                    partition: str = "aws") -> dict:
    """Write access, least-privilege, mirroring deploy/kronagent-iam-policy.json.

    Deliberately omits ec2:TerminateInstances. Terminate is classified
    destructive by the policy engine and can never auto-execute, but the point
    of a separate stack is that the customer reads what they are granting —
    and most will not want an irreversible action in the grant at all. Anyone
    who does can add it; the platform does not ask for it by default.
    """
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "DisableAndReenableAccessKeys",
                "Effect": "Allow",
                "Action": "iam:UpdateAccessKey",
                "Resource": f"arn:{partition}:iam::{account_id}:user/*",
            },
            {
                "Sid": "QuarantineDenyAllInlinePolicyOnly",
                "Effect": "Allow",
                "Action": ["iam:PutUserPolicy", "iam:DeleteUserPolicy"],
                "Resource": f"arn:{partition}:iam::{account_id}:user/*",
                "Condition": {
                    "StringEquals": {"iam:PolicyName": "kronagent-quarantine-deny-all"}
                },
            },
            {
                "Sid": "RevokeRoleSessionsInlinePolicyOnly",
                "Effect": "Allow",
                "Action": ["iam:PutRolePolicy", "iam:DeleteRolePolicy"],
                "Resource": f"arn:{partition}:iam::{account_id}:role/*",
                "Condition": {
                    "StringEquals": {"iam:PolicyName": "kronagent-revoke-sessions"}
                },
            },
            {
                # Read before write. The adapter captures the instance's current
                # security groups so the rollback hint can name them, and reads
                # the quarantine NACL to pick free rule numbers. Both happen
                # BEFORE the mutation, so without them containment does not
                # degrade — it fails outright, and ContainmentExecutor swallows
                # the denial into executed=False during an incident.
                #
                # These are the same read-only calls the observe policy already
                # grants. Containment cannot borrow that grant: it assumes a
                # different role.
                "Sid": "ReadStateForRollbackCapture",
                "Effect": "Allow",
                "Action": ["ec2:DescribeInstances", "ec2:DescribeNetworkAcls"],
                "Resource": "*",   # EC2 Describe* does not support resource ARNs
                # ...so the region condition is the only scope available here.
                "Condition": {"StringEquals": {"ec2:Region": region}},
            },
            {
                "Sid": "IsolateInstanceIntoQuarantineSG",
                "Effect": "Allow",
                "Action": "ec2:ModifyInstanceAttribute",
                # BOTH ARNs are required. AWS evaluates ModifyInstanceAttribute
                # against the security group named in Groups= as well as the
                # instance, so an instance-only grant denies the call — the
                # action appears granted and containment fails anyway. Naming
                # the quarantine SG explicitly also means this role can move an
                # instance into quarantine and nowhere else.
                "Resource": [
                    f"arn:{partition}:ec2:{region}:{account_id}:instance/*",
                    f"arn:{partition}:ec2:{region}:{account_id}:security-group/{quarantine_sg_id}",
                ],
                # Redundant with the ARNs above, and kept anyway: it was present
                # in the hand-written standalone policy and absent from both role
                # templates, which is the kind of asymmetry that makes one copy
                # quietly weaker than another.
                "Condition": {"StringEquals": {"ec2:Region": region}},
            },
            {
                "Sid": "BlockIpAtQuarantineNacl",
                "Effect": "Allow",
                "Action": ["ec2:CreateNetworkAclEntry", "ec2:DeleteNetworkAclEntry"],
                "Resource": f"arn:{partition}:ec2:{region}:{account_id}:network-acl/{quarantine_nacl_id}",
                "Condition": {"StringEquals": {"ec2:Region": region}},
            },
        ] + ([
            {
                # Only for the standalone policy an operator attaches by hand.
                # The role templates omit it: the point of asking the customer
                # to read the grant is that most will not want an irreversible
                # action in it, and anyone who does can add this statement.
                "Sid": "TerminateInstancesInRegion",
                "Effect": "Allow",
                "Action": "ec2:TerminateInstances",
                "Resource": f"arn:{partition}:ec2:{region}:{account_id}:instance/*",
                "Condition": {"StringEquals": {"ec2:Region": region}},
            },
        ] if include_terminate else []),
    }


_COMMON_PARAMETERS = {
    "KronagentAccountId": {
        "Type": "String",
        "Description": "Kronagent's AWS account id — the only principal permitted to assume this role.",
        "AllowedPattern": "^\\d{12}$",
    },
    "ExternalId": {
        "Type": "String",
        "Description": "The per-tenant External ID from your Kronagent console. Without it this role could be assumed on behalf of any Kronagent customer.",
        "MinLength": 16,
        "MaxLength": 1224,
        "NoEcho": True,
    },
}

_TEMPLATE_PARAMETERS: dict[Grant, dict] = {
    Grant.OBSERVE: {
        **_COMMON_PARAMETERS,
        "RoleName": {"Type": "String", "Default": "KronagentObserveRole",
                     "Description": "Name of the IAM role to create."},
    },
    Grant.CONTAIN: {
        **_COMMON_PARAMETERS,
        # No Default on either. They are baked into the granted ARNs, so an
        # empty value produces a syntactically valid ARN matching nothing —
        # a role that installs cleanly and fails only at containment time.
        "QuarantineSecurityGroupId": {
            "Type": "String",
            "Description": "The quarantine security group. This role may move an instance into this group and no other.",
            "AllowedPattern": "^sg-[0-9a-f]+$",
        },
        "QuarantineNaclId": {
            "Type": "String",
            "Description": "The network ACL Kronagent may add deny entries to. This role can modify no other NACL.",
            "AllowedPattern": "^acl-[0-9a-f]+$",
        },
        "RoleName": {"Type": "String", "Default": "KronagentContainRole",
                     "Description": "Name of the IAM role to create."},
    },
}


def _cfn_parameterize(obj: Any, parameters: set[str]) -> Any:
    """Rewrite `${...}` placeholders into CloudFormation intrinsic functions.

    The policy statements are rendered ONCE, by the same `_observe_policy()` /
    `_contain_policy()` the baked template uses, with CloudFormation
    placeholders standing in for the concrete ids. Only this pass differs
    between the two forms — so the hosted template and the one a customer
    downloads cannot grant different things, which is precisely what happened
    when they were maintained as separate files.

    A string that is exactly one template parameter becomes `Ref`; anything else
    containing a placeholder becomes `Fn::Sub`. Both are correct; `Ref` is what
    a reviewer expects to see, and this file is written to be read.
    """
    if isinstance(obj, dict):
        return {k: _cfn_parameterize(v, parameters) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_cfn_parameterize(v, parameters) for v in obj]
    if isinstance(obj, str) and "${" in obj:
        whole = re.fullmatch(r"\$\{([A-Za-z0-9:]+)\}", obj)
        if whole and whole.group(1) in parameters:
            return {"Ref": whole.group(1)}
        return {"Fn::Sub": obj}
    return obj


def render_template(conn: AwsConnection, grant: Grant, *,
                    kronagent_account_id: str,
                    quarantine_nacl_id: str = "QUARANTINE_NACL_ID",
                    quarantine_sg_id: str = "QUARANTINE_SG_ID",
                    parameterized: bool = False) -> dict:
    """The CloudFormation template the customer installs for one grant.

    Two forms, one source of truth for what is granted.

    **Baked (default).** Our account id, the tenant's External ID and the
    quarantine resource ids are literals in the JSON. This is what the customer
    downloads and deploys, and it is the safer form: nothing can be omitted or
    mistyped. A customer who fat-fingers a parameterized `KronagentAccountId`
    creates a role trusting a stranger's AWS account — a silent, complete
    confused-deputy compromise, and the exact failure this module exists to
    prevent.

    **Parameterized.** The same policy statements with CloudFormation
    parameters in place of those literals, for a template hosted once and
    installed by many. Required for a one-click console link, which cannot carry
    a per-tenant template.

    The statements themselves are rendered by the same functions either way. The
    forms differ only in `_cfn_parameterize`, which is what makes it structurally
    impossible for the hosted grant and the downloaded grant to mean different
    things — they were separate files, and had already drifted four ways.
    """
    if parameterized:
        # Locals, not a modified connection: AwsConnection validates its own
        # account id and External ID, and rightly rejects a placeholder.
        account_id, region = "${AWS::AccountId}", "${AWS::Region}"
        external_id = "${ExternalId}"
        kronagent_account_id = "${KronagentAccountId}"
        quarantine_nacl_id = "${QuarantineNaclId}"
        quarantine_sg_id = "${QuarantineSecurityGroupId}"
        partition = "${AWS::Partition}"
    else:
        account_id, region = conn.account_id, conn.region
        external_id = conn.external_id
        partition = partition_for(conn.region)

    if grant is Grant.OBSERVE:
        policy, role_name, desc = (
            _observe_policy(), "KronagentObserveRole",
            "Read-only access for Kronagent to ingest and investigate findings. "
            "Grants no ability to change anything in this account.",
        )
    else:
        policy, role_name, desc = (
            _contain_policy(account_id, region, quarantine_nacl_id,
                            quarantine_sg_id, partition=partition),
            "KronagentContainRole",
            "Least-privilege containment access for Kronagent. Install this only "
            "after reviewing the actions below; Kronagent operates read-only "
            "without it.",
        )

    params = _TEMPLATE_PARAMETERS[grant] if parameterized else {}
    body: dict[str, Any] = {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Description": desc,
        **({"Parameters": params} if params else {}),
        "Resources": {
            "KronagentRole": {
                "Type": "AWS::IAM::Role",
                "Properties": {
                    "RoleName": "${RoleName}" if parameterized else role_name,
                    "Description": desc,
                    "AssumeRolePolicyDocument": _trust_policy(
                        kronagent_account_id, external_id, partition),
                    "Policies": [{
                        "PolicyName": f"Kronagent{grant.value.capitalize()}Policy",
                        "PolicyDocument": policy,
                    }],
                },
            },
        },
        "Outputs": {
            "RoleArn": {
                "Description": f"Paste this back into Kronagent to finish the {grant.value} connection",
                "Value": {"Fn::GetAtt": ["KronagentRole", "Arn"]},
            },
        },
    }
    return _cfn_parameterize(body, set(params)) if parameterized else body


def launch_stack_url(conn: AwsConnection, grant: Grant, *, template_url: str) -> str:
    """A one-click link that opens CloudFormation with everything pre-filled.

    `template_url` must be a publicly readable https URL (an S3 object in our
    account). The console fetches it from the customer's browser, so anything
    private or non-http would simply fail to load for them.

    The resulting URL has an unusual shape, and it is not a mistake:

        https://<region>.console.aws.amazon.com/cloudformation/home
            ?region=<region>              <- real query string
            #/stacks/create/review        <- fragment: the console's own route
            ?templateURL=...&stackName=.. <- parameters INSIDE the fragment

    The CloudFormation console is a single-page app, so its own parameters live
    after the `#`. Putting them in the real query string instead produces a link
    that opens an empty stack wizard — which looks like it worked right up until
    the customer wonders what to paste.
    """
    scheme = urllib.parse.urlparse(template_url).scheme.lower()
    if scheme != "https":
        raise ValueError(f"template_url must be https, got {scheme or 'no scheme'!r}")

    query = urllib.parse.urlencode({
        "templateURL": template_url,
        "stackName": f"kronagent-{grant.value}",
    })
    return _CONSOLE_URL.format(region=conn.region) + "?" + query


# --------------------------------------------------------------------------- #
# Assuming the role
# --------------------------------------------------------------------------- #

# --- The one place broker credentials become a boto3 client -------------------
#
# CredentialBroker.credentials() returns **boto3 keyword arguments**
# (aws_access_key_id / aws_secret_access_key / aws_session_token), not STS's
# own Credentials shape (AccessKeyId / SecretAccessKey / SessionToken). The two
# are trivially confusable and the failure is silent: GuardDutyPollingSource
# read the STS names, raised KeyError on every single poll, and had that
# swallowed by the broad handler in its stream loop — so it retried forever
# behind a 5s->300s backoff. Live ingestion through a connection had therefore
# never once worked, and a connected tenant looked exactly like a quiet account.
#
# Routing every brokered client through here means the shape can only be wrong
# in one place, and tests/test_credential_shape.py asserts there is only one.

_BOTO3_CREDENTIAL_KWARGS = frozenset(
    {"aws_access_key_id", "aws_secret_access_key", "aws_session_token"}
)


def boto3_client(service: str, *, region: str,
                 credentials: Optional[dict] = None) -> Any:
    """A boto3 client for one service, under brokered or ambient credentials.

    `credentials` is what CredentialBroker.credentials() returned, or None to
    use the process's own ambient credentials (correct for a local
    single-account run, never correct for a multi-tenant one).

    An unexpected key is rejected rather than passed through: boto3 would raise
    a confusing TypeError deep in botocore, and STS-shaped keys arriving here
    are exactly the bug this function exists to make impossible.
    """
    kwargs: dict[str, Any] = {"region_name": region}
    if credentials:
        unexpected = set(credentials) - _BOTO3_CREDENTIAL_KWARGS
        if unexpected:
            raise ValueError(
                f"credentials for {service} carry unexpected keys "
                f"{sorted(unexpected)}; expected boto3 keyword arguments "
                f"{sorted(_BOTO3_CREDENTIAL_KWARGS)}. STS returns AccessKeyId / "
                f"SecretAccessKey / SessionToken — pass what "
                f"CredentialBroker.credentials() returned, not the raw STS "
                f"response."
            )
        kwargs.update(credentials)

    import boto3  # local import: this module stays importable without AWS
    return boto3.client(service, **kwargs)


@dataclass
class _CachedCredentials:
    access_key_id: str
    secret_access_key: str
    session_token: str
    expires_at: datetime

    @property
    def stale(self) -> bool:
        return datetime.now(timezone.utc) >= self.expires_at - _REFRESH_MARGIN


class CredentialBroker:
    """Assumes tenant roles and caches the short-lived credentials.

    One broker per process. Caching matters: STS is rate-limited, and a busy
    orchestrator would otherwise assume the same role once per API call.

    Thread-safe because the orchestrator runs parallel workers, and two workers
    racing on the same expired credential would otherwise both call STS.
    """

    def __init__(self, *, session_duration_seconds: int = 3600) -> None:
        self._duration = session_duration_seconds
        self._cache: dict[tuple[str, str], _CachedCredentials] = {}
        self._lock = threading.Lock()
        self._sts: Any = None

    def _sts_client(self):
        if self._sts is None:
            import boto3
            self._sts = boto3.client("sts")
        return self._sts

    def credentials(self, conn: AwsConnection, grant: Grant) -> dict[str, str]:
        """Credentials for one tenant and one grant, assumed or from cache.

        Raises rather than falling back to ambient credentials. A silent
        fallback would mean containment running against *our* account instead of
        the customer's — the most dangerous possible failure mode, and one that
        would look like success.
        """
        role_arn = conn.role_arn(grant)
        key = (conn.tenant_id, grant.value)

        with self._lock:
            cached = self._cache.get(key)
            if cached is not None and not cached.stale:
                return {
                    "aws_access_key_id": cached.access_key_id,
                    "aws_secret_access_key": cached.secret_access_key,
                    "aws_session_token": cached.session_token,
                }

            resp = self._sts_client().assume_role(
                RoleArn=role_arn,
                # Session name appears in the customer's CloudTrail. Naming the
                # tenant and grant means their auditor can see exactly which
                # Kronagent connection took an action, without asking us.
                RoleSessionName=f"kronagent-{conn.tenant_id}-{grant.value}"[:64],
                ExternalId=conn.external_id,
                DurationSeconds=self._duration,
            )
            c = resp["Credentials"]
            self._cache[key] = _CachedCredentials(
                access_key_id=c["AccessKeyId"],
                secret_access_key=c["SecretAccessKey"],
                session_token=c["SessionToken"],
                expires_at=c["Expiration"],
            )
            _log.info("assumed %s role for tenant %s (expires %s)",
                      grant.value, conn.tenant_id, c["Expiration"].isoformat())
            return {
                "aws_access_key_id": c["AccessKeyId"],
                "aws_secret_access_key": c["SecretAccessKey"],
                "aws_session_token": c["SessionToken"],
            }

    def invalidate(self, tenant_id: str, grant: Optional[Grant] = None) -> None:
        """Drop cached credentials — after a permission change, or on any error
        suggesting the role was altered underneath us."""
        with self._lock:
            if grant is None:
                for k in [k for k in self._cache if k[0] == tenant_id]:
                    self._cache.pop(k, None)
            else:
                self._cache.pop((tenant_id, grant.value), None)


# --------------------------------------------------------------------------- #
# Preflight
# --------------------------------------------------------------------------- #

# Probed with a dry-run or read-only call each. Kept small on purpose: this runs
# at connect time and every health check, and a customer waiting on a spinner
# does not care that we verified thirty permissions.
_OBSERVE_PROBES: tuple[tuple[str, str], ...] = (
    ("sts:GetCallerIdentity", "sts"),
    ("guardduty:ListDetectors", "guardduty"),
    ("ec2:DescribeInstances", "ec2"),
)


@dataclass
class PreflightResult:
    ok: bool
    account_id: str = ""
    missing: list[str] = field(default_factory=list)
    error: str = ""

    def as_state(self) -> ConnectionState:
        if not self.ok:
            return ConnectionState.FAILED
        return ConnectionState.DEGRADED if self.missing else ConnectionState.HEALTHY


def preflight(conn: AwsConnection, broker: CredentialBroker,
              grant: Grant = Grant.OBSERVE) -> PreflightResult:
    """Verify a role actually works before reporting the connection healthy.

    A connection that looks configured but cannot read anything is worse than no
    connection: the customer believes they are protected. So this asks the
    account directly, and names the specific permissions that are missing rather
    than reporting a generic failure the customer cannot act on.

    Also checks that the account we reached is the account we expected. A
    mismatch means the role ARN belongs to a different account than the one
    recorded — misconfiguration at best.
    """
    try:
        creds = broker.credentials(conn, grant)
    except Exception as exc:  # noqa: BLE001 - surfaced to the customer verbatim
        return PreflightResult(ok=False, error=f"could not assume role: {exc}")

    missing: list[str] = []
    reached_account = ""

    for permission, service in _OBSERVE_PROBES:
        try:
            client = boto3_client(service, region=conn.region, credentials=creds)
            if service == "sts":
                reached_account = client.get_caller_identity()["Account"]
            elif service == "guardduty":
                client.list_detectors(MaxResults=1)
            else:
                client.describe_instances(MaxResults=5)
        except Exception as exc:  # noqa: BLE001
            _log.warning("preflight probe %s failed for tenant %s: %s",
                         permission, conn.tenant_id, exc)
            missing.append(permission)

    if reached_account and reached_account != conn.account_id:
        return PreflightResult(
            ok=False, account_id=reached_account,
            error=(f"role belongs to account {reached_account}, but this connection "
                   f"is recorded against {conn.account_id}"),
        )

    return PreflightResult(ok=True, account_id=reached_account or conn.account_id,
                           missing=missing)


def template_json(conn: AwsConnection, grant: Grant, *,
                  kronagent_account_id: str,
                  quarantine_nacl_id: str = "QUARANTINE_NACL_ID") -> str:
    """The template as the customer will see it — pretty-printed, because they
    are being asked to read it before granting access."""
    return json.dumps(
        render_template(conn, grant, kronagent_account_id=kronagent_account_id,
                        quarantine_nacl_id=quarantine_nacl_id),
        indent=2,
    )


def kronagent_account_id() -> str:
    """Our own account id, which customers' trust policies point at."""
    value = os.environ.get("KRONAGENT_AWS_ACCOUNT_ID", "").strip()
    if value and not _ACCOUNT_RE.match(value):
        raise ValueError(f"KRONAGENT_AWS_ACCOUNT_ID must be 12 digits, got {value!r}")
    return value


# --------------------------------------------------------------------------- #
# Persistence
# --------------------------------------------------------------------------- #

class ConnectionStore:
    """Connections on disk, one JSON document keyed by tenant.

    Same atomic-replace pattern as AllowlistStore and ApprovalStore, and the
    same read-on-demand behaviour, so a separate process (the connect API, an
    operator CLI) can add a connection and a running orchestrator observes it
    without a restart.

    One difference from the other stores, and it is the reason this class has
    its own file handling rather than reusing theirs: **this file contains
    secrets.** An External ID is the credential that lets Kronagent assume a
    customer's role. Leaked, together with a role ARN — which is not secret and
    appears in the customer's own CloudTrail — it is enough for a third party to
    ask AWS for that customer's role. So the file is created 0600 and the mode
    is re-asserted on every write, because os.replace() takes the permissions of
    the temp file, not of the file it replaces.
    """

    def __init__(self, path: str) -> None:
        self._path = path
        self._lock = threading.Lock()

    # --- persistence ---

    def _read_all(self) -> dict[str, dict]:
        if not os.path.exists(self._path):
            return {}
        try:
            with open(self._path, encoding="utf-8") as fh:
                return json.load(fh)
        except json.JSONDecodeError:
            # Unlike an allowlist, an unreadable connection file is not
            # something to shrug at: it means we cannot prove which account we
            # are entitled to touch. Fail loudly rather than silently behaving
            # as though no customer had ever connected.
            raise RuntimeError(
                f"connection store at {self._path} is corrupt — refusing to "
                "continue with an unknown set of tenant grants"
            ) from None

    def _write_all(self, data: dict[str, dict]) -> None:
        import tempfile

        directory = os.path.dirname(os.path.abspath(self._path)) or "."
        fd, tmp = tempfile.mkstemp(dir=directory, suffix=".tmp")
        try:
            os.chmod(tmp, 0o600)          # before any secret is written into it
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump(data, fh, indent=2, sort_keys=True)
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(tmp, self._path)
            # os.replace inherits the temp file's mode, but assert it anyway:
            # a store that silently became world-readable is exactly the failure
            # nobody notices.
            os.chmod(self._path, 0o600)
        finally:
            if os.path.exists(tmp):
                os.remove(tmp)

    # --- serialisation ---

    @staticmethod
    def _to_dict(conn: AwsConnection) -> dict:
        return {
            "tenant_id": conn.tenant_id,
            "account_id": conn.account_id,
            "region": conn.region,
            "external_id": conn.external_id,
            "observe_role_arn": conn.observe_role_arn,
            "contain_role_arn": conn.contain_role_arn,
            "state": conn.state.value,
            "missing_permissions": list(conn.missing_permissions),
            "last_verified": conn.last_verified.isoformat() if conn.last_verified else None,
        }

    @staticmethod
    def _from_dict(raw: dict) -> AwsConnection:
        verified = raw.get("last_verified")
        return AwsConnection(
            tenant_id=raw["tenant_id"],
            account_id=raw["account_id"],
            region=raw["region"],
            external_id=raw["external_id"],
            observe_role_arn=raw.get("observe_role_arn", ""),
            contain_role_arn=raw.get("contain_role_arn", ""),
            state=ConnectionState(raw.get("state", ConnectionState.PENDING.value)),
            missing_permissions=tuple(raw.get("missing_permissions", ())),
            last_verified=datetime.fromisoformat(verified) if verified else None,
        )

    # --- read path ---

    def get(self, tenant_id: str) -> Optional[AwsConnection]:
        raw = self._read_all().get(tenant_id)
        return self._from_dict(raw) if raw else None

    def list(self) -> list[AwsConnection]:
        return sorted(
            (self._from_dict(v) for v in self._read_all().values()),
            key=lambda c: c.tenant_id,
        )

    def credentials_resolver(self, broker: "CredentialBroker", grant: Grant):
        """A `credentials_for(tenant_id)` callable for the containment adapters.

        Returns None for a tenant with no connection or no containment grant,
        which the adapter reads as "use ambient credentials". That is correct
        for the single-tenant install and for local development — and it is why
        the caller must still check `can_contain` before *planning* containment,
        rather than relying on credential resolution to refuse.
        """
        def resolve(tenant_id: str) -> Optional[dict]:
            conn = self.get(tenant_id)
            if conn is None:
                return None
            if grant is Grant.CONTAIN and not conn.can_contain:
                return None
            return broker.credentials(conn, grant)

        return resolve

    # --- write path ---

    def put(self, conn: AwsConnection) -> AwsConnection:
        with self._lock:
            data = self._read_all()
            data[conn.tenant_id] = self._to_dict(conn)
            self._write_all(data)
        return conn

    def create(self, *, tenant_id: str, account_id: str, region: str) -> AwsConnection:
        """Begin a connection: mint an External ID and record it as pending.

        Refuses to overwrite an existing tenant. Re-minting an External ID would
        silently invalidate the trust policy the customer already installed, and
        the only symptom would be containment failing during an incident.
        """
        with self._lock:
            if tenant_id in self._read_all():
                raise ValueError(
                    f"tenant {tenant_id!r} is already connected — rotating the "
                    "External ID requires deleting the connection and having "
                    "the customer reinstall the stack"
                )
        return self.put(AwsConnection(
            tenant_id=tenant_id, account_id=account_id, region=region,
            external_id=new_external_id(),
        ))

    def record_role(self, tenant_id: str, grant: Grant, role_arn: str) -> AwsConnection:
        """Attach a role ARN once the customer's stack has produced one."""
        conn = self.get(tenant_id)
        if conn is None:
            raise KeyError(f"no connection for tenant {tenant_id!r}")
        field_name = "observe_role_arn" if grant is Grant.OBSERVE else "contain_role_arn"
        from dataclasses import replace
        return self.put(replace(conn, **{field_name: role_arn}))

    def record_preflight(self, tenant_id: str, result: "PreflightResult") -> AwsConnection:
        conn = self.get(tenant_id)
        if conn is None:
            raise KeyError(f"no connection for tenant {tenant_id!r}")
        from dataclasses import replace
        return self.put(replace(
            conn,
            state=result.as_state(),
            missing_permissions=tuple(result.missing),
            last_verified=datetime.now(timezone.utc),
        ))

    def delete(self, tenant_id: str) -> bool:
        """Forget a tenant. The customer should also delete their stack — this
        only stops us from trying."""
        with self._lock:
            data = self._read_all()
            existed = data.pop(tenant_id, None) is not None
            if existed:
                self._write_all(data)
        return existed
