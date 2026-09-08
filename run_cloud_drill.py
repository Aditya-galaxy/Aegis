#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Aditya Kumar, trading as Kronagent · https://kronagent.com
# Source-available, not open source. Commercial use requires a licence —
# see LICENSE or contact licensing@kronagent.com
"""
Execute → verify → roll back → verify, against real AWS or a moto simulation.

This is the only thing that can answer questions the static invariants in
tests/test_grant_sufficiency.py explicitly cannot: whether the Resource ARNs are
wide enough and the Condition blocks satisfiable. `ec2:ModifyInstanceAttribute`
is the live example — AWS evaluates it against the security group named in
`Groups=` as well as the instance, which no action-name comparison can see.

ARMING. This creates and deletes real IAM users, network ACLs and (with
--with-instances) EC2 instances. It used to arm itself on the mere presence of
credentials, which on a developer laptop very often means production. It now
requires --live AND an environment variable, because having credentials is not
the same as consenting to have resources created with them.
"""
import argparse
import asyncio
import json
import os
import random
import string
import boto3
from kronagent.providers.aws import AwsContainmentAdapter
from kronagent.schemas import ProposedAction, ActionClass

ARM_VAR = "KRONAGENT_CLOUD_DRILL_ARM"
ARM_VALUE = "i-understand-this-creates-and-deletes-real-resources"

# Helper to generate unique suffixes for resources
def get_random_suffix(length: int = 8) -> str:
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=length))

def _smallest_ami(region: str, mock_mode: bool) -> str:
    """A current Amazon Linux AMI for this region, via the SSM public parameter.

    Hardcoding an AMI id would work in one region and one month. moto does not
    serve the parameter, so simulation falls back to a well-formed placeholder —
    moto accepts any syntactically valid image id.
    """
    if mock_mode:
        return "ami-12345678901234567"
    return boto3.client("ssm", region_name=region).get_parameter(
        Name="/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
    )["Parameter"]["Value"]


def whoami(region: str) -> str:
    """The account these credentials actually reach.

    Printed before anything is created, because "which account am I about to
    make an IAM user in" is the question the old credential-sniffing behaviour
    never gave anyone the chance to ask.
    """
    try:
        return boto3.client("sts", region_name=region).get_caller_identity()["Account"]
    except Exception as exc:  # noqa: BLE001
        return f"<unknown: {type(exc).__name__}>"


def adapter_for_tenant(tenant: str, region: str, nacl_id: str, sg_id: str = ""):
    """A containment adapter using the tenant's own assumed containment role.

    This is the only configuration that exercises the thing customers actually
    use: AssumeRole with the External ID, under the policy they granted. Without
    it the drill runs on ambient credentials — usually an admin — and proves the
    boto3 calls are well-formed while proving nothing at all about whether the
    granted role permits them.
    """
    from kronagent.config import Settings
    from kronagent.connect import ConnectionStore, CredentialBroker, Grant
    from kronagent.orchestrator import get_tenant_path

    settings = Settings.from_env()
    store = ConnectionStore(get_tenant_path(settings.connection_store_path, tenant))
    conn = store.get(tenant)
    if conn is None:
        raise SystemExit(f"[-] no connection recorded for tenant '{tenant}'")
    if not conn.can_contain:
        raise SystemExit(
            f"[-] tenant '{tenant}' has no contain role installed — the customer "
            f"has not granted containment permissions, so there is nothing to drill")

    broker = CredentialBroker()
    print(f"[*] Assuming {conn.contain_role_arn} for tenant '{tenant}'")
    return AwsContainmentAdapter(
        region=region, quarantine_nacl_id=nacl_id,
        quarantine_security_group_id=sg_id,
        credentials_for=lambda _tid, c=conn, b=broker: b.credentials(c, Grant.CONTAIN),
    )

async def run_drill(region: str, mock_mode: bool, tenant: str | None = None,
                    with_instances: bool = False) -> dict:
    suffix = get_random_suffix()
    user_name = f"kronagent-drill-user-{suffix}"
    
    iam = boto3.client("iam", region_name=region)
    ec2 = boto3.client("ec2", region_name=region)
    
    # 1. Setup Temporary Drill Resources
    print(f"[*] Deploying temporary drill resources in region '{region}'...")
    
    # Create IAM User
    print(f"    - Creating IAM User: {user_name}")
    iam.create_user(UserName=user_name)
    
    # Create Access Key
    print(f"    - Creating Access Key for user: {user_name}")
    key_resp = iam.create_access_key(UserName=user_name)
    access_key_id = key_resp["AccessKey"]["AccessKeyId"]
    
    # Fetch VPC ID for NACL
    vpcs = ec2.describe_vpcs()
    vpc_id = vpcs["Vpcs"][0]["VpcId"]
    
    # Create Network ACL
    print(f"    - Creating temporary Network ACL in VPC: {vpc_id}")
    nacl_resp = ec2.create_network_acl(VpcId=vpc_id)
    nacl_id = nacl_resp["NetworkAcl"]["NetworkAclId"]
    
    # Initialize the adapter. With --tenant this assumes the customer's own
    # contain role, which is the only way the drill exercises the policy they
    # actually granted rather than whatever ambient credentials happen to allow.
    adapter = (adapter_for_tenant(tenant, region, nacl_id)
               if tenant else
               AwsContainmentAdapter(region=region, quarantine_nacl_id=nacl_id))
    results: dict = {}
    
    try:
        # ------------------------------------------------------------------- #
        # DRILL 1: ATTACH_DENY_ALL_TO_PRINCIPAL
        # ------------------------------------------------------------------- #
        print("\n[+] --- DRILL 1: ATTACH_DENY_ALL_TO_PRINCIPAL ---")
        action1 = ProposedAction(
            action_class=ActionClass.ATTACH_DENY_ALL_TO_PRINCIPAL,
            target=user_name,
            provider="aws",
            rationale="Kronagent Cloud Drill"
        )
        print("[*] Executing containment action...")
        detail1, rollback1 = await adapter.perform(action1)
        print(f"[+] Containment result: {detail1}")
        print(f"    Rollback command hint: {rollback1}")
        
        # Verify state
        print("[*] Verifying resource state in AWS...")
        policies = iam.list_user_policies(UserName=user_name)
        policy_names = policies.get("PolicyNames", [])
        if "kronagent-quarantine-deny-all" not in policy_names:
            raise RuntimeError("Verification failed: Deny-all policy is not attached to IAM User.")
        print("[+] SUCCESS: Deny-all policy verified on IAM User.")
        
        # Chaos Rollback Drill
        print("[*] Executing Chaos Rollback...")
        iam.delete_user_policy(UserName=user_name, PolicyName="kronagent-quarantine-deny-all")
        
        # Verify rollback
        print("[*] Verifying rollback state...")
        policies = iam.list_user_policies(UserName=user_name)
        if "kronagent-quarantine-deny-all" in policies.get("PolicyNames", []):
            raise RuntimeError("Verification failed: Deny-all policy was not deleted during rollback.")
        print("[+] SUCCESS: Rollback verified (Deny-all policy removed).")
        results["attach_deny_all_to_principal"] = {"ok": True, "executed": True, "verified": True, "rolled_back": True, "rollback_verified": True}
        
        # ------------------------------------------------------------------- #
        # DRILL 2: DISABLE_ACCESS_KEY
        # ------------------------------------------------------------------- #
        print("\n[+] --- DRILL 2: DISABLE_ACCESS_KEY ---")
        action2 = ProposedAction(
            action_class=ActionClass.DISABLE_ACCESS_KEY,
            target=access_key_id,
            provider="aws",
            parameters={"user_name": user_name},
            rationale="Kronagent Cloud Drill"
        )
        print("[*] Executing containment action...")
        detail2, rollback2 = await adapter.perform(action2)
        print(f"[+] Containment result: {detail2}")
        print(f"    Rollback command hint: {rollback2}")
        
        # Verify state
        print("[*] Verifying access key state in AWS...")
        keys = iam.list_access_keys(UserName=user_name)
        key_metadata = next(k for k in keys["AccessKeyMetadata"] if k["AccessKeyId"] == access_key_id)
        if key_metadata["Status"] != "Inactive":
            raise RuntimeError("Verification failed: Access key is still active.")
        print("[+] SUCCESS: Access key state is Inactive.")
        
        # Chaos Rollback Drill
        print("[*] Executing Chaos Rollback...")
        iam.update_access_key(UserName=user_name, AccessKeyId=access_key_id, Status="Active")
        
        # Verify rollback
        print("[*] Verifying rollback state...")
        keys = iam.list_access_keys(UserName=user_name)
        key_metadata = next(k for k in keys["AccessKeyMetadata"] if k["AccessKeyId"] == access_key_id)
        if key_metadata["Status"] != "Active":
            raise RuntimeError("Verification failed: Access key was not reactivated during rollback.")
        print("[+] SUCCESS: Rollback verified (Access key reactivated).")
        results["disable_access_key"] = {"ok": True, "executed": True, "verified": True, "rolled_back": True, "rollback_verified": True}
        
        # ------------------------------------------------------------------- #
        # DRILL 3: BLOCK_IP
        # ------------------------------------------------------------------- #
        print("\n[+] --- DRILL 3: BLOCK_IP ---")
        action3 = ProposedAction(
            action_class=ActionClass.BLOCK_IP,
            target="99.99.99.99",
            provider="aws",
            rationale="Kronagent Cloud Drill"
        )
        print("[*] Executing containment action...")
        detail3, rollback3 = await adapter.perform(action3)
        print(f"[+] Containment result: {detail3}")
        print(f"    Rollback command hint: {rollback3}")
        
        # Verify state
        print("[*] Verifying network ACL state in AWS...")
        acls = ec2.describe_network_acls(NetworkAclIds=[nacl_id])
        entries = acls["NetworkAcls"][0]["Entries"]
        deny_entries = [e for e in entries if e["CidrBlock"] == "99.99.99.99/32" and e["RuleAction"] == "deny"]
        if len(deny_entries) < 2:  # Ingress and Egress deny rules
            raise RuntimeError("Verification failed: Ingress/Egress deny rule not found in NACL entries.")
        print("[+] SUCCESS: Remote IP block rules verified in Network ACL.")
        
        # Chaos Rollback Drill
        print("[*] Executing Chaos Rollback...")
        for entry in deny_entries:
            ec2.delete_network_acl_entry(
                NetworkAclId=nacl_id,
                RuleNumber=entry["RuleNumber"],
                Egress=entry["Egress"]
            )
            
        # Verify rollback
        print("[*] Verifying rollback state...")
        acls = ec2.describe_network_acls(NetworkAclIds=[nacl_id])
        entries = acls["NetworkAcls"][0]["Entries"]
        deny_entries = [e for e in entries if e["CidrBlock"] == "99.99.99.99/32" and e["RuleAction"] == "deny"]
        if len(deny_entries) > 0:
            raise RuntimeError("Verification failed: Deny rules were not deleted from NACL.")
        print("[+] SUCCESS: Rollback verified (Deny rules removed from NACL).")
        results["block_ip"] = {"ok": True, "executed": True, "verified": True, "rolled_back": True, "rollback_verified": True}
        
        # ------------------------------------------------------------------- #
        # DRILL 4: REVOKE_ROLE_SESSIONS
        #
        # Needs only an IAM role, so it is cheap and unconditional. It was
        # missing, and it is the action whose inline policy NAME the contain
        # template pinned wrongly — granted at the action level, denied at the
        # condition, and invisible to any check comparing action names.
        # ------------------------------------------------------------------- #
        print("\n[+] --- DRILL 4: REVOKE_ROLE_SESSIONS ---")
        role_name = f"kronagent-drill-role-{suffix}"
        iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow",
                           "Principal": {"Service": "ec2.amazonaws.com"},
                           "Action": "sts:AssumeRole"}]}))
        try:
            outcome = await adapter.perform(ProposedAction(
                provider="aws", action_class=ActionClass.REVOKE_ROLE_SESSIONS,
                target=role_name, rationale="cloud drill"))
            print(f"    - {outcome[0]}")

            # Verify with an independent read, not by trusting the return value.
            policies = iam.list_role_policies(RoleName=role_name)["PolicyNames"]
            assert "kronagent-revoke-sessions" in policies, (
                f"revoke policy absent after execution; role has {policies}")
            print("[+] SUCCESS: Session-revocation policy verified on IAM Role.")

            iam.delete_role_policy(RoleName=role_name,
                                   PolicyName="kronagent-revoke-sessions")
            assert not iam.list_role_policies(RoleName=role_name)["PolicyNames"]
            print("[+] SUCCESS: Rollback verified (revocation policy removed).")
            results["revoke_role_sessions"] = {
                "ok": True, "executed": True, "verified": True,
                "rolled_back": True, "rollback_verified": True}
        finally:
            try:
                for pn in iam.list_role_policies(RoleName=role_name)["PolicyNames"]:
                    iam.delete_role_policy(RoleName=role_name, PolicyName=pn)
                iam.delete_role(RoleName=role_name)
            except Exception as e:  # noqa: BLE001
                print(f"      [!] Failed to delete drill role: {e}")

        # ------------------------------------------------------------------- #
        # DRILL 5: ISOLATE_INSTANCE_SG  (--with-instances)
        #
        # The one drill that can settle a question no static check reaches.
        # tests/test_grant_sufficiency.py compares ACTION names; it cannot tell
        # whether a Resource ARN is wide enough. AWS evaluates
        # ec2:ModifyInstanceAttribute against the security group named in
        # Groups= as well as the instance, so an instance-only grant denies the
        # call with the action apparently granted. Under --tenant this is the
        # proof that the policy we ask customers to install actually works.
        # ------------------------------------------------------------------- #
        if with_instances:
            print("\n[+] --- DRILL 5: ISOLATE_INSTANCE_SG ---")
            instance_id = quarantine_sg = original_sg = None
            try:
                subnets = ec2.describe_subnets(
                    Filters=[{"Name": "vpc-id", "Values": [vpc_id]}])["Subnets"]
                if not subnets:
                    raise RuntimeError(f"no subnet in {vpc_id} to launch into")

                original_sg = ec2.create_security_group(
                    GroupName=f"kronagent-drill-orig-{suffix}",
                    Description="drill: the group the instance starts in",
                    VpcId=vpc_id)["GroupId"]
                quarantine_sg = ec2.create_security_group(
                    GroupName=f"kronagent-drill-quarantine-{suffix}",
                    Description="drill: deny-all quarantine group",
                    VpcId=vpc_id)["GroupId"]
                # A brand-new SG has no ingress rules; revoke the default egress
                # so it is genuinely deny-all rather than deny-inbound-only.
                try:
                    ec2.revoke_security_group_egress(
                        GroupId=quarantine_sg,
                        IpPermissions=[{"IpProtocol": "-1",
                                        "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}])
                except Exception:  # noqa: BLE001 - moto may not model the default rule
                    pass

                ami = _smallest_ami(region, mock_mode)
                print(f"    - Launching t3.micro from {ami}")
                instance_id = ec2.run_instances(
                    ImageId=ami, InstanceType="t3.micro", MinCount=1, MaxCount=1,
                    SubnetId=subnets[0]["SubnetId"], SecurityGroupIds=[original_sg],
                    TagSpecifications=[{"ResourceType": "instance", "Tags": [
                        {"Key": "Name", "Value": f"kronagent-drill-{suffix}"}]}],
                )["Instances"][0]["InstanceId"]
                print(f"    - Instance: {instance_id}")

                isolator = (adapter_for_tenant(tenant, region, nacl_id, quarantine_sg)
                            if tenant else
                            AwsContainmentAdapter(
                                region=region, quarantine_nacl_id=nacl_id,
                                quarantine_security_group_id=quarantine_sg))
                outcome = await isolator.perform(ProposedAction(
                    provider="aws", action_class=ActionClass.ISOLATE_INSTANCE_SG,
                    target=instance_id, rationale="cloud drill"))
                print(f"    - {outcome[0]}")

                groups = [g["GroupId"] for g in ec2.describe_instances(
                    InstanceIds=[instance_id])["Reservations"][0]["Instances"][0]
                    ["SecurityGroups"]]
                assert groups == [quarantine_sg], (
                    f"instance is in {groups}, expected only {quarantine_sg}")
                print("[+] SUCCESS: Instance verified in the quarantine group.")

                ec2.modify_instance_attribute(InstanceId=instance_id,
                                              Groups=[original_sg])
                groups = [g["GroupId"] for g in ec2.describe_instances(
                    InstanceIds=[instance_id])["Reservations"][0]["Instances"][0]
                    ["SecurityGroups"]]
                assert groups == [original_sg], f"rollback left instance in {groups}"
                print("[+] SUCCESS: Rollback verified (original group restored).")
                results["isolate_instance_sg"] = {
                    "ok": True, "executed": True, "verified": True,
                    "rolled_back": True, "rollback_verified": True}
            except Exception as exc:  # noqa: BLE001
                print(f"[-] FAILED: {type(exc).__name__}: {exc}")
                results["isolate_instance_sg"] = {"ok": False, "error": str(exc)}
            finally:
                # Unconditional. A drill that leaves a running instance behind
                # is a drill nobody runs twice.
                if instance_id:
                    try:
                        print(f"    - Terminating {instance_id}")
                        ec2.terminate_instances(InstanceIds=[instance_id])
                        if not mock_mode:
                            ec2.get_waiter("instance_terminated").wait(
                                InstanceIds=[instance_id])
                    except Exception as e:  # noqa: BLE001
                        print(f"      [!] Failed to terminate instance: {e}")
                for gid in (quarantine_sg, original_sg):
                    if gid:
                        try:
                            ec2.delete_security_group(GroupId=gid)
                        except Exception as e:  # noqa: BLE001
                            print(f"      [!] Failed to delete {gid}: {e}")

        print("\n[+] ============================================================")
        print("[+]           ALL CLOUD CONTAINMENT DRILLS PASSED")
        print("[+] ============================================================")
        
    finally:
        print("\n[*] Cleaning up temporary drill resources...")
        try:
            print(f"    - Deleting Access Key: {access_key_id}")
            iam.delete_access_key(UserName=user_name, AccessKeyId=access_key_id)
        except Exception as e:
            print(f"      [!] Failed to delete access key: {e}")
            
        try:
            print(f"    - Deleting IAM User: {user_name}")
            iam.delete_user(UserName=user_name)
        except Exception as e:
            print(f"      [!] Failed to delete IAM user: {e}")
            
        try:
            print(f"    - Deleting Network ACL: {nacl_id}")
            ec2.delete_network_acl(NetworkAclId=nacl_id)
        except Exception as e:
            print(f"      [!] Failed to delete network ACL: {e}")
        print("[*] Cleanup complete.")
    return results

def _parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--live", action="store_true",
                    help=f"run against a real AWS account. Also requires "
                         f"{ARM_VAR}={ARM_VALUE}. Without --live the drill runs "
                         f"against moto and touches nothing.")
    ap.add_argument("--tenant",
                    help="drive containment through this tenant's assumed "
                         "contain role instead of ambient credentials. This is "
                         "the only mode that tests the grant a customer gave us.")
    ap.add_argument("--region", default=os.environ.get("AWS_DEFAULT_REGION", "us-east-1"))
    ap.add_argument("--with-instances", action="store_true",
                    help="also drill ISOLATE_INSTANCE_SG, which needs a real EC2 "
                         "instance and a quarantine security group. This is the "
                         "only check that can settle whether the granted "
                         "Resource ARNs are wide enough — AWS evaluates "
                         "ModifyInstanceAttribute against the security group in "
                         "Groups= as well as the instance, which no static check "
                         "can see.")
    ap.add_argument("--json", dest="json_out", metavar="PATH",
                    help="write machine-readable per-action results here")
    return ap


def _armed(args) -> bool:
    """Whether a live run has been consented to, as opposed to merely enabled.

    Two independent gestures on purpose. --live alone is one typo away from a
    simulation flag; the environment variable spells out what it authorises.
    Credential presence — the previous and only gate — expresses no intent at
    all: it is the normal state of a developer's shell, frequently pointed at
    production.
    """
    if not args.live:
        return False
    if os.environ.get(ARM_VAR) != ARM_VALUE:
        print(f"[-] --live requires {ARM_VAR}={ARM_VALUE}\n"
              f"    This drill CREATES AND DELETES real IAM users, network ACLs\n"
              f"    and, with --with-instances, EC2 instances. Set it only for an\n"
              f"    account you are willing to have resources created in.\n"
              f"    Credentials currently reach account: {whoami(args.region)}")
        raise SystemExit(2)
    return True


async def main(argv=None) -> int:
    args = _parser().parse_args(argv)
    region = args.region

    if _armed(args):
        print(f"[*] LIVE mode, region {region}, account {whoami(region)}")
        if args.tenant:
            print(f"[*] Containment will run under tenant '{args.tenant}'s assumed role")
        else:
            print("[!] Containment will run under AMBIENT credentials. This does "
                  "NOT exercise the customer's granted policy — pass --tenant to "
                  "drill the path a customer actually uses.")
        results = await run_drill(region, mock_mode=False, tenant=args.tenant,
                                  with_instances=args.with_instances)
    else:
        if args.live:  # unreachable: _armed raises. Kept as a belt on the brace.
            raise SystemExit(2)
        print("[*] SIMULATION mode (moto). Nothing real is touched. Pass --live "
              f"with {ARM_VAR} set to drill a real account.")
        try:
            from moto import mock_aws
        except ImportError:
            print("[-] 'moto' is required for the simulated drill. pip install moto")
            return 1

        with mock_aws():
            ec2 = boto3.client("ec2", region_name=region)
            ec2.create_vpc(CidrBlock="10.0.0.0/16")
            # Derive the subnet range from whichever VPC run_drill will pick,
            # rather than assuming: moto lists its own default VPC first.
            v = ec2.describe_vpcs()["Vpcs"][0]
            base = v["CidrBlock"].split(".")
            ec2.create_subnet(VpcId=v["VpcId"],
                              CidrBlock=f"{base[0]}.{base[1]}.99.0/24")
            results = await run_drill(region, mock_mode=True, tenant=None,
                                      with_instances=args.with_instances)

    if args.json_out and results is not None:
        with open(args.json_out, "w", encoding="utf-8") as fh:
            json.dump(results, fh, indent=2)
        print(f"[*] Results written to {args.json_out}")

    failed = [k for k, v in (results or {}).items() if not v.get("ok")]
    if failed:
        print(f"\n[-] FAILED: {failed}")
        return 1
    return 0


def cli() -> int:
    """Console-script entry point for `kronagent-cloud-drill`."""
    try:
        return asyncio.run(main()) or 0
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    raise SystemExit(cli())
