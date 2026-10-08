"""A seeded AWS account inside the moto emulator, for testing the cloud state collector through the real boto3 code path.

Nothing here talks to AWS. `seed()` must be called inside `moto.mock_aws()`. It creates a small account with known
misconfigurations AND harmless look-alikes that must NOT be flagged, and returns the findings each rule is expected
to raise (the labels are written by the seeder, independent of the collector and the rules).
"""
import json
from datetime import datetime, timedelta, timezone

OWN = "123456789012"                       # the account id moto uses
OTHER = "999999999999"
REGION, REGION2 = "us-east-1", "us-west-2"


def _admin_doc():
    return json.dumps({"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]})


def _trust(principal, cond=None):
    st = {"Effect": "Allow", "Principal": principal, "Action": "sts:AssumeRole"}
    if cond:
        st["Condition"] = cond
    return json.dumps({"Version": "2012-10-17", "Statement": [st]})


def seed(shift_days=190):
    """Returns dict(keys=..., expected=..., created=...). Keys created before `shift_days` days from now look old when the
    collector is run with now = real now + 200 days; the 'fresh' key is created later (freezegun) and stays young."""
    import boto3
    from freezegun import freeze_time
    kw = dict(region_name=REGION, aws_access_key_id="x", aws_secret_access_key="y")
    iam, s3, ct, ec2 = (boto3.client(s, **kw) for s in ("iam", "s3", "cloudtrail", "ec2"))
    created = dict(users=0, roles=0, buckets=0, trails=0)
    keys = {}

    # ---- IAM: policies, groups, users
    iam.create_policy(PolicyName="PowerAll", PolicyDocument=_admin_doc())                       # a customer-managed policy that is a full administrator
    pa = f"arn:aws:iam::{OWN}:policy/PowerAll"
    iam.create_policy(PolicyName="AdministratorAccess", PolicyDocument=_admin_doc())           # same name as the AWS-managed one
    aa = f"arn:aws:iam::{OWN}:policy/AdministratorAccess"
    iam.create_group(GroupName="admins"); iam.attach_group_policy(GroupName="admins", PolicyArn=aa)

    def user(name, console=False, mfa=False, key=None, admin_direct=None, group=None):
        iam.create_user(UserName=name); created["users"] += 1
        if console:
            iam.create_login_profile(UserName=name, Password="Aa1!aaaaaaaaaa")
        if mfa:
            dev = iam.create_virtual_mfa_device(VirtualMFADeviceName=f"{name}-mfa")["VirtualMFADevice"]
            iam.enable_mfa_device(UserName=name, SerialNumber=dev["SerialNumber"], AuthenticationCode1="123456", AuthenticationCode2="654321")
        if key:
            k = iam.create_access_key(UserName=name)["AccessKey"]["AccessKeyId"]
            keys[name] = k
            if key == "inactive":
                iam.update_access_key(UserName=name, AccessKeyId=k, Status="Inactive")
        if admin_direct:
            iam.attach_user_policy(UserName=name, PolicyArn=admin_direct)
        if group:
            iam.add_user_to_group(GroupName=group, UserName=name)

    user("alice", console=True, key="active", admin_direct=pa)                 # admin (custom policy) without MFA, stale key
    user("bob", console=True, mfa=True, group="admins")                        # admin via group WITH MFA: must not flag admin_without_mfa
    user("carol", key="inactive")                                              # inactive key: must not flag
    user("app-uploader", key="active")                                         # ordinary user, active old key (stale)
    user("ci-bot", key="active")                                               # ordinary user, active old key never used (stale)
    with freeze_time(datetime.now(timezone.utc) + timedelta(days=shift_days)):
        user("fresh", key="active")                                            # key only ~10 days old at collection: must not flag

    # ---- roles
    def role(name, principal, cond=None, path="/"):
        iam.create_role(RoleName=name, AssumeRolePolicyDocument=_trust(principal, cond), Path=path); created["roles"] += 1
    role("cross-acct", {"AWS": f"arn:aws:iam::{OTHER}:root"})                   # trusts another account
    role("open-role", "*")                                                      # anyone
    role("open-but-conditioned", "*", cond={"StringEquals": {"aws:PrincipalOrgID": "o-abc123"}})   # conditional: must not flag
    role("svc-role", {"Service": "ec2.amazonaws.com"})                          # service trust: must not flag
    role("same-account", {"AWS": f"arn:aws:iam::{OWN}:root"})                   # own account: must not flag

    # ---- S3
    full = dict(BlockPublicAcls=True, IgnorePublicAcls=True, BlockPublicPolicy=True, RestrictPublicBuckets=True)
    off = {k: False for k in full}

    def bucket(name, pab=None, policy=None):
        s3.create_bucket(Bucket=name); created["buckets"] += 1
        if pab is not None:
            s3.put_public_access_block(Bucket=name, PublicAccessBlockConfiguration=pab)
        if policy is not None:
            s3.put_bucket_policy(Bucket=name, Policy=json.dumps(policy))
    for b in ("trail-logs-a", "trail-logs-b", "trail-logs-c", "logs-private", "backups"):
        bucket(b, pab=full)                                                     # fully blocked: must not flag
    bucket("data-public", pab=off, policy={"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::data-public/*"}]})   # public policy
    bucket("reports-open")                                                      # no public access block configured

    # ---- CloudTrail
    for name, bkt, validation, logging in (("trail-a", "trail-logs-a", True, True), ("trail-b", "trail-logs-b", True, False), ("trail-c", "trail-logs-c", False, True)):
        ct.create_trail(Name=name, S3BucketName=bkt, IsMultiRegionTrail=True, EnableLogFileValidation=validation); created["trails"] += 1
        (ct.start_logging if logging else ct.stop_logging)(Name=name)

    # ---- security groups: region 1 and a second region
    def sg(client, name, rules):
        g = client.create_security_group(GroupName=name, Description=name)["GroupId"]
        for proto, lo, hi, cidr in rules:
            perm = {"IpProtocol": proto, "IpRanges": [{"CidrIp": cidr}]}
            if proto != "-1":
                perm.update(FromPort=lo, ToPort=hi)
            client.authorize_security_group_ingress(GroupId=g, IpPermissions=[perm])
    sg(ec2, "ssh-world", [("tcp", 22, 22, "0.0.0.0/0")]); sg(ec2, "rdp-world", [("tcp", 3389, 3389, "0.0.0.0/0")]); sg(ec2, "all-open", [("-1", None, None, "0.0.0.0/0")])
    sg(ec2, "web-443", [("tcp", 443, 443, "0.0.0.0/0")]); sg(ec2, "db-internal", [("tcp", 5432, 5432, "10.0.0.0/8")])
    ec2b = boto3.client("ec2", **dict(kw, region_name=REGION2))
    sg(ec2b, "ssh-world-west", [("tcp", 22, 22, "0.0.0.0/0")])

    expected = dict(admin_without_mfa=1, stale_access_key=3, trail_logging_off=1, trail_no_log_validation=1, role_trusts_external_account=1, role_trusts_anyone=1,
                    public_bucket=1, bucket_public_access_not_blocked=1, sg_world_open_admin_port=3, root_mfa_missing=1)
    expected_all_regions = dict(expected, sg_world_open_admin_port=4)
    return dict(keys=keys, expected=expected, expected_all_regions=expected_all_regions, created=created)
