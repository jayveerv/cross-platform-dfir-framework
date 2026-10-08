"""AWS account-state collector (Acquisition layer, cloud side). READ-ONLY.

CloudTrail says what happened; the account state says what an attacker could do, what was switched off and what was
open when the investigation started. This module reads that state with boto3 and writes JSON files that
normalize.parse_cloud() turns into events, so the posture rules in correlate.py can run on them.

Files written to <out_dir>/cloud/:
  identity.json         who collected, which account, when (collected_at is the reference time for key ages)
  trails.json           CloudTrail trails: logging on/off, multi-region, log-file validation
  iam_account.json      root MFA (account summary)
  iam_users.json        users, MFA devices, administrator rights (direct, group, inline, customer-managed policy document),
                        access keys with age and last use
  iam_roles.json        roles and who can assume them
  s3_buckets.json       public access block and public bucket policy per bucket
  security_groups.json  inbound rules (one region, or every region with all_regions=True)
  manifest.json         SHA-256 of every file, API operations used, denied/failed calls, what could NOT be collected

Only List*/Get*/Describe* operations are used (READ_PREFIXES); the emulator test checks this.
A call that is denied is recorded as UNKNOWN, never as "missing": a user whose MFA could not be read is not called
"no MFA".
Required read-only permissions: sts:GetCallerIdentity, cloudtrail:DescribeTrails, cloudtrail:GetTrailStatus,
iam:GetAccountSummary, iam:ListUsers, iam:ListRoles, iam:ListAccessKeys, iam:GetAccessKeyLastUsed, iam:ListMFADevices,
iam:ListAttachedUserPolicies, iam:ListUserPolicies, iam:GetUserPolicy, iam:ListGroupsForUser, iam:ListAttachedGroupPolicies,
iam:ListGroupPolicies, iam:GetGroupPolicy, iam:GetPolicy, iam:GetPolicyVersion, s3:ListAllMyBuckets,
s3:GetBucketPublicAccessBlock, s3:GetBucketPolicyStatus, s3:GetBucketPolicy, ec2:DescribeSecurityGroups, ec2:DescribeRegions.
"""
import hashlib
import json
import os
import urllib.parse
from datetime import datetime, timezone

READ_PREFIXES = ("List", "Get", "Describe")
ADMIN_MANAGED = "arn:aws:iam::aws:policy/AdministratorAccess"
NORMAL_MISSING = {"NoSuchPublicAccessBlockConfiguration", "NoSuchBucketPolicy", "NoSuchEntity", "TrailNotFoundException"}
DENIED = {"AccessDenied", "AccessDeniedException", "UnauthorizedOperation", "UnauthorizedAccess", "AuthorizationError"}


def _iso(dt):
    if dt is None:
        return None
    if isinstance(dt, str):
        return dt
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _sha(path):
    with open(path, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


def _doc(d):
    """IAM returns policy documents as dicts (boto3 decodes them) or URL-encoded JSON strings."""
    if isinstance(d, dict):
        return d
    if not d:
        return {}
    try:
        return json.loads(urllib.parse.unquote(d))
    except ValueError:
        return {}


def _as_list(v):
    return v if isinstance(v, list) else ([] if v is None else [v])


def doc_is_admin(doc):
    """True when a policy document allows every action on every resource (Effect Allow, Action '*', Resource '*')."""
    for st in _as_list(_doc(doc).get("Statement")):
        if st.get("Effect") != "Allow" or "NotAction" in st or "Condition" in st:
            continue
        if "*" in _as_list(st.get("Action")) and "*" in _as_list(st.get("Resource")):
            return True
    return False


def doc_is_public(doc):
    """Bucket policy evaluation used when GetBucketPolicyStatus is not available: Allow to everyone without a condition."""
    for st in _as_list(_doc(doc).get("Statement")):
        if st.get("Effect") != "Allow" or "Condition" in st:
            continue
        p = st.get("Principal")
        if p == "*" or (isinstance(p, dict) and "*" in _as_list(p.get("AWS"))):
            return True
    return False


def trust_entries(doc):
    """Who can assume a role: list of dict(principal, type, conditional)."""
    out = []
    for st in _as_list(_doc(doc).get("Statement")):
        if st.get("Effect") != "Allow":
            continue
        cond = bool(st.get("Condition"))
        p = st.get("Principal")
        if p == "*":
            out.append(dict(principal="*", type="*", conditional=cond))
            continue
        if isinstance(p, dict):
            for typ, vals in p.items():
                for v in _as_list(vals):
                    out.append(dict(principal=str(v), type=typ, conditional=cond))
    return out


class _Collector:
    def __init__(self, out_dir, session, region, now, log):
        self.dir = os.path.join(out_dir, "cloud")
        os.makedirs(self.dir, exist_ok=True)
        self.session, self.region, self.now, self.log = session, region, now, log
        self.ops, self.errors, self.limited, self.artifacts = [], [], {}, []
        self.clients = {}

    def client(self, service, region=None):
        k = (service, region or self.region)
        if k not in self.clients:
            self.clients[k] = self.session.client(service, region_name=region or self.region)
        return self.clients[k]

    def _op(self, client, method):
        name = client.meta.method_to_api_mapping.get(method, method)
        if not name.startswith(READ_PREFIXES):
            raise RuntimeError(f"refusing to call a non-read operation: {name}")
        if name not in self.ops:
            self.ops.append(name)
        return name

    def call(self, client, method, quiet=(), **kw):
        """Returns (response, error_code). Expected 'not configured' errors are not reported as errors."""
        name = self._op(client, method)
        try:
            return getattr(client, method)(**kw), None
        except Exception as e:
            code = getattr(e, "response", {}).get("Error", {}).get("Code", "") or type(e).__name__
            if code not in NORMAL_MISSING and code not in quiet:
                self.errors.append(f"{name}: {code}")
            return None, code

    def pages(self, client, method, key, **kw):
        """All items of a paginated List/Describe call, or (None, code) on error."""
        name = self._op(client, method)
        items = []
        try:
            for page in client.get_paginator(method).paginate(**kw):
                items += page.get(key, [])
            return items, None
        except Exception as e:
            code = getattr(e, "response", {}).get("Error", {}).get("Code", "") or type(e).__name__
            self.errors.append(f"{name}: {code}")
            return None, code

    def write(self, name, obj, note):
        p = os.path.join(self.dir, name)
        with open(p, "w", encoding="utf-8") as f:
            json.dump(obj, f, indent=1, default=str)
        self.artifacts.append(dict(name=name, sha256=_sha(p), size=os.path.getsize(p), note=note))

    # ------------------------------------------------------------------ artifacts
    def identity(self):
        r, code = self.call(self.client("sts"), "get_caller_identity")
        self.account = (r or {}).get("Account")
        self.write("identity.json", dict(collected_at=_iso(self.now), account=self.account, arn=(r or {}).get("Arn"), region=self.region,
                                         known=r is not None), "caller identity and collection time")

    def trails(self):
        ct = self.client("cloudtrail")
        r, code = self.call(ct, "describe_trails", includeShadowTrails=False)
        if r is None:
            self.limited["trails"] = f"CloudTrail trails could not be read ({code})."
            self.write("trails.json", dict(listed=False, items=[]), "CloudTrail trails (NOT readable)")
            return
        items = []
        for t in r.get("trailList", []):
            st, scode = self.call(ct, "get_trail_status", Name=t.get("TrailARN") or t.get("Name"))
            items.append(dict(name=t.get("Name"), arn=t.get("TrailARN"), home_region=t.get("HomeRegion"), multi_region=t.get("IsMultiRegionTrail"),
                              organization=t.get("IsOrganizationTrail"), log_validation=t.get("LogFileValidationEnabled"), bucket=t.get("S3BucketName"),
                              is_logging=(st or {}).get("IsLogging") if st is not None else None,
                              stop_logging_time=_iso((st or {}).get("StopLoggingTime")), latest_delivery=_iso((st or {}).get("LatestDeliveryTime")),
                              delivery_error=(st or {}).get("LatestDeliveryError")))
        self.write("trails.json", dict(listed=True, items=items), "CloudTrail trails and logging status")

    def account_summary(self):
        r, code = self.call(self.client("iam"), "get_account_summary")
        if r is None:
            self.limited["iam_account"] = f"Account summary (root MFA) could not be read ({code})."
            self.write("iam_account.json", dict(known=False), "root MFA (NOT readable)")
            return
        m = r.get("SummaryMap", {})
        self.write("iam_account.json", dict(known=True, root_mfa=bool(m.get("AccountMFAEnabled")), users=m.get("Users"),
                                            root_access_keys=m.get("AccountAccessKeysPresent")), "root MFA, account summary")

    def _policy_admin(self, arn, cache):
        if arn == ADMIN_MANAGED:
            return True
        if arn in cache:
            return cache[arn]
        iam = self.client("iam")
        cache[arn] = None
        if arn.startswith("arn:aws:iam::aws:policy/"):
            cache[arn] = False                  # other AWS-managed policies are not full administrator
            return False
        p, code = self.call(iam, "get_policy", PolicyArn=arn)
        if p is None:
            return None
        v, code = self.call(iam, "get_policy_version", PolicyArn=arn, VersionId=p["Policy"]["DefaultVersionId"])
        if v is None:
            return None
        cache[arn] = doc_is_admin(v["PolicyVersion"].get("Document"))
        return cache[arn]

    def users(self):
        iam = self.client("iam")
        users, code = self.pages(iam, "list_users", "Users")
        if users is None:
            self.limited["iam_users"] = f"IAM users could not be listed ({code})."
            self.write("iam_users.json", dict(listed=False, items=[]), "IAM users (NOT readable)")
            return
        cache, gcache, items, unknown = {}, {}, [], 0
        for u in users:
            name = u["UserName"]
            admin, via, policies = False, [], []
            att, c1 = self.pages(iam, "list_attached_user_policies", "AttachedPolicies", UserName=name)
            for p in att or []:
                policies.append(p["PolicyName"])
                if self._policy_admin(p["PolicyArn"], cache):
                    admin = True
                    via.append(f"policy {p['PolicyName']}")
            inl, c2 = self.pages(iam, "list_user_policies", "PolicyNames", UserName=name)
            for pn in inl or []:
                d, _ = self.call(iam, "get_user_policy", UserName=name, PolicyName=pn)
                if d and doc_is_admin(d.get("PolicyDocument")):
                    admin = True
                    via.append(f"inline {pn}")
            groups, c3 = self.pages(iam, "list_groups_for_user", "Groups", UserName=name)
            gnames, gpols = [], []
            for g in groups or []:
                gn = g["GroupName"]
                gnames.append(gn)
                if gn not in gcache:
                    gadmin, gp = False, []
                    ga, _ = self.pages(iam, "list_attached_group_policies", "AttachedPolicies", GroupName=gn)
                    for p in ga or []:
                        gp.append(p["PolicyName"])
                        if self._policy_admin(p["PolicyArn"], cache):
                            gadmin = True
                    gi, _ = self.pages(iam, "list_group_policies", "PolicyNames", GroupName=gn)
                    for pn in gi or []:
                        d, _ = self.call(iam, "get_group_policy", GroupName=gn, PolicyName=pn)
                        if d and doc_is_admin(d.get("PolicyDocument")):
                            gadmin = True
                    gcache[gn] = (gadmin, gp)
                if gcache[gn][0]:
                    admin = True
                    via.append(f"group {gn}")
                gpols += gcache[gn][1]
            mfa, c4 = self.pages(iam, "list_mfa_devices", "MFADevices", UserName=name)
            keys, c5 = self.pages(iam, "list_access_keys", "AccessKeyMetadata", UserName=name)
            krec = []
            for k in keys or []:
                lu, _ = self.call(iam, "get_access_key_last_used", AccessKeyId=k["AccessKeyId"])
                last = (lu or {}).get("AccessKeyLastUsed", {})
                krec.append(dict(key_id=k["AccessKeyId"], status=k.get("Status"), created=_iso(k.get("CreateDate")),
                                 last_used=_iso(last.get("LastUsedDate")), last_service=last.get("ServiceName"), last_region=last.get("Region")))
            known = all(c is None for c in (c1, c2, c3))
            if not known or c4 is not None:
                unknown += 1
            items.append(dict(user=name, created=_iso(u.get("CreateDate")), password_last_used=_iso(u.get("PasswordLastUsed")),
                              is_admin=admin if known or admin else None, admin_via=via, policies=policies, groups=gnames, group_policies=gpols,
                              mfa_devices=len(mfa) if mfa is not None else None, keys=krec))
        if unknown:
            self.limited["iam_users_detail"] = f"{unknown} user(s) with policies or MFA that could not be read (recorded as unknown)."
        self.write("iam_users.json", dict(listed=True, items=items), "IAM users, admin rights, MFA, access keys")

    def roles(self):
        roles, code = self.pages(self.client("iam"), "list_roles", "Roles")
        if roles is None:
            self.limited["iam_roles"] = f"IAM roles could not be listed ({code})."
            self.write("iam_roles.json", dict(listed=False, items=[]), "IAM roles (NOT readable)")
            return
        items = [dict(role=r["RoleName"], path=r.get("Path"), created=_iso(r.get("CreateDate")), trust=trust_entries(r.get("AssumeRolePolicyDocument")))
                 for r in roles]
        self.write("iam_roles.json", dict(listed=True, items=items), "IAM roles and their trust policies")

    def buckets(self):
        s3 = self.client("s3")
        r, code = self.call(s3, "list_buckets")
        if r is None:
            self.limited["s3"] = f"S3 buckets could not be listed ({code})."
            self.write("s3_buckets.json", dict(listed=False, items=[]), "S3 buckets (NOT readable)")
            return
        items = []
        for b in r.get("Buckets", []):
            name = b["Name"]
            pab, c1 = self.call(s3, "get_public_access_block", Bucket=name)
            cfg = (pab or {}).get("PublicAccessBlockConfiguration")
            block_all = bool(cfg) and all(cfg.get(k) for k in ("BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets"))
            st, c2 = self.call(s3, "get_bucket_policy_status", Bucket=name, quiet=("NotImplemented", "XNotImplemented"))
            public, how = None, None
            if st is not None and "IsPublic" in (st.get("PolicyStatus") or {}):
                public, how = bool(st["PolicyStatus"]["IsPublic"]), "GetBucketPolicyStatus"
            elif c2 in ("NoSuchBucketPolicy",):
                public, how = False, "no bucket policy"
            else:                                   # status not available: evaluate the policy document ourselves
                pol, c3 = self.call(s3, "get_bucket_policy", Bucket=name)
                if pol is not None:
                    public, how = doc_is_public(pol.get("Policy")), "policy evaluated by the collector"
                elif c3 == "NoSuchBucketPolicy":
                    public, how = False, "no bucket policy"
            checked = (c1 is None or c1 in NORMAL_MISSING) and public is not None
            items.append(dict(bucket=name, created=_iso(b.get("CreationDate")), block_config=cfg, block_all=block_all,
                              policy_public=public, public_how=how, checked=checked))
        self.write("s3_buckets.json", dict(listed=True, items=items), "S3 public access block and bucket policy status")

    def security_groups(self, all_regions):
        regions = [self.region]
        if all_regions:
            r, code = self.call(self.client("ec2"), "describe_regions")
            if r is not None:
                regions = sorted(x["RegionName"] for x in r.get("Regions", []))
            else:
                self.limited["regions"] = f"Region list could not be read ({code}); only {self.region} was checked."
        else:
            self.limited["security_groups"] = f"Security groups were read in {self.region} only (use --all-regions for every region)."
        items = []
        for reg in regions:
            groups, code = self.pages(self.client("ec2", reg), "describe_security_groups", "SecurityGroups")
            for g in groups or []:
                rules = []
                for p in g.get("IpPermissions", []):
                    cidrs = [x.get("CidrIp") for x in p.get("IpRanges", [])] + [x.get("CidrIpv6") for x in p.get("Ipv6Ranges", [])]
                    rules.append(dict(protocol=p.get("IpProtocol"), from_port=p.get("FromPort"), to_port=p.get("ToPort"), cidrs=[c for c in cidrs if c],
                                      groups=[x.get("GroupId") for x in p.get("UserIdGroupPairs", [])]))
                items.append(dict(group_id=g.get("GroupId"), name=g.get("GroupName"), vpc=g.get("VpcId"), region=reg, rules=rules))
        self.write("security_groups.json", dict(regions=regions, items=items), "security group inbound rules")


def collect_cloud_state(out_dir, region=None, profile=None, now=None, log=print, all_regions=False, session=None):
    """Collect the AWS account state into out_dir/cloud/. Returns the manifest (also written as manifest.json)."""
    if session is None:
        try:
            import boto3
        except ImportError:
            raise RuntimeError("AWS account-state collection needs boto3:  pip install boto3")
        session = boto3.Session(profile_name=profile, region_name=region) if profile else boto3.Session(region_name=region)
    region = region or session.region_name or "us-east-1"
    now = now or datetime.now(timezone.utc)
    c = _Collector(out_dir, session, region, now, log)
    started = datetime.now(timezone.utc)
    log("Collecting AWS account state (read-only) ...")
    c.identity()
    for step in (c.trails, c.account_summary, c.users, c.roles, c.buckets):
        log(f"  {step.__name__.replace('_', ' ')}")
        step()
    log("  security groups")
    c.security_groups(all_regions)
    man = dict(collector="cloudstate", account=getattr(c, "account", None), region=region, all_regions=all_regions,
               started_utc=_iso(started), finished_utc=_iso(datetime.now(timezone.utc)), reference_time=_iso(now),
               artifacts=c.artifacts, api_operations=c.ops, errors=c.errors, limited=c.limited)
    with open(os.path.join(c.dir, "manifest.json"), "w", encoding="utf-8") as f:
        json.dump(man, f, indent=1)
    return man
