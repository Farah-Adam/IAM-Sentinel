# IAM Sentinel Audit Report — account `182102543085`

*Source:* `iam-small.json` · *Analyzed:* 2026-11-18T10:10:12.299048+00:00 · *Tool:* IAM Sentinel 1.0.0

## Executive summary

| Security grade | Score | Identities | Findings | Critical attack paths | Excess permission ratio |
|---|---|---|---|---|---|
| **F** | 39/100 | 5 (3 users, 0 groups, 2 roles) | 14 | 1 | 50% (5 of 10 attached Allow statements are wildcard/over-broad) |

**Findings by severity:** CRITICAL: 1, HIGH: 4, MEDIUM: 5, LOW: 3, INFO: 1

**Administrator-equivalent identities:** test-admin

> ⚠️ User activity telemetry (credential report / PasswordLastUsed) is absent — dormant-user checks were limited.

## Identity blast radius

| Identity | Type | Blast radius | Level | Top factors |
|---|---|---|---|---|
| test-admin | user | 100 | CRITICAL | Administrator privileges (+80); Long-lived user credentials (+5); Wildcard resource scope (+10) |
| test-s3-all | user | 59 | HIGH | Sensitive capabilities (+37); Sensitive service breadth (+2); Long-lived user credentials (+5) |
| test-passrole | user | 57 | HIGH | Sensitive capabilities (+25); Sensitive service breadth (+4); Privilege escalation primitive (+8) |
| ec2-console-devops-agent-us-east-1 | role | 34 | MEDIUM | Sensitive capabilities (+18); Sensitive service breadth (+6); Wildcard resource scope (+10) |
| connct-with-ssm | role | 24 | LOW | Sensitive capabilities (+12); Sensitive service breadth (+2); Wildcard resource scope (+10) |

## Attack paths

- **PATH-001 [CRITICAL]** test-admin → [attached] AdministratorAccess → [Statement[0]: Action * / Resource *] FULL ACCOUNT CONTROL
- **PATH-002 [HIGH]** test-passrole → [inline] ci-deploy → [Statement[0]: lambda:CreateFunction] lambda · *
- **PATH-003 [HIGH]** test-s3-all → [inline] s3-all → [Statement[0]: s3:*] s3 · *
- **PATH-004 [HIGH · latent]** test-passrole → [PRIV-015] PassRole to new Lambda function
- **PATH-005 [MEDIUM]** ec2.amazonaws.com → [can assume (trust)] connct-with-ssm → [attached] AmazonSSMManagedInstanceCore → [Statement[0]: ssm:GetParameter, ssm:GetParameters, ssm:DescribeAssociation…] ssm · *
- **PATH-006 [MEDIUM]** aidevops.amazonaws.com → [can assume (trust)] ec2-console-devops-agent-us-east-1 → [attached] AIDevOpsAgentAccessPolicy → [AIOPSServiceAccess: cloudformation:GetTemplate, eks:AccessKubernetesApi, logs:FilterLogEvents…] 190 services (989 actions) · *

## Findings

| ID | Severity | Rule | Title | Identity | Policy / Sid |
|---|---|---|---|---|---|
| F-001 | CRITICAL | ADMIN-001 | Full administrator access (Action "*" on Resource "*") via AWS managed policy AdministratorAccess | test-admin | AdministratorAccess / Statement[0] |
| F-002 | HIGH | HYG-003 | Administrator is a long-lived IAM user | test-admin | - / - |
| F-003 | HIGH | PRIV-015 | Privilege escalation: PassRole to new Lambda function | test-passrole | ci-deploy / Statement[0] |
| F-004 | HIGH | RES-001 | Sensitive action(s) allowed on Resource "*" (Compute / code execution, Privilege escalation primitive) | test-passrole | ci-deploy / Statement[0] |
| F-005 | HIGH | WILD-002 | Service-wide wildcard s3:* on all resources | test-s3-all | s3-all / Statement[0] |
| F-006 | MEDIUM | HYG-002 | Recently created privileged user (created < 24 hours ago) | test-admin | - / - |
| F-007 | MEDIUM | HYG-002 | Recently created privileged user (created < 24 hours ago) | test-passrole | - / - |
| F-008 | MEDIUM | HYG-002 | Recently created privileged user (created < 24 hours ago) | test-s3-all | - / - |
| F-009 | MEDIUM | RES-001 | Sensitive action(s) allowed on Resource "*" (Credential / secret access) | connct-with-ssm | AmazonSSMManagedInstanceCore / Statement[0] |
| F-010 | MEDIUM | RES-001 | Sensitive action(s) allowed on Resource "*" (Credential / secret access, Sensitive data read) | ec2-console-devops-agent-us-east-1 | AIDevOpsAgentAccessPolicy / AIOPSServiceAccess |
| F-011 | LOW | HYG-001 | Permissions granted through inline user policy | test-passrole | ci-deploy / - |
| F-012 | LOW | HYG-001 | Permissions granted through inline user policy | test-s3-all | s3-all / - |
| F-013 | LOW | READ-001 | Very broad permission surface: 989 actions across 190 services on "*" | ec2-console-devops-agent-us-east-1 | AIDevOpsAgentAccessPolicy / AIOPSServiceAccess |
| F-014 | INFO | TELEM-001 | Usage telemetry absent - dormancy cannot be assessed for some identities | test-admin, test-passrole, test-s3-all | - / - |

## Finding details

### F-001 · CRITICAL · Full administrator access (Action "*" on Resource "*") via AWS managed policy AdministratorAccess

- **Rule:** `ADMIN-001` (Excessive Privilege) · **Exploitability:** confirmed · **MITRE ATT&CK:** T1078.004, T1098, T1562.008
- **Identities:** test-admin
- **Policy:** AdministratorAccess (aws-managed) arn:aws:iam::aws:policy/AdministratorAccess · **Sid:** (none) · **Effect:** Allow
- **Offending actions:** `*`
- **Resource:** `*`
- **Risk:** The statement grants every action on every resource in the account. Holders can create users and keys, rewrite any policy, read all data, disable CloudTrail/GuardDuty and delete resources.
- **Attack path:** Credential theft of this identity = full account takeover. An attacker typically creates a backdoor user or access key (persistence), disables logging (defense evasion) and exfiltrates S3/RDS/Secrets data.
- **Fix:** Remove standing admin. Use role-based, MFA-gated, time-bound elevation (IAM Identity Center permission set or an assumable break-glass role) and protect security tooling with explicit Deny.
- **Remediation:** REM-001

### F-002 · HIGH · Administrator is a long-lived IAM user

- **Rule:** `HYG-003` (Hygiene) · **Exploitability:** confirmed · **MITRE ATT&CK:** T1078.004
- **Identities:** test-admin
- **Risk:** test-admin is an IAM user with full administrator rights. IAM users carry long-lived credentials (password / access keys).
- **Attack path:** Leaked access keys of an admin IAM user never expire; MFA cannot be enforced on API keys without explicit conditions.
- **Fix:** Use IAM Identity Center or an assumable admin role with MFA and short sessions; remove the user's direct admin policy.

### F-003 · HIGH · Privilege escalation: PassRole to new Lambda function

- **Rule:** `PRIV-015` (Privilege Escalation) · **Exploitability:** latent · **MITRE ATT&CK:** T1648, T1098
- **Identities:** test-passrole
- **Policy:** ci-deploy (inline)  · **Sid:** (none) · **Effect:** Allow
- **Offending actions:** `iam:PassRole, lambda:CreateFunction, (missing) lambda:InvokeFunction`
- **Resource:** `*`
- **Risk:** Can create a Lambda function that executes attacker code with any passable execution role. Required permissions present: iam:PassRole, lambda:CreateFunction.
- **Attack path:** 1) test-passrole calls lambda:CreateFunction with --role pointing at a privileged role/policy (allowed by iam:PassRole on that ARN). 2) The function code reads AWS_ACCESS_KEY_ID/SECRET/SESSION_TOKEN from its environment or calls IAM directly. 3) Once invoked, the attacker operates with the execution role's privileges.
- **Fix:** Scope iam:PassRole to the exact execution role ARN(s) and add Condition StringEquals iam:PassedToService = lambda.amazonaws.com; scope the compute action to a function/instance naming prefix.
- *Note:* No role in this export currently trusts lambda.amazonaws.com; PassRole on "*" means the escalation becomes immediate the moment any privileged role trusting lambda.amazonaws.com exists (common for Lambda/EC2 execution roles).
- *Note:* No trigger permission (lambda:InvokeFunction / lambda:CreateEventSourceMapping / lambda:CreateFunctionUrlConfig / lambda:AddPermission) found - the chain is one permission away from executable, or relies on an existing event source / another principal to invoke it.
- **Remediation:** REM-002

### F-004 · HIGH · Sensitive action(s) allowed on Resource "*" (Compute / code execution, Privilege escalation primitive)

- **Rule:** `RES-001` (Unscoped Resource) · **Exploitability:** confirmed · **MITRE ATT&CK:** T1098, T1648
- **Identities:** test-passrole
- **Policy:** ci-deploy (inline)  · **Sid:** (none) · **Effect:** Allow
- **Offending actions:** `iam:PassRole, lambda:CreateFunction`
- **Resource:** `*`
- **Risk:** 2 sensitive action(s) apply to every resource: iam:PassRole, lambda:CreateFunction.
- **Attack path:** iam:PassRole on "*" lets the holder hand ANY role (including admin roles) to an AWS service it controls. Code-execution APIs on "*" allow running attacker-controlled code inside the account.
- **Fix:** Scope Resource to the specific ARNs (bucket, function, parameter path, role) and add guardrail conditions (aws:ResourceAccount, iam:PassedToService, aws:MultiFactorAuthPresent).
- **Remediation:** REM-002

### F-005 · HIGH · Service-wide wildcard s3:* on all resources

- **Rule:** `WILD-002` (Wildcard Permission) · **Exploitability:** confirmed · **MITRE ATT&CK:** T1530, T1485
- **Identities:** test-s3-all
- **Policy:** s3-all (inline)  · **Sid:** (none) · **Effect:** Allow
- **Offending actions:** `s3:*`
- **Resource:** `*`
- **Risk:** s3:* grants every current and future API of the service, including 12 known-sensitive action(s) such as s3:DeleteBucket, s3:DeleteBucketPolicy, s3:DeleteObject, s3:DeleteObjectVersion, s3:GetObject, s3:GetObjectVersion.
- **Attack path:** The holder can read and download every object in every bucket (data exfiltration), make buckets public via s3:PutBucketPolicy / PutBucketAcl, and destroy data with s3:DeleteBucket / DeleteObject (ransomware pattern).
- **Fix:** Replace the service wildcard with the specific read/write actions the workload needs and scope Resource to named ARNs.
- **Remediation:** REM-003

### F-006 · MEDIUM · Recently created privileged user (created < 24 hours ago)

- **Rule:** `HYG-002` (Hygiene) · **Exploitability:** informational · **MITRE ATT&CK:** T1136.003
- **Identities:** test-admin
- **Risk:** test-admin was created 2026-11-17 13:12 UTC and already holds high-risk permissions.
- **Attack path:** Creating a new privileged IAM user/role is a classic persistence technique after initial compromise (T1136.003). Confirm it maps to an approved change ticket.
- **Fix:** Verify the creator in CloudTrail (CreateUser/CreateRole events) and the business justification.

### F-007 · MEDIUM · Recently created privileged user (created < 24 hours ago)

- **Rule:** `HYG-002` (Hygiene) · **Exploitability:** informational · **MITRE ATT&CK:** T1136.003
- **Identities:** test-passrole
- **Risk:** test-passrole was created 2026-11-17 13:12 UTC and already holds high-risk permissions.
- **Attack path:** Creating a new privileged IAM user/role is a classic persistence technique after initial compromise (T1136.003). Confirm it maps to an approved change ticket.
- **Fix:** Verify the creator in CloudTrail (CreateUser/CreateRole events) and the business justification.

### F-008 · MEDIUM · Recently created privileged user (created < 24 hours ago)

- **Rule:** `HYG-002` (Hygiene) · **Exploitability:** informational · **MITRE ATT&CK:** T1136.003
- **Identities:** test-s3-all
- **Risk:** test-s3-all was created 2026-11-17 13:12 UTC and already holds high-risk permissions.
- **Attack path:** Creating a new privileged IAM user/role is a classic persistence technique after initial compromise (T1136.003). Confirm it maps to an approved change ticket.
- **Fix:** Verify the creator in CloudTrail (CreateUser/CreateRole events) and the business justification.

### F-009 · MEDIUM · Sensitive action(s) allowed on Resource "*" (Credential / secret access)

- **Rule:** `RES-001` (Unscoped Resource) · **Exploitability:** confirmed · **MITRE ATT&CK:** T1555.006
- **Identities:** connct-with-ssm
- **Policy:** AmazonSSMManagedInstanceCore (aws-managed) arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore · **Sid:** (none) · **Effect:** Allow
- **Offending actions:** `ssm:GetParameter, ssm:GetParameters`
- **Resource:** `*`
- **Risk:** 2 sensitive action(s) apply to every resource: ssm:GetParameter, ssm:GetParameters.
- **Attack path:** Every parameter/secret in the account is readable - including database passwords and API tokens of other apps.
- **Fix:** Scope Resource to the specific ARNs (bucket, function, parameter path, role) and add guardrail conditions (aws:ResourceAccount, iam:PassedToService, aws:MultiFactorAuthPresent).
- *Note:* AWS-managed policy: you cannot edit it - replace it with a scoped customer-managed copy (generated below).
- **Remediation:** REM-004

### F-010 · MEDIUM · Sensitive action(s) allowed on Resource "*" (Credential / secret access, Sensitive data read)

- **Rule:** `RES-001` (Unscoped Resource) · **Exploitability:** confirmed · **MITRE ATT&CK:** T1530, T1555.006
- **Identities:** ec2-console-devops-agent-us-east-1
- **Policy:** AIDevOpsAgentAccessPolicy (aws-managed) arn:aws:iam::aws:policy/AIDevOpsAgentAccessPolicy · **Sid:** AIOPSServiceAccess · **Effect:** Allow
- **Offending actions:** `cloudformation:GetTemplate, eks:AccessKubernetesApi, logs:FilterLogEvents, logs:GetLogEvents, logs:StartQuery`
- **Resource:** `*`
- **Risk:** 5 sensitive action(s) apply to every resource: cloudformation:GetTemplate, eks:AccessKubernetesApi, logs:FilterLogEvents, logs:GetLogEvents, logs:StartQuery.
- **Attack path:** All CloudWatch log data is readable (logs often contain tokens, PII and request payloads). Kubernetes API access on every EKS cluster (subject to cluster access entries).
- **Fix:** Scope Resource to the specific ARNs (bucket, function, parameter path, role) and add guardrail conditions (aws:ResourceAccount, iam:PassedToService, aws:MultiFactorAuthPresent).
- *Note:* AWS-managed policy: you cannot edit it - replace it with a scoped customer-managed copy (generated below).
- **Remediation:** REM-005

### F-011 · LOW · Permissions granted through inline user policy

- **Rule:** `HYG-001` (Hygiene) · **Exploitability:** informational · **MITRE ATT&CK:** T1098
- **Identities:** test-passrole
- **Policy:** ci-deploy (inline)  · **Sid:** (none) · **Effect:** None
- **Risk:** test-passrole has inline policies: ci-deploy. Inline user policies are invisible in policy inventories, cannot be reused or versioned, and bypass group-based access reviews.
- **Attack path:** Attackers favour inline policies for persistence because they are easy to overlook.
- **Fix:** Move permissions to a versioned customer-managed policy attached to a group or role.

### F-012 · LOW · Permissions granted through inline user policy

- **Rule:** `HYG-001` (Hygiene) · **Exploitability:** informational · **MITRE ATT&CK:** T1098
- **Identities:** test-s3-all
- **Policy:** s3-all (inline)  · **Sid:** (none) · **Effect:** None
- **Risk:** test-s3-all has inline policies: s3-all. Inline user policies are invisible in policy inventories, cannot be reused or versioned, and bypass group-based access reviews.
- **Attack path:** Attackers favour inline policies for persistence because they are easy to overlook.
- **Fix:** Move permissions to a versioned customer-managed policy attached to a group or role.

### F-013 · LOW · Very broad permission surface: 989 actions across 190 services on "*"

- **Rule:** `READ-001` (Excessive Privilege) · **Exploitability:** confirmed · **MITRE ATT&CK:** T1580
- **Identities:** ec2-console-devops-agent-us-east-1
- **Policy:** AIDevOpsAgentAccessPolicy (aws-managed) arn:aws:iam::aws:policy/AIDevOpsAgentAccessPolicy · **Sid:** AIOPSServiceAccess · **Effect:** Allow
- **Resource:** `*`
- **Risk:** A single statement grants 989 actions across 190 services on all resources (mostly read/list).
- **Attack path:** Broad read access enables full reconnaissance of the account (T1580) and reading of operational data such as logs and templates.
- **Fix:** Confirm the identity really needs account-wide visibility; otherwise restrict to the services in use.
- *Note:* AWS-managed policy: you cannot edit it - replace it with a scoped customer-managed copy (generated below).
- **Remediation:** REM-005

### F-014 · INFO · Usage telemetry absent - dormancy cannot be assessed for some identities

- **Rule:** `TELEM-001` (Stale / Unused Identity) · **Exploitability:** informational
- **Identities:** test-admin, test-passrole, test-s3-all
- **Risk:** The export has no PasswordLastUsed / credential report data for 3 user(s): test-admin, test-passrole, test-s3-all. get-account-authorization-details does not include user login or access-key activity.
- **Attack path:** Unused credentials cannot be distinguished from active ones without telemetry.
- **Fix:** Run `python cli.py collect` (adds the IAM credential report) or merge `aws iam get-credential-report` output into the export under the key "CredentialReport".

## Least-privilege remediations

### REM-001 · AdministratorAccess (aws-managed) → applies to test-admin

Residual risk after fix: **CRITICAL → HIGH**

- AWS-managed policies cannot be edited: this is a customer-managed replacement for AdministratorAccess.
- Admin access now requires an MFA-authenticated session younger than 1 hour (blocks leaked access keys).
- Explicit Deny protects CloudTrail, GuardDuty, Config, Security Hub and Access Analyzer from tampering.
- Preferred end-state: delete standing admin; grant an assumable break-glass role / IAM Identity Center permission set.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AdminOnlyWithRecentMFA",
      "Effect": "Allow",
      "Action": "*",
      "Resource": "*",
      "Condition": {
        "Bool": {
          "aws:MultiFactorAuthPresent": "true"
        },
        "NumericLessThan": {
          "aws:MultiFactorAuthAge": "3600"
        }
      }
    },
    {
      "Sid": "ProtectSecurityTooling",
      "Effect": "Deny",
      "Action": [
        "cloudtrail:StopLogging",
        "cloudtrail:DeleteTrail",
        "cloudtrail:UpdateTrail",
        "guardduty:DeleteDetector",
        "guardduty:UpdateDetector",
        "config:StopConfigurationRecorder",
        "config:DeleteConfigurationRecorder",
        "organizations:LeaveOrganization",
        "iam:DeleteAccountPasswordPolicy",
        "iam:DeactivateMFADevice",
        "access-analyzer:DeleteAnalyzer",
        "securityhub:DisableSecurityHub"
      ],
      "Resource": "*"
    },
    {
      "Sid": "DenyPrivilegedIdentityCreation",
      "Effect": "Deny",
      "Action": [
        "iam:CreateUser",
        "iam:CreateAccessKey",
        "iam:CreateLoginProfile"
      ],
      "Resource": "*",
      "Condition": {
        "BoolIfExists": {
          "aws:MultiFactorAuthPresent": "false"
        }
      }
    }
  ]
}
```

```diff
--- original.json
+++ least-privilege.json
@@ -3,7 +3,50 @@
   "Statement": [
     {
+      "Sid": "AdminOnlyWithRecentMFA",
       "Effect": "Allow",
       "Action": "*",
+      "Resource": "*",
+      "Condition": {
+        "Bool": {
+          "aws:MultiFactorAuthPresent": "true"
+        },
+        "NumericLessThan": {
+          "aws:MultiFactorAuthAge": "3600"
+        }
+      }
+    },
+    {
+      "Sid": "ProtectSecurityTooling",
+      "Effect": "Deny",
+      "Action": [
+        "cloudtrail:StopLogging",
+        "cloudtrail:DeleteTrail",
+        "cloudtrail:UpdateTrail",
+        "guardduty:DeleteDetector",
+        "guardduty:UpdateDetector",
+        "config:StopConfigurationRecorder",
+        "config:DeleteConfigurationRecorder",
+        "organizations:LeaveOrganization",
+        "iam:DeleteAccountPasswordPolicy",
+        "iam:DeactivateMFADevice",
+        "access-analyzer:DeleteAnalyzer",
+        "securityhub:DisableSecurityHub"
+      ],
       "Resource": "*"
+    },
+    {
+      "Sid": "DenyPrivilegedIdentityCreation",
+      "Effect": "Deny",
+      "Action": [
+        "iam:CreateUser",
+        "iam:CreateAccessKey",
+        "iam:CreateLoginProfile"
+      ],
+      "Resource": "*",
+      "Condition": {
+        "BoolIfExists": {
+          "aws:MultiFactorAuthPresent": "false"
+        }
+      }
     }
   ]
```

Apply:

```bash
aws accessanalyzer validate-policy --policy-type IDENTITY_POLICY --policy-document file://remediation/AdministratorAccess-least-privilege.json
aws iam create-policy --policy-name AdministratorAccess-LeastPrivilege --policy-document file://remediation/AdministratorAccess-least-privilege.json
aws iam attach-user-policy --user-name test-admin --policy-arn arn:aws:iam::182102543085:policy/AdministratorAccess-LeastPrivilege
aws iam detach-user-policy --user-name test-admin --policy-arn arn:aws:iam::aws:policy/AdministratorAccess
```

### REM-002 · ci-deploy (inline) → applies to test-passrole

Residual risk after fix: **HIGH → NONE**

- iam:PassRole scoped to one execution role and limited to iam:PassedToService = lambda.amazonaws.com.
- lambda:CreateFunction moved from Resource "*" to arn:aws:lambda:<REGION>:182102543085:function:ci-deploy-* with aws:ResourceAccount guardrail.

Fill in placeholders before applying: `<APPROVED_EXECUTION_ROLE>`, `<REGION>`

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "PassOnlyApprovedRole",
      "Effect": "Allow",
      "Action": "iam:PassRole",
      "Resource": [
        "arn:aws:iam::182102543085:role/<APPROVED_EXECUTION_ROLE>"
      ],
      "Condition": {
        "StringEquals": {
          "iam:PassedToService": "lambda.amazonaws.com"
        }
      }
    },
    {
      "Sid": "ScopedLambda",
      "Effect": "Allow",
      "Action": [
        "lambda:CreateFunction"
      ],
      "Resource": [
        "arn:aws:lambda:<REGION>:182102543085:function:ci-deploy-*"
      ],
      "Condition": {
        "StringEquals": {
          "aws:ResourceAccount": "182102543085"
        }
      }
    }
  ]
}
```

```diff
--- original.json
+++ least-privilege.json
@@ -3,10 +3,30 @@
   "Statement": [
     {
+      "Sid": "PassOnlyApprovedRole",
+      "Effect": "Allow",
+      "Action": "iam:PassRole",
+      "Resource": [
+        "arn:aws:iam::182102543085:role/<APPROVED_EXECUTION_ROLE>"
+      ],
+      "Condition": {
+        "StringEquals": {
+          "iam:PassedToService": "lambda.amazonaws.com"
+        }
+      }
+    },
+    {
+      "Sid": "ScopedLambda",
       "Effect": "Allow",
       "Action": [
-        "iam:PassRole",
         "lambda:CreateFunction"
       ],
-      "Resource": "*"
+      "Resource": [
+        "arn:aws:lambda:<REGION>:182102543085:function:ci-deploy-*"
+      ],
+      "Condition": {
+        "StringEquals": {
+          "aws:ResourceAccount": "182102543085"
+        }
+      }
     }
   ]
```

Apply:

```bash
aws accessanalyzer validate-policy --policy-type IDENTITY_POLICY --policy-document file://remediation/ci-deploy-least-privilege.json
aws iam put-user-policy --user-name test-passrole --policy-name ci-deploy --policy-document file://remediation/ci-deploy-least-privilege.json
```

### REM-003 · s3-all (inline) → applies to test-s3-all

Residual risk after fix: **HIGH → NONE**

- s3:* replaced by 5 day-to-day s3 actions; admin/destructive APIs (policy, ACL, delete, encryption config) removed.
- s3:ListBucket, s3:GetObject, s3:PutObject moved from Resource "*" to arn:aws:s3:::<BUCKET_NAME>, arn:aws:s3:::<BUCKET_NAME>/* with aws:ResourceAccount guardrail.

Fill in placeholders before applying: `<BUCKET_NAME>`

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "s3:ListAllMyBuckets",
        "s3:GetBucketLocation"
      ],
      "Resource": "*"
    },
    {
      "Sid": "ScopedS3",
      "Effect": "Allow",
      "Action": [
        "s3:ListBucket",
        "s3:GetObject",
        "s3:PutObject"
      ],
      "Resource": [
        "arn:aws:s3:::<BUCKET_NAME>",
        "arn:aws:s3:::<BUCKET_NAME>/*"
      ],
      "Condition": {
        "StringEquals": {
          "aws:ResourceAccount": "182102543085"
        }
      }
    }
  ]
}
```

```diff
--- original.json
+++ least-privilege.json
@@ -4,6 +4,27 @@
     {
       "Effect": "Allow",
-      "Action": "s3:*",
+      "Action": [
+        "s3:ListAllMyBuckets",
+        "s3:GetBucketLocation"
+      ],
       "Resource": "*"
+    },
+    {
+      "Sid": "ScopedS3",
+      "Effect": "Allow",
+      "Action": [
+        "s3:ListBucket",
+        "s3:GetObject",
+        "s3:PutObject"
+      ],
+      "Resource": [
+        "arn:aws:s3:::<BUCKET_NAME>",
+        "arn:aws:s3:::<BUCKET_NAME>/*"
+      ],
+      "Condition": {
+        "StringEquals": {
+          "aws:ResourceAccount": "182102543085"
+        }
+      }
     }
   ]
```

Apply:

```bash
aws accessanalyzer validate-policy --policy-type IDENTITY_POLICY --policy-document file://remediation/s3-all-least-privilege.json
aws iam put-user-policy --user-name test-s3-all --policy-name s3-all --policy-document file://remediation/s3-all-least-privilege.json
```

### REM-004 · AmazonSSMManagedInstanceCore (aws-managed) → applies to connct-with-ssm

Residual risk after fix: **MEDIUM → NONE**

- AWS-managed policies cannot be edited: this is a customer-managed replacement for AmazonSSMManagedInstanceCore.
- ssm:GetParameter, ssm:GetParameters moved from Resource "*" to arn:aws:ssm:<REGION>:182102543085:parameter/<APP_PREFIX>/* with aws:ResourceAccount guardrail.

Fill in placeholders before applying: `<APP_PREFIX>`, `<REGION>`

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "ssm:DescribeAssociation",
        "ssm:GetDeployablePatchSnapshotForInstance",
        "ssm:GetDocument",
        "ssm:DescribeDocument",
        "ssm:GetManifest",
        "ssm:ListAssociations",
        "ssm:ListInstanceAssociations",
        "ssm:PutInventory",
        "ssm:PutComplianceItems",
        "ssm:PutConfigurePackageResult",
        "ssm:UpdateAssociationStatus",
        "ssm:UpdateInstanceAssociationStatus",
        "ssm:UpdateInstanceInformation"
      ],
      "Resource": "*"
    },
    {
      "Sid": "ScopedSsm",
      "Effect": "Allow",
      "Action": [
        "ssm:GetParameter",
        "ssm:GetParameters"
      ],
      "Resource": [
        "arn:aws:ssm:<REGION>:182102543085:parameter/<APP_PREFIX>/*"
      ],
      "Condition": {
        "StringEquals": {
          "aws:ResourceAccount": "182102543085"
        }
      }
    },
    {
      "Effect": "Allow",
      "Action": [
        "ssmmessages:CreateControlChannel",
        "ssmmessages:CreateDataChannel",
        "ssmmessages:OpenControlChannel",
        "ssmmessages:OpenDataChannel"
      ],
      "Resource": "*"
    },
    {
      "Effect": "Allow",
      "Action": [
        "ec2messages:AcknowledgeMessage",
        "ec2messages:DeleteMessage",
        "ec2messages:FailMessage",
        "ec2messages:GetEndpoint",
        "ec2messages:GetMessages",
        "ec2messages:SendReply"
      ],
      "Resource": "*"
    }
  ]
}
```

```diff
--- original.json
+++ least-privilege.json
@@ -10,6 +10,4 @@
         "ssm:DescribeDocument",
         "ssm:GetManifest",
-        "ssm:GetParameter",
-        "ssm:GetParameters",
         "ssm:ListAssociations",
         "ssm:ListInstanceAssociations",
@@ -22,4 +20,20 @@
       ],
       "Resource": "*"
+    },
+    {
+      "Sid": "ScopedSsm",
+      "Effect": "Allow",
+      "Action": [
+        "ssm:GetParameter",
+        "ssm:GetParameters"
+      ],
+      "Resource": [
+        "arn:aws:ssm:<REGION>:182102543085:parameter/<APP_PREFIX>/*"
+      ],
+      "Condition": {
+        "StringEquals": {
+          "aws:ResourceAccount": "182102543085"
+        }
+      }
     },
     {
```

Apply:

```bash
aws accessanalyzer validate-policy --policy-type IDENTITY_POLICY --policy-document file://remediation/AmazonSSMManagedInstanceCore-least-privilege.json
aws iam create-policy --policy-name AmazonSSMManagedInstanceCore-LeastPrivilege --policy-document file://remediation/AmazonSSMManagedInstanceCore-least-privilege.json
aws iam attach-role-policy --role-name connct-with-ssm --policy-arn arn:aws:iam::182102543085:policy/AmazonSSMManagedInstanceCore-LeastPrivilege
aws iam detach-role-policy --role-name connct-with-ssm --policy-arn arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore
```

### REM-005 · AIDevOpsAgentAccessPolicy (aws-managed) → applies to ec2-console-devops-agent-us-east-1

Residual risk after fix: **MEDIUM → LOW**

- AWS-managed policies cannot be edited: this is a customer-managed replacement for AIDevOpsAgentAccessPolicy.
- cloudformation:GetTemplate moved from Resource "*" to arn:aws:cloudformation:<REGION>:182102543085:stack/<STACK_PREFIX>-*/* with aws:ResourceAccount guardrail.
- eks:AccessKubernetesApi moved from Resource "*" to arn:aws:eks:<REGION>:182102543085:<EKS_RESOURCE> with aws:ResourceAccount guardrail.
- logs:FilterLogEvents, logs:GetLogEvents, logs:StartQuery moved from Resource "*" to arn:aws:logs:<REGION>:182102543085:log-group:<LOG_GROUP>:* with aws:ResourceAccount guardrail.

Fill in placeholders before applying: `<EKS_RESOURCE>`, `<LOG_GROUP>`, `<REGION>`, `<STACK_PREFIX>`

```json
{"Version": "2012-10-17", "Statement": [{"Sid": "AIOPSServiceWriteAccess", "Effect": "Allow", "Action": ["cloudtrail:StartQuery", "support:CreateCase"], "Resource": "*"}, {"Sid": "AIOPSServiceAccess", "Effect": "Allow", "Action": ["access-analyzer:GetAnalyzer", "access-analyzer:List*", "acm-pca:Describe*", "acm-pca:GetCertificate", "acm-pca:GetCertificateAuthorityCertificate", "acm-pca:GetCertificateAuthorityCsr", "acm-pca:List*", "acm:DescribeCertificate", "acm:GetAccountConfiguration", "acm:GetCertificate", "acm:ListCertificates", "aidevops:GetAsset", "aidevops:GetAssetContent", "aidevops:GetAssetFile", "aidevops:GetKnowledgeItem", "aidevops:ListAssetFiles", "aidevops:ListAssets", "aidevops:ListAssetTypes", "aidevops:ListAssetVersions", "aidevops:ListKnowledgeItems", "airflow:GetEnvironment", "airflow:List*", "amplify:GetApp", "amplify:GetBranch", "amplify:GetDomainAssociation", "amplify:List*", "aoss:BatchGetCollection", "aoss:BatchGetLifecyclePolicy", "aoss:BatchGetVpcEndpoint", "aoss:GetAccessPolicy", "aoss:GetSecurityConfig", "aoss:GetSecurityPolicy", "aoss:List*", "appconfig:GetApplication", "appconfig:GetConfigurationProfile", "appconfig:GetEnvironment", "appconfig:GetHostedConfigurationVersion", "appconfig:List*", "appflow:Describe*", "appflow:List*", "application-autoscaling:Describe*", "application-signals:BatchGetServiceLevelObjectiveBudgetReport", "application-signals:GetService", "application-signals:GetServiceLevelObjective", "application-signals:List*", "applicationinsights:Describe*", "applicationinsights:List*", "apprunner:Describe*", "apprunner:List*", "appstream:Describe*", "appstream:List*", "appsync:GetApiAssociation", "appsync:GetDataSource", "appsync:GetDomainName", "appsync:GetFunction", "appsync:GetGraphqlApi", "appsync:GetGraphqlApiEnvironmentVariables", "appsync:GetIntrospectionSchema", "appsync:GetResolver", "appsync:GetSourceApiAssociation", "appsync:List*", "aps:Describe*", "aps:List*", "arc-zonal-shift:GetManagedResource", "arc-zonal-shift:List*", "athena:GetCapacityAssignmentConfiguration", "athena:GetCapacityReservation", "athena:GetDataCatalog", "athena:GetNamedQuery", "athena:GetPreparedStatement", "athena:GetWorkGroup", "athena:List*", "auditmanager:GetAssessment", "auditmanager:List*", "autoscaling:Describe*", "backup-gateway:GetHypervisor", "backup-gateway:List*", "backup:Describe*", "backup:GetBackupPlan", "backup:GetBackupSelection", "backup:GetBackupVaultAccessPolicy", "backup:GetBackupVaultNotifications", "backup:GetRestoreTestingPlan", "backup:GetRestoreTestingSelection", "backup:List*", "batch:DescribeComputeEnvironments", "batch:DescribeJobQueues", "batch:DescribeSchedulingPolicies", "batch:List*", "bcm-data-exports:Get*", "bcm-data-exports:List*", "bedrock:GetAgent", "bedrock:GetAgentActionGroup", "bedrock:GetAgentAlias", "bedrock:GetAgentKnowledgeBase", "bedrock:GetCustomModel", "bedrock:GetDataSource", "bedrock:GetFoundationModel", "bedrock:GetGuardrail", "bedrock:GetInferenceProfile", "bedrock:GetKnowledgeBase", "bedrock:GetModelInvocationLoggingConfiguration", "bedrock:GetProvisionedModelThroughput", "bedrock:List*", "budgets:Describe*", "budgets:List*", "budgets:ViewBudget", "ce:Describe*", "ce:Get*", "ce:List*", "chatbot:Describe*", "chatbot:GetMicrosoftTeamsChannelConfiguration", "chatbot:List*", "cleanrooms-ml:GetTrainingDataset", "cleanrooms-ml:List*", "cleanrooms:GetAnalysisTemplate", "cleanrooms:GetCollaboration", "cleanrooms:GetConfiguredTable", "cleanrooms:GetConfiguredTableAnalysisRule", "cleanrooms:GetConfiguredTableAssociation", "cleanrooms:GetMembership", "cleanrooms:List*", "cloudformation:Describe*", "cloudformation:GetResource", "cloudformation:GetStackPolicy", "cloudformation:List*", "cloudfront:Describe*", "cloudfront:GetCachePolicy", "cloudfront:GetCloudFrontOriginAccessIdentity", "cloudfront:GetContinuousDeploymentPolicy", "cloudfront:GetDistribution", "cloudfront:GetDistributionConfig", "cloudfront:GetFunction", "cloudfront:GetKeyGroup", "cloudfront:GetMonitoringSubscription", "cloudfront:GetOriginAccessControl", "cloudfront:GetOriginRequestPolicy", "cloudfront:GetPublicKey", "cloudfront:GetRealtimeLogConfig", "cloudfront:GetResponseHeadersPolicy", "cloudfront:List*", "cloudtrail:Describe*", "cloudtrail:GetChannel", "cloudtrail:GetEventConfiguration", "cloudtrail:GetEventDataStore", "cloudtrail:GetEventSelectors", "cloudtrail:GetInsightSelectors", "cloudtrail:GetQueryResults", "cloudtrail:GetResourcePolicy", "cloudtrail:GetTrail", "cloudtrail:GetTrailStatus", "cloudtrail:List*", "cloudtrail:LookupEvents", "cloudwatch:Describe*", "cloudwatch:GenerateQuery", "cloudwatch:GetAlert", "cloudwatch:GetContextGraph", "cloudwatch:GetDashboard", "cloudwatch:GetInsightRuleReport", "cloudwatch:GetIntelligenceConfiguration", "cloudwatch:GetMetricData", "cloudwatch:GetMetricStatistics", "cloudwatch:GetMetricStream", "cloudwatch:GetOTelEnrichment", "cloudwatch:GetProfileRecords", "cloudwatch:GetRecords", "cloudwatch:GetService", "cloudwatch:GetServiceLevelObjective", "cloudwatch:GetSpace", "cloudwatch:GetTelemetryQueryResults", "cloudwatch:List*", "cloudwatch:StartTelemetryQuery", "cloudwatch:StartTelemetryQuerySession", "cloudwatch:StopTelemetryQuery", "cloudwatch:StopTelemetryQuerySession", "codeartifact:Describe*", "codeartifact:GetDomainPermissionsPolicy", "codeartifact:GetRepositoryPermissionsPolicy", "codeartifact:List*", "codebuild:BatchGetFleets", "codebuild:List*", "codecommit:BatchDescribe*", "codecommit:BatchGet*", "codecommit:Describe*", "codecommit:EvaluatePullRequestApprovalRules", "codecommit:GetApprovalRuleTemplate", "codecommit:GetBranch", "codecommit:GetComment", "codecommit:GetCommentReactions", "codecommit:GetCommentsForComparedCommit", "codecommit:GetCommentsForPullRequest", "codecommit:GetCommit", "codecommit:GetCommitHistory", "codecommit:GetCommitsFromMergeBase", "codecommit:GetDifferences", "codecommit:GetMergeCommit", "codecommit:GetMergeConflicts", "codecommit:GetMergeOptions", "codecommit:GetObjectIdentifier", "codecommit:GetPullRequest", "codecommit:GetPullRequestApprovalStates", "codecommit:GetPullRequestOverrideState", "codecommit:GetReferences", "codecommit:GetRepository", "codecommit:GetRepositoryTriggers", "codecommit:GetTree", "codecommit:GetUploadArchiveStatus", "codecommit:List*", "codedeploy:BatchGetDeployments", "codedeploy:BatchGetDeploymentTargets", "codedeploy:GetApplication", "codedeploy:GetDeploymentConfig", "codedeploy:GetDeploymentTarget", "codedeploy:List*", "codeguru-profiler:Describe*", "codeguru-profiler:GetNotificationConfiguration", "codeguru-profiler:GetPolicy", "codeguru-profiler:List*", "codeguru-reviewer:Describe*", "codeguru-reviewer:List*", "codepipeline:GetPipeline", "codepipeline:GetPipelineState", "codepipeline:List*", "codestar-connections:GetConnection", "codestar-connections:GetRepositoryLink", "codestar-connections:GetSyncConfiguration", "codestar-connections:List*", "codestar-notifications:Describe*", "codestar-notifications:List*", "cognito-identity:DescribeIdentityPool", "cognito-identity:GetIdentityPoolRoles", "cognito-identity:ListIdentityPools", "cognito-identity:ListTagsForResource", "cognito-idp:AdminListGroupsForUser", "cognito-idp:DescribeIdentityProvider", "cognito-idp:DescribeResourceServer", "cognito-idp:DescribeRiskConfiguration", "cognito-idp:DescribeUserImportJob", "cognito-idp:DescribeUserPool", "cognito-idp:DescribeUserPoolDomain", "cognito-idp:GetGroup", "cognito-idp:GetLogDeliveryConfiguration", "cognito-idp:GetUICustomization", "cognito-idp:GetUserPoolMfaConfig", "cognito-idp:GetWebACLForResource", "cognito-idp:ListGroups", "cognito-idp:ListIdentityProviders", "cognito-idp:ListResourceServers", "cognito-idp:ListUserPoolClients", "cognito-idp:ListUserPools", "cognito-idp:ListTagsForResource", "comprehend:Describe*", "comprehend:List*", "config:Describe*", "config:GetAggregateResourceConfig", "config:GetStoredQuery", "config:List*", "config:SelectAggregateResourceConfig", "connect:Describe*", "connect:GetMetricDataV2", "connect:GetTaskTemplate", "connect:List*", "cur:Describe*", "cur:Get*", "databrew:Describe*", "databrew:List*", "datapipeline:Describe*", "datapipeline:GetPipelineDefinition", "datapipeline:List*", "datasync:Describe*", "datasync:List*", "deadline:GetFarm", "deadline:GetFleet", "deadline:GetLicenseEndpoint", "deadline:GetMonitor", "deadline:GetQueue", "deadline:GetQueueEnvironment", "deadline:GetQueueFleetAssociation", "deadline:GetStorageProfile", "deadline:List*", "detective:GetMembers", "detective:List*", "devicefarm:GetDevicePool", "devicefarm:GetInstanceProfile", "devicefarm:GetNetworkProfile", "devicefarm:GetProject", "devicefarm:GetTestGridProject", "devicefarm:GetVPCEConfiguration", "devicefarm:List*", "devops-guru:Describe*", "devops-guru:GetResourceCollection", "devops-guru:List*", "directconnect:DescribeConnections", "directconnect:DescribeDirectConnectGatewayAssociations", "directconnect:DescribeDirectConnectGatewayAttachments", "directconnect:DescribeDirectConnectGateways", "directconnect:DescribeHostedConnections", "directconnect:DescribeInterconnects", "directconnect:DescribeLags", "directconnect:DescribeTags", "directconnect:DescribeVirtualGateways", "directconnect:DescribeVirtualInterfaces", "directconnect:ListVirtualInterfaceRoutes", "dms:Describe*", "dms:List*", "ds:Describe*", "dynamodb:Describe*", "dynamodb:GetResourcePolicy", "dynamodb:List*", "ec2:Describe*", "ec2:GetActiveVpnTunnelStatus", "ec2:GetAssociatedEnclaveCertificateIamRoles", "ec2:GetAssociatedIpv6PoolCidrs", "ec2:GetAwsNetworkPerformanceData", "ec2:GetCapacityManagerAttributes", "ec2:GetCapacityManagerMetricData", "ec2:GetCapacityManagerMonitoredTagKeys", "ec2:GetIpamDiscoveredAccounts", "ec2:GetIpamDiscoveredPublicAddresses", "ec2:GetIpamDiscoveredResourceCidrs", "ec2:GetIpamPoolAllocations", "ec2:GetIpamPoolCidrs", "ec2:GetIpamResourceCidrs", "ec2:GetManagedPrefixListAssociations", "ec2:GetManagedPrefixListEntries", "ec2:GetNetworkInsightsAccessScopeContent", "ec2:GetRouteServerPropagations", "ec2:GetRouteServerRoutingDatabase", "ec2:GetSnapshotBlockPublicAccessState", "ec2:GetSubnetCidrReservations", "ec2:GetTransitGatewayAttachmentPropagations", "ec2:GetTransitGatewayMulticastDomainAssociations", "ec2:GetTransitGatewayPolicyTableEntries", "ec2:GetTransitGatewayPrefixListReferences", "ec2:GetTransitGatewayRouteTableAssociations", "ec2:GetTransitGatewayRouteTablePropagations", "ec2:GetVerifiedAccessEndpointPolicy", "ec2:GetVerifiedAccessGroupPolicy", "ec2:GetVerifiedAccessInstanceWebAcl", "ec2:GetVpcResourcesBlockingEncryptionEnforcement", "ec2:GetVpnConnectionDeviceTypes", "ec2:GetVpnTunnelReplacementStatus", "ec2:SearchLocalGatewayRoutes", "ec2:SearchTransitGatewayRoutes", "ecr:Describe*", "ecr:GetLifecyclePolicy", "ecr:GetRegistryPolicy", "ecr:GetRepositoryPolicy", "ecr:List*", "ecs:Describe*", "ecs:List*", "eks:Describe*", "eks:List*", "elasticache:Describe*", "elasticache:List*", "elasticbeanstalk:Describe*", "elasticbeanstalk:List*", "elasticfilesystem:Describe*", "elasticloadbalancing:GetResourcePolicy", "elasticloadbalancing:GetTrustStoreCaCertificatesBundle", "elasticloadbalancing:GetTrustStoreRevocationContent", "elasticloadbalancing:Describe*", "elasticmapreduce:Describe*", "elasticmapreduce:List*", "emr-containers:Describe*", "emr-containers:List*", "emr-serverless:GetApplication", "emr-serverless:List*", "es:Describe*", "es:List*", "events:Describe*", "events:List*", "evidently:GetExperiment", "evidently:GetFeature", "evidently:GetLaunch", "evidently:GetProject", "evidently:GetSegment", "evidently:List*", "firehose:Describe*", "firehose:List*", "fis:GetExperimentTemplate", "fis:GetTargetAccountConfiguration", "fis:List*", "fms:GetNotificationChannel", "fms:GetPolicy", "fms:List*", "forecast:Describe*", "forecast:List*", "frauddetector:BatchGetVariable", "frauddetector:Describe*", "frauddetector:GetDetectors", "frauddetector:GetDetectorVersion", "frauddetector:GetEntityTypes", "frauddetector:GetEventTypes", "frauddetec …(truncated, see JSON export)
```

```diff
--- original.json
+++ least-privilege.json
@@ -140,5 +140,4 @@
         "cloudformation:GetResource",
         "cloudformation:GetStackPolicy",
-        "cloudformation:GetTemplate",
         "cloudformation:List*",
         "cloudfront:Describe*",
@@ -367,5 +366,4 @@
         "ecs:Describe*",
         "ecs:List*",
-        "eks:AccessKubernetesApi",
         "eks:Describe*",
         "eks:List*",
@@ -620,5 +618,4 @@
         "lightsail:GetStaticIps",
         "logs:Describe*",
-        "logs:FilterLogEvents",
         "logs:GetDataProtectionPolicy",
         "logs:GetDelivery",
@@ -628,9 +625,7 @@
         "logs:GetLogAnomalyDetector",
         "logs:GetLogDelivery",
-        "logs:GetLogEvents",
         "logs:GetLogGroupFields",
         "logs:GetQueryResults",
         "logs:List*",
-        "logs:StartQuery",
         "logs:StopLiveTail",
         "logs:StopQuery",
@@ -1008,4 +1003,51 @@
     },
     {
+      "Sid": "AIOPSServiceAccessScopedCloudformation",
+      "Effect": "Allow",
+      "Action": [
+        "cloudformation:GetTemplate"
+      ],
+      "Resource": [
+        "arn:aws:cloudformation:<REGION>:182102543085:stack/<STACK_PREFIX>-*/*"
+      ],
+      "Condition": {
+        "StringEquals": {
+          "aws:ResourceAccount": "182102543085"
+        }
+      }
+    },
+    {
+      "Sid": "AIOPSServiceAccessScopedEks",
+      "Effect": "Allow",
+      "Action": [
+        "eks:AccessKubernetesApi"
+      ],
+      "Resource": [
+        "arn:aws:eks:<REGION>:182102543085:<EKS_RESOURCE>"
+      ],
+      "Condition": {
+        "StringEquals": {
+          "aws:ResourceAccount": "182102543085"
+        }
+      }
+    },
+    {
+      "Sid": "AIOPSServiceAccessScopedLogs",
+      "Effect": "Allow",
+      "Action": [
+        "logs:FilterLogEvents",
+        "logs:GetLogEvents",
+        "logs:StartQuery"
+      ],
+      "Resource": [
+        "arn:aws:logs:<REGION>:182102543085:log-group:<LOG_GROUP>:*"
+      ],
+      "Condition": {
+        "StringEquals": {
+          "aws:ResourceAccount": "182102543085"
+        }
+      }
+    },
+    {
       "Sid": "AIOPSAPIGatewayAccess",
       "Effect": "Allow",
@@ -1037,5 +1079,7 @@
       "Sid": "AllowListBucketAWSLogs",
       "Effect": "Allow",
-      "Action": "s3:ListBucket",
+      "Action": [
+        "s3:ListBucket"
+      ],
       "Resource": "arn:aws:s3:::*",
       "Condition": {
```

Apply:

```bash
aws accessanalyzer validate-policy --policy-type IDENTITY_POLICY --policy-document file://remediation/AIDevOpsAgentAccessPolicy-least-privilege.json
aws iam create-policy --policy-name AIDevOpsAgentAccessPolicy-LeastPrivilege --policy-document file://remediation/AIDevOpsAgentAccessPolicy-least-privilege.json
aws iam attach-role-policy --role-name ec2-console-devops-agent-us-east-1 --policy-arn arn:aws:iam::182102543085:policy/AIDevOpsAgentAccessPolicy-LeastPrivilege
aws iam detach-role-policy --role-name ec2-console-devops-agent-us-east-1 --policy-arn arn:aws:iam::aws:policy/AIDevOpsAgentAccessPolicy
```

## Positive controls observed

- **Confused-deputy protection on service trust** — ec2-console-devops-agent-us-east-1: aidevops.amazonaws.com restricted by aws:sourceaccount, aws:sourcearn
