"""IAM security knowledge base: sensitive actions, escalation methods, managed policies.

Everything that encodes "security opinion" lives here so detectors stay generic and the
rules can be reviewed/extended in one place.
"""
from __future__ import annotations

from dataclasses import dataclass, field

# --------------------------------------------------------------------------------------
# Sensitive action catalog. category -> (weight for blast radius, severity when on "*")
# --------------------------------------------------------------------------------------
CATEGORIES = {
    "permissions-management": {"weight": 15, "severity": "HIGH", "label": "Permissions management"},
    "privilege-escalation": {"weight": 15, "severity": "HIGH", "label": "Privilege escalation primitive"},
    "credential-access": {"weight": 12, "severity": "HIGH", "label": "Credential / secret access"},
    "defense-evasion": {"weight": 12, "severity": "HIGH", "label": "Logging / detection tampering"},
    "code-execution": {"weight": 10, "severity": "HIGH", "label": "Compute / code execution"},
    "data-destruction": {"weight": 8, "severity": "HIGH", "label": "Destructive write"},
    "data-write": {"weight": 8, "severity": "MEDIUM", "label": "Data write / exposure"},
    "data-read": {"weight": 6, "severity": "MEDIUM", "label": "Sensitive data read"},
}

SENSITIVE_ACTIONS: dict[str, str] = {
    # permissions management
    "iam:CreatePolicyVersion": "privilege-escalation",
    "iam:SetDefaultPolicyVersion": "privilege-escalation",
    "iam:AttachUserPolicy": "privilege-escalation",
    "iam:AttachGroupPolicy": "privilege-escalation",
    "iam:AttachRolePolicy": "privilege-escalation",
    "iam:PutUserPolicy": "privilege-escalation",
    "iam:PutGroupPolicy": "privilege-escalation",
    "iam:PutRolePolicy": "privilege-escalation",
    "iam:AddUserToGroup": "privilege-escalation",
    "iam:UpdateAssumeRolePolicy": "privilege-escalation",
    "iam:PassRole": "privilege-escalation",
    "iam:CreateAccessKey": "credential-access",
    "iam:CreateLoginProfile": "credential-access",
    "iam:UpdateLoginProfile": "credential-access",
    "iam:CreateUser": "permissions-management",
    "iam:CreateRole": "permissions-management",
    "iam:CreatePolicy": "permissions-management",
    "iam:DeletePolicy": "permissions-management",
    "iam:DeleteRolePermissionsBoundary": "permissions-management",
    "iam:DeleteUserPermissionsBoundary": "permissions-management",
    "iam:PutRolePermissionsBoundary": "permissions-management",
    "iam:PutUserPermissionsBoundary": "permissions-management",
    "iam:CreateServiceLinkedRole": "permissions-management",
    "iam:DeactivateMFADevice": "defense-evasion",
    "sts:AssumeRole": "privilege-escalation",
    "sts:AssumeRoleWithWebIdentity": "privilege-escalation",
    "organizations:LeaveOrganization": "defense-evasion",
    "organizations:DeletePolicy": "permissions-management",
    "organizations:DetachPolicy": "permissions-management",
    "s3:PutBucketPolicy": "permissions-management",
    "s3:PutBucketAcl": "data-write",
    "s3:PutObjectAcl": "data-write",
    "s3:DeleteBucketPolicy": "permissions-management",
    "s3:PutBucketPublicAccessBlock": "data-write",
    "s3:PutAccountPublicAccessBlock": "data-write",
    "kms:PutKeyPolicy": "permissions-management",
    "kms:CreateGrant": "permissions-management",
    "lambda:AddPermission": "permissions-management",
    "secretsmanager:PutResourcePolicy": "permissions-management",
    "ecr:SetRepositoryPolicy": "permissions-management",
    "sns:AddPermission": "permissions-management",
    "sqs:AddPermission": "permissions-management",
    # credential / secret access
    "secretsmanager:GetSecretValue": "credential-access",
    "ssm:GetParameter": "credential-access",
    "ssm:GetParameters": "credential-access",
    "ssm:GetParametersByPath": "credential-access",
    "kms:Decrypt": "credential-access",
    "ec2:GetPasswordData": "credential-access",
    "ecr:GetAuthorizationToken": "credential-access",
    "redshift:GetClusterCredentials": "credential-access",
    "rds:GenerateDBAuthToken": "credential-access",
    "lambda:GetFunction": "credential-access",
    "eks:AccessKubernetesApi": "credential-access",
    "cognito-idp:AdminInitiateAuth": "credential-access",
    "cognito-idp:AdminSetUserPassword": "credential-access",
    # defense evasion
    "cloudtrail:StopLogging": "defense-evasion",
    "cloudtrail:DeleteTrail": "defense-evasion",
    "cloudtrail:UpdateTrail": "defense-evasion",
    "cloudtrail:PutEventSelectors": "defense-evasion",
    "guardduty:DeleteDetector": "defense-evasion",
    "guardduty:UpdateDetector": "defense-evasion",
    "guardduty:DisassociateFromMasterAccount": "defense-evasion",
    "config:StopConfigurationRecorder": "defense-evasion",
    "config:DeleteConfigurationRecorder": "defense-evasion",
    "logs:DeleteLogGroup": "defense-evasion",
    "logs:DeleteLogStream": "defense-evasion",
    "securityhub:DisableSecurityHub": "defense-evasion",
    "access-analyzer:DeleteAnalyzer": "defense-evasion",
    # code execution
    "ec2:RunInstances": "code-execution",
    "ec2:ModifyInstanceAttribute": "code-execution",
    "lambda:CreateFunction": "code-execution",
    "lambda:UpdateFunctionCode": "code-execution",
    "lambda:UpdateFunctionConfiguration": "code-execution",
    "lambda:InvokeFunction": "code-execution",
    "lambda:CreateEventSourceMapping": "code-execution",
    "ssm:SendCommand": "code-execution",
    "ssm:StartSession": "code-execution",
    "ecs:RunTask": "code-execution",
    "ecs:RegisterTaskDefinition": "code-execution",
    "glue:CreateDevEndpoint": "code-execution",
    "glue:UpdateDevEndpoint": "code-execution",
    "cloudformation:CreateStack": "code-execution",
    "cloudformation:UpdateStack": "code-execution",
    "datapipeline:CreatePipeline": "code-execution",
    "sagemaker:CreateNotebookInstance": "code-execution",
    "sagemaker:CreatePresignedNotebookInstanceUrl": "code-execution",
    "codebuild:StartBuild": "code-execution",
    "codebuild:CreateProject": "code-execution",
    # data destruction
    "s3:DeleteBucket": "data-destruction",
    "s3:DeleteObject": "data-destruction",
    "s3:DeleteObjectVersion": "data-destruction",
    "ec2:TerminateInstances": "data-destruction",
    "ec2:DeleteSnapshot": "data-destruction",
    "ec2:DeleteVolume": "data-destruction",
    "rds:DeleteDBInstance": "data-destruction",
    "rds:DeleteDBCluster": "data-destruction",
    "dynamodb:DeleteTable": "data-destruction",
    "kms:ScheduleKeyDeletion": "data-destruction",
    "kms:DisableKey": "data-destruction",
    "backup:DeleteRecoveryPoint": "data-destruction",
    # data write
    "s3:PutObject": "data-write",
    "ec2:ModifySnapshotAttribute": "data-write",
    "ec2:CreateSnapshot": "data-write",
    "rds:ModifyDBSnapshotAttribute": "data-write",
    "rds:CopyDBSnapshot": "data-write",
    "dynamodb:PutItem": "data-write",
    "dynamodb:UpdateItem": "data-write",
    "ec2:AuthorizeSecurityGroupIngress": "data-write",
    # sensitive data read
    "s3:GetObject": "data-read",
    "s3:GetObjectVersion": "data-read",
    "dynamodb:Scan": "data-read",
    "dynamodb:Query": "data-read",
    "dynamodb:GetItem": "data-read",
    "dynamodb:BatchGetItem": "data-read",
    "logs:GetLogEvents": "data-read",
    "logs:FilterLogEvents": "data-read",
    "logs:StartQuery": "data-read",
    "cloudformation:GetTemplate": "data-read",
    "athena:GetQueryResults": "data-read",
    "rds:DownloadDBLogFilePortion": "data-read",
    "sqs:ReceiveMessage": "data-read",
    "kinesis:GetRecords": "data-read",
    "codecommit:GetFile": "data-read",
    "ebs:GetSnapshotBlock": "data-read",
}

# Services where "svc:*" is effectively account takeover or near it.
CRITICAL_SERVICES = {"iam", "sts", "organizations", "kms", "secretsmanager", "cloudtrail", "account"}
HIGH_RISK_SERVICES = {
    "s3", "ec2", "lambda", "dynamodb", "rds", "ssm", "ecs", "eks", "glue", "cloudformation",
    "sagemaker", "codebuild", "logs", "guardduty", "config", "backup", "ecr", "redshift",
}

READ_VERBS = (
    "Get", "List", "Describe", "BatchGet", "BatchDescribe", "Search", "Lookup", "View", "Read",
    "Query", "Scan", "Filter", "Select", "Check", "Validate", "Estimate", "Test", "Simulate",
    "Preview", "Evaluate", "Generate", "Retrieve", "Detect", "Analyze", "Head",
)
LIST_VERBS = ("List", "Describe", "BatchDescribe", "Search", "Lookup")


def access_level(action: str) -> str:
    """Rough AWS access-level classification derived from the API verb."""
    if ":" not in action:
        return "Unknown"
    verb = action.split(":", 1)[1]
    if verb in ("*", ""):
        return "All"
    if SENSITIVE_ACTIONS.get(action) in ("privilege-escalation", "permissions-management"):
        return "Permissions management"
    if verb.startswith(LIST_VERBS):
        return "List"
    if verb.startswith(READ_VERBS):
        return "Read"
    if "Policy" in verb or "Permission" in verb or "Acl" in verb:
        return "Permissions management"
    if verb.startswith(("Tag", "Untag")):
        return "Tagging"
    return "Write"


# --------------------------------------------------------------------------------------
# Privilege-escalation methods (Rhino Security Labs research + common cloud pentest TTPs)
# --------------------------------------------------------------------------------------
@dataclass(frozen=True)
class EscalationMethod:
    id: str
    name: str
    requires: tuple[tuple[str, ...], ...]  # AND over groups, OR inside group
    completion: tuple[str, ...] = ()  # optional "trigger" permission; missing => latent
    pass_to_service: str | None = None  # PassRole target service principal
    target: str = "self"  # self | users | groups | roles | passrole | instances
    description: str = ""
    mitre: tuple[str, ...] = ("T1098",)


ESCALATION_METHODS: list[EscalationMethod] = [
    EscalationMethod("PRIV-001", "Create new default policy version", (("iam:CreatePolicyVersion",),), target="self",
                     description="Can publish a new default version of a customer-managed policy attached to itself containing Action:* / Resource:*."),
    EscalationMethod("PRIV-002", "Roll back to a permissive policy version", (("iam:SetDefaultPolicyVersion",),), target="self",
                     description="Can switch a policy to an older, more permissive version that is still stored."),
    EscalationMethod("PRIV-003", "Attach managed policy to user", (("iam:AttachUserPolicy",),), target="self",
                     description="Can attach arn:aws:iam::aws:policy/AdministratorAccess to itself or another user."),
    EscalationMethod("PRIV-004", "Attach managed policy to group", (("iam:AttachGroupPolicy",),), target="self",
                     description="Can attach AdministratorAccess to a group it belongs to."),
    EscalationMethod("PRIV-005", "Attach managed policy to role", (("iam:AttachRolePolicy",),), target="roles",
                     description="Can attach AdministratorAccess to a role and then use that role."),
    EscalationMethod("PRIV-006", "Write inline user policy", (("iam:PutUserPolicy",),), target="self",
                     description="Can write an inline policy granting itself Action:* on Resource:*."),
    EscalationMethod("PRIV-007", "Write inline group policy", (("iam:PutGroupPolicy",),), target="self",
                     description="Can write an inline admin policy on a group it belongs to."),
    EscalationMethod("PRIV-008", "Write inline role policy", (("iam:PutRolePolicy",),), target="roles",
                     description="Can write an inline admin policy on any matching role."),
    EscalationMethod("PRIV-009", "Add self to privileged group", (("iam:AddUserToGroup",),), target="groups",
                     description="Can add itself to any group, inheriting that group's permissions."),
    EscalationMethod("PRIV-010", "Create access key for another user", (("iam:CreateAccessKey",),), target="users",
                     description="Can mint long-lived access keys for other (possibly admin) users.", mitre=("T1098.001",)),
    EscalationMethod("PRIV-011", "Create console login profile", (("iam:CreateLoginProfile",),), target="users",
                     description="Can set a console password for users that have none and log in as them.", mitre=("T1098",)),
    EscalationMethod("PRIV-012", "Reset another user's console password", (("iam:UpdateLoginProfile",),), target="users",
                     description="Can change console passwords of other users and take over their sessions.", mitre=("T1098",)),
    EscalationMethod("PRIV-013", "Rewrite role trust policy", (("iam:UpdateAssumeRolePolicy",),), completion=("sts:AssumeRole",), target="roles",
                     description="Can rewrite a role's trust policy to trust itself, then assume the role."),
    EscalationMethod("PRIV-014", "PassRole to new EC2 instance", (("iam:PassRole",), ("ec2:RunInstances",)), pass_to_service="ec2.amazonaws.com", target="passrole",
                     description="Can launch an EC2 instance with a privileged instance profile and read its credentials from IMDS.", mitre=("T1098", "T1078.004")),
    EscalationMethod("PRIV-015", "PassRole to new Lambda function", (("iam:PassRole",), ("lambda:CreateFunction",)),
                     completion=("lambda:InvokeFunction", "lambda:CreateEventSourceMapping", "lambda:CreateFunctionUrlConfig", "lambda:AddPermission"),
                     pass_to_service="lambda.amazonaws.com", target="passrole",
                     description="Can create a Lambda function that executes attacker code with any passable execution role.", mitre=("T1648", "T1098")),
    EscalationMethod("PRIV-016", "Hijack existing Lambda code", (("lambda:UpdateFunctionCode",),), target="self",
                     description="Can replace the code of existing functions and inherit their execution roles.", mitre=("T1648",)),
    EscalationMethod("PRIV-017", "PassRole to Glue dev endpoint", (("iam:PassRole",), ("glue:CreateDevEndpoint",)), pass_to_service="glue.amazonaws.com", target="passrole",
                     description="Can create a Glue dev endpoint with a privileged role and SSH into it."),
    EscalationMethod("PRIV-018", "PassRole to CloudFormation stack", (("iam:PassRole",), ("cloudformation:CreateStack",)), pass_to_service="cloudformation.amazonaws.com", target="passrole",
                     description="Can deploy a stack that creates arbitrary resources with a privileged service role."),
    EscalationMethod("PRIV-019", "PassRole to ECS task", (("iam:PassRole",), ("ecs:RunTask", "ecs:StartTask"), ("ecs:RegisterTaskDefinition",)), pass_to_service="ecs-tasks.amazonaws.com", target="passrole",
                     description="Can register and run a task definition using a privileged task role."),
    EscalationMethod("PRIV-020", "PassRole to SageMaker notebook", (("iam:PassRole",), ("sagemaker:CreateNotebookInstance",)), pass_to_service="sagemaker.amazonaws.com", target="passrole",
                     description="Can start a notebook with a privileged execution role and open a shell in it."),
    EscalationMethod("PRIV-021", "PassRole to CodeBuild project", (("iam:PassRole",), ("codebuild:CreateProject",)), completion=("codebuild:StartBuild",), pass_to_service="codebuild.amazonaws.com", target="passrole",
                     description="Can run arbitrary build commands with a privileged CodeBuild service role."),
    EscalationMethod("PRIV-022", "Remote command on EC2 via SSM", (("ssm:SendCommand", "ssm:StartSession"),), target="instances",
                     description="Can execute commands on managed instances and steal their instance-profile credentials.", mitre=("T1651",)),
    EscalationMethod("PRIV-023", "Remove permissions boundary", (("iam:DeleteUserPermissionsBoundary", "iam:DeleteRolePermissionsBoundary"),), target="self",
                     description="Can delete the permissions boundary that is limiting it."),
]

# --------------------------------------------------------------------------------------
# Well-known AWS managed policies (used when an export references but omits the document)
# --------------------------------------------------------------------------------------
BROAD_MANAGED_POLICIES = {
    "AdministratorAccess": ("CRITICAL", "Full administrative access to every service and resource."),
    "PowerUserAccess": ("HIGH", "Full access to all services except IAM/Organizations - can still exfiltrate and destroy data."),
    "IAMFullAccess": ("CRITICAL", "Full IAM control - trivially escalates to administrator."),
    "AmazonS3FullAccess": ("HIGH", "Read/write/delete every S3 bucket and object."),
    "AmazonEC2FullAccess": ("HIGH", "Full EC2 control including instance launch with any profile."),
    "AWSLambda_FullAccess": ("HIGH", "Full Lambda control including code updates of all functions."),
    "AmazonDynamoDBFullAccess": ("HIGH", "Read/write/delete every DynamoDB table."),
    "SecretsManagerReadWrite": ("HIGH", "Read every secret in the account."),
    "AmazonRDSFullAccess": ("HIGH", "Full RDS control including snapshot sharing."),
    "AWSOrganizationsFullAccess": ("CRITICAL", "Full AWS Organizations control."),
}

KNOWN_MANAGED_DOCUMENTS = {
    "AdministratorAccess": {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]},
    "PowerUserAccess": {"Version": "2012-10-17", "Statement": [
        {"Effect": "Allow", "NotAction": ["iam:*", "organizations:*", "account:*"], "Resource": "*"},
        {"Effect": "Allow", "Action": ["iam:CreateServiceLinkedRole", "iam:DeleteServiceLinkedRole", "iam:ListRoles",
                                       "organizations:DescribeOrganization", "account:ListRegions"], "Resource": "*"}]},
    "IAMFullAccess": {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": ["iam:*", "organizations:DescribeAccount",
        "organizations:DescribeOrganization", "organizations:DescribeOrganizationalUnit", "organizations:DescribePolicy",
        "organizations:ListChildren", "organizations:ListParents", "organizations:ListPoliciesForTarget",
        "organizations:ListRoots", "organizations:ListPolicies", "organizations:ListTargetsForPolicy"], "Resource": "*"}]},
    "AmazonS3FullAccess": {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": ["s3:*", "s3-object-lambda:*"], "Resource": "*"}]},
    "ReadOnlyAccess": {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": ["*:Describe*", "*:Get*", "*:List*"], "Resource": "*"}]},
    "AmazonEC2FullAccess": {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "ec2:*", "Resource": "*"}]},
}

# Conditions that meaningfully narrow who/where an Allow applies.
STRONG_CONDITION_KEYS = {
    "aws:multifactorauthpresent", "aws:multifactorauthage", "aws:principalorgid", "aws:principalorgpaths",
    "aws:sourceip", "aws:sourcevpc", "aws:sourcevpce", "aws:principalarn", "aws:sourceaccount",
    "aws:sourcearn", "sts:externalid", "aws:resourceaccount", "aws:principalaccount", "iam:passedtoservice",
    "aws:requestedregion", "aws:resourcetag", "aws:principaltag",
}

# Service principals that can act on behalf of *other* customers -> confused deputy risk
# if the trust has no aws:SourceAccount / aws:SourceArn.
CONFUSED_DEPUTY_SAFE_SERVICES = {
    "ec2.amazonaws.com", "lambda.amazonaws.com", "ecs-tasks.amazonaws.com", "eks.amazonaws.com",
    "edgelambda.amazonaws.com", "ssm.amazonaws.com", "states.amazonaws.com", "eks-fargate-pods.amazonaws.com",
    "glue.amazonaws.com", "codebuild.amazonaws.com", "sagemaker.amazonaws.com", "batch.amazonaws.com",
    "elasticmapreduce.amazonaws.com", "apigateway.amazonaws.com", "cloudformation.amazonaws.com",
}

# Well-known OIDC providers and the claim that MUST be pinned.
OIDC_SUBJECT_KEYS = {
    "token.actions.githubusercontent.com": ("token.actions.githubusercontent.com:sub", "repo:<GITHUB_ORG>/<REPO>:ref:refs/heads/main"),
    "gitlab.com": ("gitlab.com:sub", "project_path:<GROUP>/<PROJECT>:ref_type:branch:ref:main"),
    "app.terraform.io": ("app.terraform.io:sub", "organization:<ORG>:project:<PROJECT>:workspace:<WS>:run_phase:*"),
}

# ARN templates used by the least-privilege synthesizer when scoping Resource:*.
RESOURCE_TEMPLATES = {
    "s3": ["arn:aws:s3:::<BUCKET_NAME>", "arn:aws:s3:::<BUCKET_NAME>/*"],
    "lambda": ["arn:aws:lambda:<REGION>:{acct}:function:<FUNCTION_PREFIX>-*"],
    "iam": ["arn:aws:iam::{acct}:role/<ROLE_NAME>"],
    "ec2": ["arn:aws:ec2:<REGION>:{acct}:instance/*"],
    "dynamodb": ["arn:aws:dynamodb:<REGION>:{acct}:table/<TABLE_NAME>"],
    "secretsmanager": ["arn:aws:secretsmanager:<REGION>:{acct}:secret:<APP_PREFIX>/*"],
    "ssm": ["arn:aws:ssm:<REGION>:{acct}:parameter/<APP_PREFIX>/*"],
    "kms": ["arn:aws:kms:<REGION>:{acct}:key/<KEY_ID>"],
    "sqs": ["arn:aws:sqs:<REGION>:{acct}:<QUEUE_NAME>"],
    "sns": ["arn:aws:sns:<REGION>:{acct}:<TOPIC_NAME>"],
    "logs": ["arn:aws:logs:<REGION>:{acct}:log-group:<LOG_GROUP>:*"],
    "rds": ["arn:aws:rds:<REGION>:{acct}:db:<DB_INSTANCE>"],
    "ecr": ["arn:aws:ecr:<REGION>:{acct}:repository/<REPOSITORY>"],
    "cloudformation": ["arn:aws:cloudformation:<REGION>:{acct}:stack/<STACK_PREFIX>-*/*"],
}

# Curated "day-to-day" action sets used to replace service wildcards (svc:*).
SERVICE_WORKLOAD_ACTIONS = {
    "s3": {
        "list": ["s3:ListAllMyBuckets", "s3:GetBucketLocation"],
        "bucket": ["s3:ListBucket"],
        "object": ["s3:GetObject", "s3:PutObject"],
    },
    "ec2": {"list": ["ec2:Describe*"], "object": ["ec2:StartInstances", "ec2:StopInstances", "ec2:RebootInstances"]},
    "lambda": {"list": ["lambda:ListFunctions", "lambda:GetAccountSettings"], "object": ["lambda:GetFunction", "lambda:InvokeFunction", "lambda:UpdateFunctionCode"]},
    "dynamodb": {"list": ["dynamodb:ListTables", "dynamodb:DescribeLimits"], "object": ["dynamodb:GetItem", "dynamodb:Query", "dynamodb:PutItem", "dynamodb:UpdateItem", "dynamodb:DescribeTable"]},
    "sqs": {"list": ["sqs:ListQueues"], "object": ["sqs:SendMessage", "sqs:ReceiveMessage", "sqs:DeleteMessage", "sqs:GetQueueAttributes"]},
    "sns": {"list": ["sns:ListTopics"], "object": ["sns:Publish", "sns:GetTopicAttributes"]},
    "logs": {"list": ["logs:DescribeLogGroups"], "object": ["logs:CreateLogStream", "logs:PutLogEvents", "logs:DescribeLogStreams"]},
    "secretsmanager": {"list": ["secretsmanager:ListSecrets"], "object": ["secretsmanager:GetSecretValue", "secretsmanager:DescribeSecret"]},
    "ssm": {"list": ["ssm:DescribeParameters"], "object": ["ssm:GetParameter", "ssm:GetParameters"]},
    "kms": {"list": ["kms:ListKeys", "kms:ListAliases"], "object": ["kms:Encrypt", "kms:Decrypt", "kms:GenerateDataKey", "kms:DescribeKey"]},
    "ecr": {"list": ["ecr:GetAuthorizationToken"], "object": ["ecr:BatchGetImage", "ecr:GetDownloadUrlForLayer", "ecr:BatchCheckLayerAvailability", "ecr:PutImage"]},
    "iam": {"list": ["iam:ListRoles", "iam:ListPolicies"], "object": ["iam:GetRole", "iam:GetPolicy", "iam:GetPolicyVersion"]},
    "rds": {"list": ["rds:DescribeDBInstances", "rds:DescribeDBClusters"], "object": ["rds:StartDBInstance", "rds:StopDBInstance", "rds:RebootDBInstance"]},
    "cloudformation": {"list": ["cloudformation:ListStacks", "cloudformation:DescribeStacks"], "object": ["cloudformation:CreateChangeSet", "cloudformation:ExecuteChangeSet", "cloudformation:DescribeStackEvents"]},
}

# Defense-evasion and break-glass deny set appended to admin replacements.
ADMIN_PROTECTION_DENY = [
    "cloudtrail:StopLogging", "cloudtrail:DeleteTrail", "cloudtrail:UpdateTrail", "guardduty:DeleteDetector",
    "guardduty:UpdateDetector", "config:StopConfigurationRecorder", "config:DeleteConfigurationRecorder",
    "organizations:LeaveOrganization", "iam:DeleteAccountPasswordPolicy", "iam:DeactivateMFADevice",
    "access-analyzer:DeleteAnalyzer", "securityhub:DisableSecurityHub",
]

SERVICE_PRINCIPAL_FOR_ACTION_PREFIX = {
    "lambda": "lambda.amazonaws.com", "ec2": "ec2.amazonaws.com", "ecs": "ecs-tasks.amazonaws.com",
    "glue": "glue.amazonaws.com", "cloudformation": "cloudformation.amazonaws.com", "sagemaker": "sagemaker.amazonaws.com",
    "codebuild": "codebuild.amazonaws.com", "states": "states.amazonaws.com", "batch": "batch.amazonaws.com",
}

MITRE_NAMES = {
    "T1078.004": "Valid Accounts: Cloud Accounts",
    "T1098": "Account Manipulation",
    "T1098.001": "Account Manipulation: Additional Cloud Credentials",
    "T1098.003": "Account Manipulation: Additional Cloud Roles",
    "T1136.003": "Create Account: Cloud Account",
    "T1199": "Trusted Relationship",
    "T1530": "Data from Cloud Storage",
    "T1552.005": "Unsecured Credentials: Cloud Instance Metadata API",
    "T1562.008": "Impair Defenses: Disable or Modify Cloud Logs",
    "T1580": "Cloud Infrastructure Discovery",
    "T1648": "Serverless Execution",
    "T1651": "Cloud Administration Command",
    "T1485": "Data Destruction",
    "T1555.006": "Credentials from Password Stores: Cloud Secrets Management Stores",
}
