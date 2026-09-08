# -----------------------------------------------
# Phase 2 — GitHub Actions CI/CD via OIDC (pulled forward from its
# original slot — see locals.tf's github_oidc_provider_arn comment for why)
#
# No static AWS keys in GitHub secrets. GitHub Actions presents a
# short-lived signed OIDC token; AWS trades it for temporary STS
# credentials scoped to one of two roles: a read-only plan role any ref/PR
# can assume, and a read-write apply role only a push to main can assume.
#
# The trust-boundary roles now come from the shared oidc-cicd module
# (app.terraform.io/macgothub/oidc-cicd/aws) — the read/write split, the
# branch pin, and the OIDC plumbing were identical across three sibling
# repos. This file keeps only the project-specific permission policies
# bolted onto the module's roles; the module deliberately attaches none.
#
# The OIDC provider itself is not created here — satellite-tracker's Phase
# 5 already registered token.actions.githubusercontent.com in this account
# (providers are keyed by URL, not repo), so the module reuses it via
# existing_oidc_provider_arn. github_subject_prefix_override carries
# GitHub's immutable numeric-ID sub claim form (see locals.tf).
# -----------------------------------------------

module "cicd" {
  source  = "app.terraform.io/macgothub/oidc-cicd/aws"
  version = "~> 0.2"

  name_prefix = local.name_prefix

  create_oidc_provider           = false
  existing_oidc_provider_arn     = local.github_oidc_provider_arn
  github_subject_prefix_override = local.github_oidc_sub_prefix

  # No tags argument: provider default_tags already applies common_tags to
  # every resource in this project, these roles included.
}

# The roles pre-exist in state (bootstrap-imported 2026-08-24). Their names
# and trust policies are byte-identical to what the module generates, so
# these are pure state address changes -- no resource replacement.
moved {
  from = aws_iam_role.gha_plan
  to   = module.cicd.aws_iam_role.plan
}

moved {
  from = aws_iam_role.gha_apply
  to   = module.cicd.aws_iam_role.apply
}

# -----------------------------------------------
# Permissions — read (both roles: plan needs it to compute a diff, apply
# needs it too since apply always plans first)
# -----------------------------------------------

resource "aws_iam_policy" "gha_read" {
  # checkov:skip=CKV_AWS_355: two Resource "*" statements in this policy on
  # "restrictable" actions — GuardDutyRead (GuardDuty's Get/List actions
  # have no documented per-detector resource-level IAM support) and
  # CloudTrailDescribe (DescribeTrails specifically doesn't support
  # resource-level scoping at all, confirmed live: scoping it to the trail
  # ARN still failed). Every other statement in this policy is scoped to a
  # specific ARN; "*" here is a pragmatic ceiling, not a shortcut.
  name = "${local.name_prefix}-gha-read"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "CallerIdentity"
        Effect   = "Allow"
        Action   = "sts:GetCallerIdentity"
        Resource = "*" # no resource-level permission model exists for this action
      },
      {
        Sid      = "StateBucketList"
        Effect   = "Allow"
        Action   = "s3:ListBucket"
        Resource = "arn:aws:s3:::351668480009-opentofu-state"
        Condition = {
          StringLike = { "s3:prefix" = ["detect-respond/pipeline/*"] }
        }
      },
      {
        Sid      = "StateObjectRead"
        Effect   = "Allow"
        Action   = "s3:GetObject"
        Resource = "arn:aws:s3:::351668480009-opentofu-state/detect-respond/pipeline/*"
      },
      {
        Sid      = "StateLock"
        Effect   = "Allow"
        Action   = ["dynamodb:GetItem", "dynamodb:PutItem", "dynamodb:DeleteItem"]
        Resource = "arn:aws:dynamodb:us-east-1:${data.aws_caller_identity.current.account_id}:table/opentofu-state-lock"
      },
      {
        # GuardDuty's resource-level IAM support is limited enough (no
        # documented per-detector scoping for Get/List actions the way
        # e.g. Lambda or SNS support) that "*" is the pragmatic choice
        # here, same reasoning satellite-tracker applied to CloudFront and
        # logs:DescribeLogGroups.
        Sid      = "GuardDutyRead"
        Effect   = "Allow"
        Action   = ["guardduty:GetDetector", "guardduty:ListTagsForResource", "guardduty:ListDetectors"]
        Resource = "*"
      },
      {
        Sid      = "CloudTrailRead"
        Effect   = "Allow"
        Action   = ["cloudtrail:GetTrail", "cloudtrail:GetTrailStatus", "cloudtrail:GetEventSelectors", "cloudtrail:ListTags"]
        Resource = local.cloudtrail_arn
      },
      {
        # DescribeTrails, unlike the Get*/ListTags actions above, doesn't
        # support resource-level scoping at all — confirmed live: scoping
        # it to the trail ARN still failed with the identical
        # AccessDenied, same constraint as logs:DescribeLogGroups below.
        Sid      = "CloudTrailDescribe"
        Effect   = "Allow"
        Action   = "cloudtrail:DescribeTrails"
        Resource = "*"
      },
      {
        # Full action list matches satellite-tracker's own already-proven
        # set — the AWS provider's drift-detection refresh probes every one
        # of these sub-configs on a bucket regardless of whether this
        # project's own code ever sets them (Cors/Website/Accelerate/
        # RequestPayment/Logging/Replication/ObjectLock), not just the ones
        # main.tf explicitly configures. Confirmed live: GetBucketCors was
        # missing from an earlier, narrower version of this list and the
        # first real apply failed on it.
        Sid    = "S3BucketRead"
        Effect = "Allow"
        Action = [
          "s3:GetBucketPolicy", "s3:GetBucketPublicAccessBlock", "s3:GetBucketTagging",
          "s3:GetBucketAcl", "s3:GetEncryptionConfiguration", "s3:GetBucketCors",
          "s3:GetBucketWebsite", "s3:GetBucketVersioning", "s3:GetAccelerateConfiguration",
          "s3:GetBucketRequestPayment", "s3:GetBucketLogging", "s3:GetLifecycleConfiguration",
          "s3:GetReplicationConfiguration", "s3:GetBucketObjectLockConfiguration", "s3:ListBucket"
        ]
        Resource = aws_s3_bucket.cloudtrail.arn
      },
      {
        Sid      = "SnsRead"
        Effect   = "Allow"
        Action   = ["sns:GetTopicAttributes", "sns:ListTagsForResource", "sns:ListSubscriptionsByTopic"]
        Resource = aws_sns_topic.alerts.arn
      },
      {
        Sid      = "LambdaRead"
        Effect   = "Allow"
        Action   = ["lambda:GetFunction", "lambda:GetFunctionConfiguration", "lambda:GetFunctionCodeSigningConfig", "lambda:ListVersionsByFunction", "lambda:GetPolicy", "lambda:ListTags"]
        Resource = aws_lambda_function.alert.arn
      },
      {
        Sid      = "IamRoleRead"
        Effect   = "Allow"
        Action   = ["iam:GetRole", "iam:GetRolePolicy", "iam:ListRolePolicies", "iam:ListAttachedRolePolicies", "iam:ListRoleTags"]
        Resource = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/${local.name_prefix}-*"
      },
      {
        Sid      = "OwnPolicyRead"
        Effect   = "Allow"
        Action   = ["iam:GetPolicy", "iam:GetPolicyVersion"]
        Resource = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:policy/${local.name_prefix}-gha-*"
      },
      {
        Sid      = "EventBridgeRead"
        Effect   = "Allow"
        Action   = ["events:DescribeRule", "events:ListTargetsByRule", "events:ListTagsForResource"]
        Resource = "arn:aws:events:us-east-1:${data.aws_caller_identity.current.account_id}:rule/${local.name_prefix}-*"
      },
      {
        # Account-wide list operation, no per-group resource scoping
        # supported — same constraint satellite-tracker hit.
        Sid      = "LogsDescribe"
        Effect   = "Allow"
        Action   = "logs:DescribeLogGroups"
        Resource = "*"
      },
      {
        Sid      = "LogsReadTags"
        Effect   = "Allow"
        Action   = "logs:ListTagsForResource"
        Resource = "arn:aws:logs:us-east-1:${data.aws_caller_identity.current.account_id}:log-group:/aws/lambda/${local.name_prefix}-*"
      },
    ]
  })
}

resource "aws_iam_role_policy_attachment" "gha_plan_read" {
  role       = module.cicd.plan_role_name
  policy_arn = aws_iam_policy.gha_read.arn
}

resource "aws_iam_role_policy_attachment" "gha_apply_read" {
  role       = module.cicd.apply_role_name
  policy_arn = aws_iam_policy.gha_read.arn
}

# -----------------------------------------------
# Permissions — write (apply role only)
# -----------------------------------------------

resource "aws_iam_policy" "gha_write" {
  # checkov:skip=CKV_AWS_355: same GuardDuty resource-level-IAM limitation
  # as gha_read above — CreateDetector in particular has no pre-existing
  # resource to scope to at all (it's the create call), so "*" is the only
  # option for that action regardless of how the rest are scoped.
  # checkov:skip=CKV_AWS_290: same root cause — this flags the GuardDutyWrite
  # statement's unconstrained "*" on Create/Update/Delete/Tag/Untag; every
  # other write statement in this policy is scoped to a specific resource
  # ARN pattern (Lambda, SNS, IAM roles/policies, EventBridge, Logs).
  name = "${local.name_prefix}-gha-write"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "StateObjectWrite"
        Effect   = "Allow"
        Action   = "s3:PutObject"
        Resource = "arn:aws:s3:::351668480009-opentofu-state/detect-respond/pipeline/*"
      },
      {
        Sid      = "GuardDutyWrite"
        Effect   = "Allow"
        Action   = ["guardduty:CreateDetector", "guardduty:UpdateDetector", "guardduty:DeleteDetector", "guardduty:TagResource", "guardduty:UntagResource"]
        Resource = "*" # same resource-level limitation as GuardDutyRead above
      },
      {
        # GuardDuty's first-ever CreateDetector call in an account needs
        # to create its own service-linked role — confirmed live: the
        # first real apply failed with "you do not have the required
        # iam:CreateServiceLinkedRole permission" before this was added.
        Sid      = "GuardDutyServiceLinkedRole"
        Effect   = "Allow"
        Action   = "iam:CreateServiceLinkedRole"
        Resource = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/aws-service-role/guardduty.amazonaws.com/AWSServiceRoleForAmazonGuardDuty"
        Condition = {
          StringLike = { "iam:AWSServiceName" = "guardduty.amazonaws.com" }
        }
      },
      {
        Sid      = "CloudTrailWrite"
        Effect   = "Allow"
        Action   = ["cloudtrail:CreateTrail", "cloudtrail:UpdateTrail", "cloudtrail:DeleteTrail", "cloudtrail:StartLogging", "cloudtrail:StopLogging", "cloudtrail:AddTags", "cloudtrail:RemoveTags"]
        Resource = local.cloudtrail_arn
      },
      {
        Sid    = "S3BucketWrite"
        Effect = "Allow"
        Action = [
          "s3:CreateBucket", "s3:PutBucketPolicy", "s3:PutBucketPublicAccessBlock",
          "s3:PutBucketTagging", "s3:PutEncryptionConfiguration", "s3:PutLifecycleConfiguration"
        ]
        Resource = aws_s3_bucket.cloudtrail.arn
      },
      {
        Sid      = "SnsWrite"
        Effect   = "Allow"
        Action   = ["sns:CreateTopic", "sns:DeleteTopic", "sns:SetTopicAttributes", "sns:TagResource", "sns:UntagResource"]
        Resource = aws_sns_topic.alerts.arn
      },
      {
        Sid    = "LambdaWrite"
        Effect = "Allow"
        Action = [
          "lambda:CreateFunction", "lambda:UpdateFunctionCode", "lambda:UpdateFunctionConfiguration",
          "lambda:DeleteFunction", "lambda:AddPermission", "lambda:RemovePermission", "lambda:TagResource", "lambda:UntagResource"
        ]
        Resource = "arn:aws:lambda:us-east-1:${data.aws_caller_identity.current.account_id}:function:${local.name_prefix}-*"
      },
      {
        Sid    = "IamRoleWrite"
        Effect = "Allow"
        Action = [
          "iam:CreateRole", "iam:DeleteRole", "iam:UpdateRole",
          "iam:PutRolePolicy", "iam:DeleteRolePolicy",
          "iam:AttachRolePolicy", "iam:DetachRolePolicy",
          "iam:TagRole", "iam:UntagRole"
        ]
        Resource = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/${local.name_prefix}-*"
      },
      {
        Sid    = "OwnPolicyWrite"
        Effect = "Allow"
        Action = [
          "iam:CreatePolicy", "iam:CreatePolicyVersion", "iam:DeletePolicyVersion", "iam:ListPolicyVersions",
          "iam:DeletePolicy", "iam:TagPolicy", "iam:UntagPolicy"
        ]
        Resource = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:policy/${local.name_prefix}-gha-*"
      },
      {
        # PassRole is the classic IAM privilege-escalation vector —
        # restrict it to exactly the AWS services that ever assume a
        # detect-respond-* role.
        Sid      = "PassRoleToOwnServices"
        Effect   = "Allow"
        Action   = "iam:PassRole"
        Resource = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/${local.name_prefix}-*"
        Condition = {
          StringEquals = {
            "iam:PassedToService" = ["lambda.amazonaws.com", "events.amazonaws.com"]
          }
        }
      },
      {
        Sid      = "EventBridgeWrite"
        Effect   = "Allow"
        Action   = ["events:PutRule", "events:DeleteRule", "events:PutTargets", "events:RemoveTargets", "events:TagResource", "events:UntagResource"]
        Resource = "arn:aws:events:us-east-1:${data.aws_caller_identity.current.account_id}:rule/${local.name_prefix}-*"
      },
      {
        Sid    = "LogsWrite"
        Effect = "Allow"
        Action = ["logs:CreateLogGroup", "logs:DeleteLogGroup", "logs:PutRetentionPolicy", "logs:TagResource"]
        Resource = [
          "arn:aws:logs:us-east-1:${data.aws_caller_identity.current.account_id}:log-group:/aws/lambda/${local.name_prefix}-*",
          "arn:aws:logs:us-east-1:${data.aws_caller_identity.current.account_id}:log-group:/aws/lambda/${local.name_prefix}-*:*",
        ]
      },
    ]
  })
}

resource "aws_iam_role_policy_attachment" "gha_apply_write" {
  role       = module.cicd.apply_role_name
  policy_arn = aws_iam_policy.gha_write.arn
}
