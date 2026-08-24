# -----------------------------------------------
# Phase 2 — GitHub Actions CI/CD via OIDC (pulled forward from its
# original slot — see locals.tf's github_oidc_provider_arn comment for why)
#
# No static AWS keys in GitHub secrets. GitHub Actions presents a
# short-lived signed OIDC token; AWS trades it for temporary STS
# credentials scoped to one of the two roles below. Two roles, not one, so
# a PR from any branch can only ever get read-only access — write access
# requires the token to additionally prove `ref = refs/heads/main`, which
# only a push to main (post-merge) can produce. Same shape as
# satellite-tracker's Phase 5, single read/write policy pair rather than
# that project's later bootstrap-policy split — this is a first-ever
# apply with no already-live permissions to avoid regressing, so there's
# no equivalent problem to design around yet.
# -----------------------------------------------

resource "aws_iam_role" "gha_plan" {
  # checkov:skip=CKV_AWS_393: false positive, traced through Checkov's own
  # check source (GithubActionsOIDCTrustPolicyOnRole.py) before accepting
  # this — its gh_repo_regex expects a plain "owner/repo" shape and doesn't
  # recognize GitHub's newer immutable-numeric-ID sub claim format
  # ("owner@ownerid/repo@repoid") this trust policy uses. That format is
  # what GitHub actually sends for this repo (confirmed via `gh api`, same
  # as satellite-tracker's own Phase 5 discovery) and is strictly tighter
  # than a plain name match, not looser — it survives a repo rename and
  # can't be produced by a differently-named repo. The regex gap is
  # Checkov's, not a real weakening of this policy.
  name = "${local.name_prefix}-gha-plan"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Federated = local.github_oidc_provider_arn }
      Action    = "sts:AssumeRoleWithWebIdentity"
      Condition = {
        StringEquals = {
          "token.actions.githubusercontent.com:aud" = "sts.amazonaws.com"
        }
        StringLike = {
          "token.actions.githubusercontent.com:sub" = "${local.github_oidc_sub_prefix}:*"
        }
      }
    }]
  })
}

# Pinned to exactly one ref (no wildcard in the ref segment) — a wildcard
# here would let a PR from a fork assume a role that can change live
# infrastructure.
resource "aws_iam_role" "gha_apply" {
  # checkov:skip=CKV_AWS_393: same Checkov regex gap as gha_plan above —
  # see that resource's comment.
  name = "${local.name_prefix}-gha-apply"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Federated = local.github_oidc_provider_arn }
      Action    = "sts:AssumeRoleWithWebIdentity"
      Condition = {
        StringEquals = {
          "token.actions.githubusercontent.com:aud" = "sts.amazonaws.com"
          "token.actions.githubusercontent.com:sub" = "${local.github_oidc_sub_prefix}:ref:refs/heads/main"
        }
      }
    }]
  })
}

# -----------------------------------------------
# Permissions — read (both roles: plan needs it to compute a diff, apply
# needs it too since apply always plans first)
# -----------------------------------------------

resource "aws_iam_policy" "gha_read" {
  # checkov:skip=CKV_AWS_355: the GuardDutyRead statement below is the only
  # Resource "*" in this policy on a "restrictable" action — GuardDuty's
  # Get/List actions have no documented per-detector resource-level IAM
  # support (unlike Lambda/SNS/EventBridge elsewhere in this policy, which
  # all are scoped to a specific ARN), so "*" is the pragmatic ceiling
  # here, not a shortcut taken instead of scoping.
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
  role       = aws_iam_role.gha_plan.name
  policy_arn = aws_iam_policy.gha_read.arn
}

resource "aws_iam_role_policy_attachment" "gha_apply_read" {
  role       = aws_iam_role.gha_apply.name
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
        Sid    = "EventBridgeWrite"
        Effect = "Allow"
        Action = ["events:PutRule", "events:DeleteRule", "events:PutTargets", "events:RemoveTargets", "events:TagResource", "events:UntagResource"]
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
  role       = aws_iam_role.gha_apply.name
  policy_arn = aws_iam_policy.gha_write.arn
}
