locals {
  name_prefix = "detect-respond"

  common_tags = {
    Project   = "aws-detect-respond"
    ManagedBy = "opentofu"
    Repo      = "MacGotHub/aws-detect-respond"
  }

  # Phase 1's deliberately small starting set of CloudTrail/sign-in event
  # names worth alerting on beyond whatever GuardDuty itself flags. Expand
  # this list once real signal (or noise) from this account shows what's
  # actually worth watching — see DESIGN.md. Root/IAM-user console login,
  # new access keys, admin-policy attachment, and disabling this pipeline's
  # own logging/detection are the seed set.
  watched_event_names = [
    "ConsoleLogin",
    "CreateAccessKey",
    "AttachUserPolicy",
    "PutUserPolicy",
    "StopLogging",
    "DeleteTrail",
    "DeleteDetector",
  ]

  # Predictable trail ARN, constructed rather than referenced from
  # aws_cloudtrail.this.arn — the S3 bucket policy's aws:SourceArn
  # condition needs this value, but AWS validates that policy at
  # trail-creation time, before the trail resource (and its computed .arn)
  # exists. Building the ARN from known values (region, account ID, and a
  # name this project chooses) breaks the circular dependency; see
  # main.tf's depends_on for how the ordering is still enforced.
  cloudtrail_name = "${local.name_prefix}-trail"
  cloudtrail_arn  = "arn:aws:cloudtrail:us-east-1:${data.aws_caller_identity.current.account_id}:trail/${local.cloudtrail_name}"

  # Phase 2 — CI/CD, pulled forward from its original later slot because
  # local tofu is blocked in this environment (endpoint security
  # "Application Control policy") and this repo had no other apply path
  # yet. satellite-tracker's Phase 5 already registered a GitHub OIDC
  # provider for token.actions.githubusercontent.com in this account — IAM
  # OIDC providers are keyed by URL, not by repo, so this hardcodes that
  # provider's (fully predictable) ARN rather than creating a second
  # provider resource or looking it up via a data source. A data source
  # would also hit the exact timing problem satellite-tracker's own
  # cloudfront_managed_security_headers_policy_id local was designed to
  # avoid: a first-ever apply's data-source reads happen before that same
  # apply's IAM policy grants take effect.
  github_oidc_provider_arn = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:oidc-provider/token.actions.githubusercontent.com"

  # GitHub's OIDC `sub` claim uses the immutable numeric owner/repo IDs,
  # not the plain name (confirmed the hard way in satellite-tracker's own
  # Phase 5) — fetched directly via `gh api user` / `gh api repos/...`
  # rather than guessed: owner 188585672 (MacGotHub, same account as
  # satellite-tracker), repo 1344321220 (aws-detect-respond).
  github_oidc_sub_prefix = "repo:MacGotHub@188585672/aws-detect-respond@1344321220"
}
