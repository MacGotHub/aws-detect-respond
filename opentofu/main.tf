# -----------------------------------------------
# Phase 1 — GuardDuty detector, CloudTrail trail, alert SNS topic
# -----------------------------------------------

resource "aws_guardduty_detector" "this" {
  enable = true

  tags = {
    Name = "${local.name_prefix}-guardduty"
  }
}

# -----------------------------------------------
# S3 — CloudTrail log delivery
# -----------------------------------------------

resource "aws_s3_bucket" "cloudtrail" {
  # checkov:skip=CKV2_AWS_61: security-audit log bucket — nothing here needs
  # a lifecycle transition to a cheaper storage class at this volume; the
  # expiration rule below already bounds growth.
  # checkov:skip=CKV_AWS_144: cross-region replication — no DR requirement
  # for a personal account's audit trail.
  # checkov:skip=CKV_AWS_18: access logging needs a second dedicated
  # log-target bucket — disproportionate for this project, same call
  # satellite-tracker made for its own buckets.
  # checkov:skip=CKV_AWS_21: versioning — CloudTrail never overwrites an
  # existing log object, so there's nothing to version-protect against.
  bucket = "${local.name_prefix}-cloudtrail-${data.aws_caller_identity.current.account_id}"

  tags = {
    Name = "${local.name_prefix}-cloudtrail"
  }
}

resource "aws_s3_bucket_public_access_block" "cloudtrail" {
  bucket = aws_s3_bucket.cloudtrail.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# AWS-managed key (aws/s3), not a customer CMK — same cost-conscious choice
# satellite-tracker made for its own buckets (zero monthly key cost, same
# "encrypted at rest" protection Checkov's KMS check wants).
resource "aws_s3_bucket_server_side_encryption_configuration" "cloudtrail" {
  bucket = aws_s3_bucket.cloudtrail.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "aws:kms"
    }
  }
}

# A security-audit log growing forever with no expiry defeats a chunk of
# its own point (unbounded storage, harder to reason about what's even in
# it) — 1 year is deliberately longer than satellite-tracker's 90-day
# archive, since this bucket's whole purpose is being able to look back at
# what happened, not just recent debugging.
resource "aws_s3_bucket_lifecycle_configuration" "cloudtrail" {
  bucket = aws_s3_bucket.cloudtrail.id

  rule {
    id     = "expire-after-1-year"
    status = "Enabled"

    filter {}

    expiration {
      days = 365
    }
  }
}

# aws:SourceArn condition per AWS's current documented best practice (not
# the older account-ID-only version) — scopes delivery to exactly this
# trail, not "any CloudTrail trail in this account." local.cloudtrail_arn
# is a hand-built string, not a resource attribute — see locals.tf for why.
resource "aws_s3_bucket_policy" "cloudtrail" {
  bucket = aws_s3_bucket.cloudtrail.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AWSCloudTrailAclCheck"
        Effect    = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action    = "s3:GetBucketAcl"
        Resource  = aws_s3_bucket.cloudtrail.arn
        Condition = {
          StringEquals = { "aws:SourceArn" = local.cloudtrail_arn }
        }
      },
      {
        Sid       = "AWSCloudTrailWrite"
        Effect    = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action    = "s3:PutObject"
        Resource  = "${aws_s3_bucket.cloudtrail.arn}/AWSLogs/${data.aws_caller_identity.current.account_id}/*"
        Condition = {
          StringEquals = {
            "s3:x-amz-acl"  = "bucket-owner-full-control"
            "aws:SourceArn" = local.cloudtrail_arn
          }
        }
      }
    ]
  })
}

# Load-bearing for the CloudTrail-sourced EventBridge rule (see
# eventbridge.tf), not just an audit log on the side — verified that
# CloudTrail events only reach EventBridge's default bus when an active
# Trail is logging them (unlike GuardDuty findings, which land there the
# moment a detector exists, no Trail required).
resource "aws_cloudtrail" "this" {
  # checkov:skip=CKV_AWS_252: SNS notification on log delivery — no
  # consumer subscribes to it; this project's own detection pipeline reads
  # CloudTrail events via EventBridge, not via a CloudTrail-SNS topic.
  # checkov:skip=CKV_AWS_35: CloudTrail's own logs encrypted with a
  # customer-managed CMK — AWS-managed S3 encryption (above) already
  # applies; same cost-conscious call as everywhere else in this project.
  name                          = local.cloudtrail_name
  s3_bucket_name                = aws_s3_bucket.cloudtrail.id
  include_global_service_events = true
  is_multi_region_trail         = true
  enable_log_file_validation    = true

  # Bucket policy must exist (with the correct aws:SourceArn) before
  # CloudTrail will accept this bucket — AWS validates it at trail-creation
  # time, but OpenTofu has no automatic edge for that since the policy's
  # condition references a hand-built ARN string, not a resource attribute.
  depends_on = [aws_s3_bucket_policy.cloudtrail]

  tags = {
    Name = "${local.name_prefix}-trail"
  }
}

# -----------------------------------------------
# SNS — alert delivery. Email subscription added out-of-band (same pattern
# as satellite-tracker's alerts.tf) so the address never lands in the repo
# or the state file:
#   aws sns subscribe --topic-arn <alerts_topic_arn output> \
#     --protocol email --notification-endpoint <address>
# -----------------------------------------------

resource "aws_sns_topic" "alerts" {
  name = "${local.name_prefix}-alerts"

  # AWS-managed key (alias/aws/sns), not a customer CMK.
  kms_master_key_id = "alias/aws/sns"

  tags = {
    Name = "${local.name_prefix}-alerts"
  }
}
