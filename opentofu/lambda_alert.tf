# -----------------------------------------------
# Phase 1 — alert-processing Lambda
#
# Triggered by two independent EventBridge rules (see eventbridge.tf):
# GuardDuty findings, and a small watchlist of high-value CloudTrail/
# sign-in events. One function, not two — the branching logic (which event
# shape it received) lives in the handler itself, not in infra duplication.
# -----------------------------------------------

data "archive_file" "alert" {
  type        = "zip"
  source_file = "${path.module}/../src/alert/handler.py"
  output_path = "${path.module}/build/alert.zip"
}

resource "aws_iam_role" "alert" {
  name = "${local.name_prefix}-alert"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy_attachment" "alert_logs" {
  role       = aws_iam_role.alert.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

# Publish to the alert topic only — this Lambda never reads from anywhere,
# it just formats whatever EventBridge handed it and forwards to SNS.
resource "aws_iam_role_policy" "alert" {
  name = "${local.name_prefix}-alert-access"
  role = aws_iam_role.alert.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = "sns:Publish"
      Resource = aws_sns_topic.alerts.arn
    }]
  })
}

resource "aws_lambda_function" "alert" {
  # checkov:skip=CKV_AWS_272: code-signing (AWS Signer) — supply-chain
  # control for untrusted contributors; N/A, solo repo. Same accepted
  # posture as satellite-tracker's .checkov.yaml.
  # checkov:skip=CKV_AWS_116: DLQ for async invocations — EventBridge
  # itself retries failed Lambda invocations before this needs one;
  # revisit if silent alert-drop becomes a real observed problem.
  # checkov:skip=CKV_AWS_115: reserved concurrency — a cost/throttling
  # knob, not a vulnerability, at this event volume.
  # checkov:skip=CKV_AWS_117: Lambda-in-VPC — this function only calls the
  # SNS API; VPC adds a NAT gateway bill for zero benefit.
  # checkov:skip=CKV_AWS_50: X-Ray tracing — observability nice-to-have,
  # not a security gap.
  # checkov:skip=CKV_AWS_173: env var CMK — no secrets in this function's
  # env vars (just an SNS topic ARN); default at-rest encryption applies.
  function_name    = "${local.name_prefix}-alert"
  role             = aws_iam_role.alert.arn
  handler          = "handler.handler"
  runtime          = "python3.12"
  timeout          = 30
  memory_size      = 128
  filename         = data.archive_file.alert.output_path
  source_code_hash = data.archive_file.alert.output_base64sha256

  environment {
    variables = {
      TOPIC_ARN = aws_sns_topic.alerts.arn
    }
  }

  tags = {
    Name = "${local.name_prefix}-alert"
  }
}

resource "aws_cloudwatch_log_group" "alert" {
  # checkov:skip=CKV_AWS_158: CloudWatch Logs CMK — AWS-managed default
  # encryption already applies; same cost-conscious call as elsewhere.
  # checkov:skip=CKV_AWS_338: 14-day retention is a deliberate cost choice,
  # not a compliance gap — no mandate requires longer for this project.
  name              = "/aws/lambda/${aws_lambda_function.alert.function_name}"
  retention_in_days = 14
}
