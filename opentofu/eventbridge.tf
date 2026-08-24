# -----------------------------------------------
# Phase 1 — EventBridge rules routing findings/events to the alert Lambda
# -----------------------------------------------

# GuardDuty findings land on the default event bus automatically once a
# detector exists — no CloudTrail/Trail involvement at all for this path.
resource "aws_cloudwatch_event_rule" "guardduty_findings" {
  name = "${local.name_prefix}-guardduty-findings"

  event_pattern = jsonencode({
    source      = ["aws.guardduty"]
    detail-type = ["GuardDuty Finding"]
  })
}

# Watched CloudTrail/sign-in events. Two source/detail-type pairs, not one:
# console sign-in is delivered as source "aws.signin", detail-type
# "AWS Console Sign In via CloudTrail"; every other watched event name here
# is a general API call, delivered as source "aws.cloudtrail", detail-type
# "AWS API Call via CloudTrail" — confirmed against AWS's own EventBridge
# reference docs before writing this, not assumed to share one shape.
# Requires aws_cloudtrail.this (main.tf) to actually be logging — see that
# resource's comment.
resource "aws_cloudwatch_event_rule" "watched_events" {
  name = "${local.name_prefix}-watched-events"

  event_pattern = jsonencode({
    source      = ["aws.cloudtrail", "aws.signin"]
    detail-type = ["AWS API Call via CloudTrail", "AWS Console Sign In via CloudTrail"]
    detail = {
      eventName = local.watched_event_names
    }
  })
}

resource "aws_cloudwatch_event_target" "guardduty_to_alert" {
  rule = aws_cloudwatch_event_rule.guardduty_findings.name
  arn  = aws_lambda_function.alert.arn
}

resource "aws_cloudwatch_event_target" "watched_events_to_alert" {
  rule = aws_cloudwatch_event_rule.watched_events.name
  arn  = aws_lambda_function.alert.arn
}

resource "aws_lambda_permission" "guardduty_invoke" {
  statement_id  = "AllowGuardDutyEventBridge"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.alert.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.guardduty_findings.arn
}

resource "aws_lambda_permission" "watched_events_invoke" {
  statement_id  = "AllowWatchedEventsEventBridge"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.alert.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.watched_events.arn
}
