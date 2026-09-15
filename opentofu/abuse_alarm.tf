# -----------------------------------------------
# abuse-alarm module (app.terraform.io/macgothub/abuse-alarm/aws) — this
# repo's first CloudWatch alarm of any kind. Cost profile here is
# naturally low (event-driven only, no always-on compute — see CLAUDE.md
# "What NOT to Do"), so this isn't a cost guardrail like the sibling
# repos' DynamoDB-write alarms. It's a feedback-loop / flood sanity check
# on the one thing that actually runs here: a real security incident (or
# a misconfigured EventBridge rule matching too broadly, or a retry
# storm) would show up as a spike in detect-respond-alert's invocation
# count before it shows up anywhere else.
#
# Threshold set from a real baseline, not a guess: detect-respond-alert's
# Invocations over the last 14 days shows 9 total invocations, never more
# than 1 in any given hour. 10 in a single 5-minute window is already a
# large, real jump from that baseline in either direction — a genuine
# flood of findings worth knowing about immediately, or a bug.
#
# Own dedicated, unencrypted topic (create_sns_topic defaults true) rather
# than sharing aws_sns_topic.alerts: that topic is alias/aws/sns-encrypted
# (main.tf) and CloudWatch alarms can't publish through that key — the
# same real bug orbital-watch hit and fixed in its own PR #42. Flipping
# the existing findings topic wasn't worth it just for this.
# -----------------------------------------------

module "abuse_alarm" {
  # checkov:skip=CKV_TF_1: private registry source pinned by the `version`
  # constraint below — same reasoning as module.cicd above.
  source  = "app.terraform.io/macgothub/abuse-alarm/aws"
  version = "~> 0.4.0"

  name = local.name_prefix

  alarms = {
    alert-lambda-invocation-flood = {
      namespace   = "AWS/Lambda"
      metric_name = "Invocations"
      dimensions  = { FunctionName = aws_lambda_function.alert.function_name }
      threshold   = 10
      description = "detect-respond-alert invoked far more than its ~9-per-14-days baseline -- either a real flood of findings or an EventBridge/retry loop."
    }
  }

  # No tags argument: provider default_tags (providers.tf) already applies
  # local.common_tags to every resource this module creates.

  depends_on = [time_sleep.wait_for_abuse_alarm_iam]
}

output "abuse_alarm_topic_arn" {
  value       = module.abuse_alarm.sns_topic_arn
  description = <<-EOT
    Cost/volume-spike alarm topic. Subscribe a real endpoint:
      aws sns subscribe --topic-arn <this> --protocol email \
        --notification-endpoint you@example.com
    then force one alarm to ALARM and confirm the email lands.
  EOT
}
