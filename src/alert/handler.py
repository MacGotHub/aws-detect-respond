"""Alert Lambda — the response half of Phase 1's detection pipeline.

Triggered by two independent EventBridge rules (see opentofu/eventbridge.tf):
GuardDuty findings, and a small watchlist of high-value CloudTrail/sign-in
events. The two event shapes are different enough (GuardDuty's own finding
detail vs. a raw CloudTrail/sign-in detail) that this branches on
`event["detail-type"]` and formats each differently, then publishes one
human-readable message to SNS either way. No auto-remediation here by
design — see DESIGN.md's Phase 4 for why that's deliberately deferred.
"""

import json
import os

import boto3

_sns = None


def _sns_client():
    global _sns
    if _sns is None:
        _sns = boto3.client("sns")
    return _sns


def _format_guardduty(detail: dict) -> str:
    return (
        f"[GuardDuty] {detail.get('title', 'Untitled finding')}\n"
        f"Type: {detail.get('type', 'unknown')}\n"
        f"Severity: {detail.get('severity', 'unknown')}\n"
        f"Account: {detail.get('accountId', 'unknown')}  "
        f"Region: {detail.get('region', 'unknown')}"
    )


def _format_watched_event(detail: dict) -> str:
    user_identity = detail.get("userIdentity", {})
    actor = user_identity.get("arn") or user_identity.get("type", "unknown actor")
    return (
        f"[Watched event] {detail.get('eventName', 'unknown event')} "
        f"({detail.get('eventSource', 'unknown source')})\n"
        f"By: {actor}\n"
        f"Source IP: {detail.get('sourceIPAddress', 'unknown')}  "
        f"Region: {detail.get('awsRegion', 'unknown')}"
    )


def handler(event, context):
    detail_type = event.get("detail-type", "")
    detail = event.get("detail", {})

    if detail_type == "GuardDuty Finding":
        message = _format_guardduty(detail)
        subject = "GuardDuty finding"
    else:
        message = _format_watched_event(detail)
        # SNS subjects are capped at 100 characters.
        subject = f"Watched event: {detail.get('eventName', 'unknown')}"[:100]

    _sns_client().publish(
        TopicArn=os.environ["TOPIC_ARN"],
        Subject=subject,
        Message=message,
    )

    return {"statusCode": 200, "body": json.dumps({"published": True})}
