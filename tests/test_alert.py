import json

import boto3
import pytest
from moto import mock_aws

from src.alert.handler import handler

GUARDDUTY_EVENT = {
    "detail-type": "GuardDuty Finding",
    "detail": {
        "title": "Unusual API call pattern",
        "type": "Recon:IAMUser/TorIPCaller",
        "severity": 8.5,
        "accountId": "351668480009",
        "region": "us-east-1",
    },
}

WATCHED_EVENT = {
    "detail-type": "AWS API Call via CloudTrail",
    "detail": {
        "eventName": "CreateAccessKey",
        "eventSource": "iam.amazonaws.com",
        "userIdentity": {"arn": "arn:aws:iam::351668480009:user/someone"},
        "sourceIPAddress": "203.0.113.5",
        "awsRegion": "us-east-1",
    },
}

CONSOLE_LOGIN_EVENT = {
    "detail-type": "AWS Console Sign In via CloudTrail",
    "detail": {
        "eventName": "ConsoleLogin",
        "eventSource": "signin.amazonaws.com",
        "userIdentity": {"type": "Root"},
        "sourceIPAddress": "203.0.113.9",
        "awsRegion": "us-east-1",
    },
}


@pytest.fixture(autouse=True)
def reset_sns_client(monkeypatch):
    # Module-level client cache — force a fresh one per test against
    # whichever moto backend that test set up.
    import src.alert.handler as alert_handler

    monkeypatch.setattr(alert_handler, "_sns", None)


def setup_aws(monkeypatch):
    """Create the moto topic and wire an SQS queue to it so tests can read
    exactly what SNS delivered — same pattern satellite-tracker's own
    alerts tests use."""
    sns = boto3.client("sns", region_name="us-east-1")
    topic_arn = sns.create_topic(Name="test-alerts")["TopicArn"]
    monkeypatch.setenv("TOPIC_ARN", topic_arn)

    sqs = boto3.client("sqs", region_name="us-east-1")
    queue_url = sqs.create_queue(QueueName="test-alert-sink")["QueueUrl"]
    queue_arn = sqs.get_queue_attributes(
        QueueUrl=queue_url, AttributeNames=["QueueArn"]
    )["Attributes"]["QueueArn"]
    sns.subscribe(TopicArn=topic_arn, Protocol="sqs", Endpoint=queue_arn)
    return queue_url


def delivered_messages(queue_url) -> list[dict]:
    sqs = boto3.client("sqs", region_name="us-east-1")
    received = sqs.receive_message(
        QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=0
    ).get("Messages", [])
    return [json.loads(m["Body"]) for m in received]


@mock_aws
def test_guardduty_finding_publishes_formatted_message(monkeypatch):
    queue_url = setup_aws(monkeypatch)

    response = handler(GUARDDUTY_EVENT, None)

    assert response["statusCode"] == 200
    delivered = delivered_messages(queue_url)
    assert len(delivered) == 1
    assert delivered[0]["Subject"] == "GuardDuty finding"
    assert "Unusual API call pattern" in delivered[0]["Message"]
    assert "Recon:IAMUser/TorIPCaller" in delivered[0]["Message"]
    assert "8.5" in delivered[0]["Message"]


@mock_aws
def test_watched_event_publishes_formatted_message(monkeypatch):
    queue_url = setup_aws(monkeypatch)

    response = handler(WATCHED_EVENT, None)

    assert response["statusCode"] == 200
    delivered = delivered_messages(queue_url)
    assert delivered[0]["Subject"] == "Watched event: CreateAccessKey"
    assert "CreateAccessKey" in delivered[0]["Message"]
    assert "arn:aws:iam::351668480009:user/someone" in delivered[0]["Message"]
    assert "203.0.113.5" in delivered[0]["Message"]


@mock_aws
def test_console_login_falls_back_to_userIdentity_type_when_no_arn(monkeypatch):
    # Root logins have userIdentity.type == "Root" and no "arn" key at all —
    # the handler must not KeyError on that shape.
    queue_url = setup_aws(monkeypatch)

    response = handler(CONSOLE_LOGIN_EVENT, None)

    assert response["statusCode"] == 200
    delivered = delivered_messages(queue_url)
    assert "ConsoleLogin" in delivered[0]["Message"]
    assert "Root" in delivered[0]["Message"]


@mock_aws
def test_long_event_name_truncates_subject_to_100_chars(monkeypatch):
    queue_url = setup_aws(monkeypatch)
    event = {
        "detail-type": "AWS API Call via CloudTrail",
        "detail": {"eventName": "X" * 200, "eventSource": "iam.amazonaws.com"},
    }

    handler(event, None)

    delivered = delivered_messages(queue_url)
    assert len(delivered[0]["Subject"]) <= 100
