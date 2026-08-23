# DESIGN.md — aws-detect-respond Architecture Design Document

## Purpose

Detect suspicious or anomalous activity in AWS account `351668480009` and
respond — today via alerting, later via narrowly-scoped automated
remediation for the safest, highest-confidence cases. This document is the
architecture rationale; CLAUDE.md is the persistent context/conventions
file; README.md is the entry point.

## Background

Confirmed live against the account before writing any of this (2026-08-23):

```
$ aws guardduty list-detectors --region us-east-1
{"DetectorIds": []}

$ aws cloudtrail describe-trails --region us-east-1
{"trailList": []}
```

Neither GuardDuty nor a CloudTrail trail exists yet. This project starts
from a genuinely blank slate on both — Phase 1 has to create them, not just
wire alerting on top of something already running.

This account already hosts two sibling projects (`aws-iac-lab`,
`satellite-tracker`), including a GitHub OIDC identity provider registered
by `satellite-tracker`'s Phase 5 and a shared OpenTofu remote-state bucket
(`351668480009-opentofu-state`). Both are reused here rather than
duplicated — see "Why the same AWS account" and "Why reuse the OIDC
provider" below.

## Why the same AWS account (not an isolated one)

Considered account isolation (the "watcher" living outside the blast radius
of what it watches) and decided against it for now:
- Reusing `351668480009` means zero new-account setup — no new
  Organizations member account, no new root-user bootstrap, no new billing
  console to check.
- The watcher-in-a-separate-account pattern matters most when the accounts
  it monitors are ALSO separate/many (a real security team watching dozens
  of workload accounts from a dedicated security-tooling account). For one
  person's single personal account, the isolation buys little today.
- Revisit this if the account ever needs to watch a second AWS account —
  that's the point at which "dedicated security account" starts earning its
  complexity.

## Why reuse the existing GitHub OIDC provider (not create a second one)

`satellite-tracker`'s `opentofu/cicd_oidc.tf` already created an
`aws_iam_openid_connect_provider` for `token.actions.githubusercontent.com`
in this account. AWS IAM OIDC providers are keyed by URL, not by repo — a
second `aws_iam_openid_connect_provider` resource for the same URL, managed
in a different Terraform/OpenTofu state, would either conflict or be
redundant. This project's `cicd_oidc.tf` (Phase 2) should reference the
existing provider via a `data "aws_iam_openid_connect_provider"` lookup (or
a hardcoded ARN, matching whichever pattern reads cleaner once written) and
create only new, repo-scoped IAM roles trusting it — mirroring how
`satellite-tracker` itself scoped its trust policy to its own repo's numeric
GitHub IDs, not a name match.

## Full Topology (Phase 1 target)

```
                    ┌─────────────────┐
                    │   GuardDuty      │  (threat detection —
                    │   detector       │   compromised creds, unusual
                    └────────┬─────────┘   API calls, recon, etc.)
                             │ finding events
                             ▼
                 ┌───────────────────────┐
                 │  EventBridge (default   │
                 │  bus) — rule matching   │
                 │  source: aws.guardduty  │
                 └───────────┬─────────────┘
                             │
        ┌────────────────────┼────────────────────┐
        │                                          │
        │           ┌─────────────────────────┐    │
        │           │  CloudTrail management   │    │
        │           │  events already flow to  │    │
        │           │  the default bus WITHOUT │    │
        │           │  a custom Trail — a Trail│    │
        │           │  is created anyway for a │    │
        │           │  durable S3 audit log,   │    │
        │           │  not because EventBridge  │    │
        │           │  needs it                │    │
        │           └────────────┬─────────────┘    │
        │                        │ rule matching     │
        │                        │ specific event    │
        │                        │ names (root       │
        │                        │ login, CreateAccessKey,
        │                        │ admin policy attach,
        │                        │ StopLogging, etc.)│
        └────────────────────────┴────────────────────┘
                             │
                             ▼
                    ┌─────────────────┐
                    │  Lambda (alert)  │  parse event, classify
                    │                  │  severity, format message
                    └────────┬─────────┘
                             │
                             ▼
                    ┌─────────────────┐
                    │  SNS topic       │ → email (Phase 1)
                    └─────────────────┘    Slack webhook, safe
                                           auto-remediation: later phases
```

## Phase 1 — Foundation & Alerting

**Scope:**
- `aws_guardduty_detector` — enable GuardDuty on the account. Default
  finding-publishing frequency; revisit if alert latency matters more than
  the default 6-hour/15-minute tiers once this is actually running.
- `aws_cloudtrail` trail + a dedicated S3 bucket for log delivery
  (encrypted, lifecycle policy — same posture as `satellite-tracker`'s
  `tle_archive` bucket). Not strictly required for EventBridge delivery of
  most management events (see topology diagram), but a durable, queryable
  audit log is a real part of "detection and response," and it's cheap
  (S3 storage only, no compute).
- EventBridge rule(s): one matching GuardDuty findings
  (`source: ["aws.guardduty"]`), one matching a deliberately small starting
  set of high-value CloudTrail event names via the default bus — root
  console login, `CreateAccessKey`, `AttachUserPolicy`/`PutUserPolicy` with
  an admin-level policy, `StopLogging`/`DeleteTrail`/`DeleteDetector` (someone
  disabling the very logging/detection this project depends on). Expand this
  list deliberately over time, not speculatively up front — an
  overly-broad event-name list at launch just becomes alert fatigue before
  there's any real signal about what's actually worth watching on this
  account.
- One Lambda: parses whichever event shape it received (GuardDuty finding
  JSON vs. a raw CloudTrail event have different shapes — the Lambda needs
  to branch on that), formats a human-readable message, publishes to an SNS
  topic.
- SNS topic → email subscription, added out-of-band (same pattern as
  `satellite-tracker`'s `alerts.tf`: never store the notification address in
  code or state).
- No auto-remediation. Every finding/event in Phase 1 becomes an alert, full
  stop — the goal here is establishing signal and reducing false-alarm rate
  by watching real output for a while, not reacting automatically to
  anything yet.

**Deliberately open, to decide once Phase 1 is actually being built rather
than guessed at now:**
- Exact starting list of watched CloudTrail event names (the four above are
  a reasonable seed, not a final list)
- GuardDuty finding-severity threshold worth alerting on (all findings vs.
  medium+/high+ only) — likely start broad and narrow down once real
  findings start arriving and false-positive rate is visible
- Whether one Lambda handling both GuardDuty and CloudTrail-sourced events
  is the right shape long-term, or whether it's cleaner as two Lambdas
  behind two EventBridge rules once the parsing logic for each grows

## Phase 2 — CI/CD

GitHub Actions + OIDC, Checkov gate — matching `satellite-tracker`'s Phase 5
almost exactly, with the one deliberate difference already called out above
(reuse the existing OIDC provider, don't recreate it).

## Phase 3 — Dashboarding

A CloudWatch dashboard summarizing findings over time — counts by severity,
by finding type, maybe a simple trend view. Needs Phase 1 actually running
first; there is nothing to visualize before real findings exist.

## Phase 4 — Safe Auto-Remediation

Deliberately last, and deliberately not designed in detail yet. The
temptation with a "detection and response" project is to reach for
automated remediation immediately, since it's the more impressive-sounding
half of the name — resisted here on purpose. A wrong automated action taken
against a false positive (revoking a legitimate access key, deleting a
security group rule someone actually needed) is a worse outcome than a
human reading an extra email. Once Phase 1 has been running long enough to
see what a real, common, safe-to-automate finding actually looks like on
this specific account, re-scope this phase against that real data instead
of a hypothetical.

## Roadmap / Ideas Not Yet Scoped

- Slack webhook alerting alongside (or instead of) email
- Cost Anomaly Detection integration (ties into Derek's separately-noted
  "billing alerting/dashboarding" backlog item — worth checking for overlap
  before building either in isolation)
- A home-network security data source (Pi-hole/router logs) feeding this
  same pipeline as an additional EventBridge source, distinct from the
  AWS-account-activity focus above — a separately-discussed idea, not yet
  merged into this design
