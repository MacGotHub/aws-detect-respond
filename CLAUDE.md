# CLAUDE.md — aws-detect-respond Project Context

This file provides Claude Code with persistent context about this project,
its owner, goals, and conventions. Read this before making any changes.

---

## Owner

- **Name:** Derek McWilliams
- **Role:** Network Security Engineer (working toward DevSecOps)
- **GitHub:** MacGotHub

---

## Project Purpose

A cloud security detection & automated response pipeline for AWS account
`351668480009`, built for two reasons:
1. **Actually useful** — real-time visibility into suspicious account
   activity (compromised credentials, unusual API behavior, root-account
   use, dangerous IAM/network changes) with alerting today and automated
   remediation for the safest, highest-confidence cases later.
2. **DevSecOps portfolio piece** — this is the one project genre neither
   sibling project covers: `aws-iac-lab` is general AWS/network-security IaC
   patterns, `satellite-tracker` is a serverless app + CI/CD showcase.
   Detection engineering and automated response plays directly to Derek's
   Network Security Engineer background in a way a hiring manager for a
   DevSecOps role will specifically recognize.

**Known tradeoff, already discussed with Derek:** this project is less
demo-able than `satellite-tracker` — no fun UI, just findings, alerts, and a
dashboard. It's meant to read well on a resume and in an interview, not as a
casual link to show someone.

---

## Tooling

| Tool | Purpose |
|---|---|
| OpenTofu | Infrastructure provisioning (all AWS resources) |
| Python 3.x | Lambda function(s) (finding/event processing, alerting, later remediation) |
| GitHub Actions | CI/CD — `tofu plan`/`tofu apply` via OIDC role assumption |
| AWS CLI | Ad-hoc verification and troubleshooting |
| Git / GitHub | Version control (repo: MacGotHub/aws-detect-respond, created 2026-08-23) |

**OpenTofu version:** match whatever `satellite-tracker`/`aws-iac-lab` are
pinned to at the time — check their `opentofu/providers.tf`/workflow files
rather than assuming, since these get bumped independently per project.
**AWS Region:** us-east-1 (primary), matching the sibling projects.
**AWS Account ID:** 351668480009 — same account as `aws-iac-lab` and
`satellite-tracker`, chosen deliberately (see DESIGN.md) rather than a new
isolated account.

---

## Repo Structure

```
aws-detect-respond/
├── README.md                  # Short pitch + pointers here ✓
├── CLAUDE.md                  # This file ✓
├── DESIGN.md                  # Architecture rationale ✓
├── .checkov.yaml              # Repo-wide Checkov config — no skips yet, see the file itself ✓
├── .gitattributes             # * text=auto eol=lf, same as satellite-tracker ✓
├── .gitignore ✓
├── pytest.ini ✓
├── opentofu/                  # All IaC ✓
│   ├── backend.tf             # Remote state — shared 351668480009-opentofu-state
│   │                          #   bucket, key detect-respond/pipeline/terraform.tfstate ✓
│   ├── providers.tf ✓
│   ├── locals.tf              # name_prefix, common_tags, watched event names,
│   │                          #   the hand-built cloudtrail/OIDC-provider ARN strings ✓
│   ├── main.tf                # GuardDuty detector, CloudTrail bucket+policy+trail, SNS topic ✓
│   ├── lambda_alert.tf        # Alert-processing Lambda + IAM ✓
│   ├── eventbridge.tf         # Rules + targets + Lambda permissions ✓
│   ├── cicd_oidc.tf           # Phase 2, pulled forward — new repo-scoped IAM roles
│   │                          #   ONLY; the GitHub OIDC provider itself already
│   │                          #   exists in this account (satellite-tracker's Phase
│   │                          #   5) and is referenced as a hardcoded ARN string,
│   │                          #   not a data source or a second provider resource ✓
│   └── outputs.tf ✓
├── src/
│   └── alert/handler.py       # Parses GuardDuty findings / CloudTrail events, publishes to SNS ✓
├── tests/
│   └── test_alert.py          # pytest + moto (SNS→SQS subscription, same pattern
│                               #   satellite-tracker's alerts tests use) ✓
└── .github/
    └── workflows/
        ├── plan.yml ✓
        └── apply.yml ✓
```

All of Phase 1 and Phase 2 exist as code as of 2026-08-23 but have **not
been applied/verified yet** — see Current Status below for exactly why and
what's still outstanding before trusting any of this is actually live.

---

## Architecture Overview

```
GuardDuty (threat detection: compromised creds, unusual API calls, etc.)
    ↓ (finding events land on the default EventBridge bus automatically —
    ↓  no CloudTrail/Trail involvement needed for this path)
CloudTrail trail (VERIFIED, not assumed: CloudTrail-sourced events only
    reach EventBridge when an active Trail is logging them — this Trail is
    load-bearing for the path below, not just a nice-to-have audit log)
    ↓
EventBridge rules (GuardDuty findings + a watchlist of event names:
    ConsoleLogin, CreateAccessKey, AttachUserPolicy/PutUserPolicy,
    StopLogging/DeleteTrail/DeleteDetector — two source/detail-type pairs,
    since console sign-in is shaped differently from a general API call)
    ↓
Lambda (parse whichever shape it received, format human-readable message)
    ↓
SNS topic → email (Phase 1); Slack webhook and/or safe auto-remediation
    actions are later phases, not Phase 1
```

### Phases

| Phase | Scope | Status |
|---|---|---|
| 1 — Foundation & alerting | GuardDuty detector, CloudTrail trail, EventBridge rules on GuardDuty findings + a watched-event-name list, one Lambda → SNS (email). No auto-remediation. | Code written 2026-08-23; not yet applied — see Current Status |
| 2 — CI/CD | GitHub Actions + OIDC (reusing the existing provider via hardcoded ARN, new repo-scoped roles), Checkov gate. | Pulled forward ahead of Phase 1 being live — see Current Status for why; code written 2026-08-23, not yet run |
| 3 — Dashboarding | CloudWatch dashboard summarizing findings over time (counts by severity/type). | Not started — needs Phase 1 actually producing findings first |
| 4 — Safe auto-remediation | Only for extremely high-confidence, low-blast-radius actions — deliberately conservative; alerting-only is the safe default until specific remediation actions are individually reasoned through. | Not started, not designed in detail on purpose |

---

## Coding Conventions

Same conventions as `satellite-tracker` (same owner, same bar):

1. `for_each` over repeated resource blocks, driven by `locals` — never
   `count` for keyed collections.
2. `locals.tf` is the single source of truth for naming prefixes, common
   tags, and any watchlists/thresholds.
3. Common tags on every resource via `merge(local.common_tags, ...)`.
4. Least-privilege IAM per Lambda — scoped to exactly the resources it
   touches.
5. Secrets never in git — if a Slack webhook URL or similar is ever needed,
   it's SSM SecureString or a GitHub secret, never a literal in code or state.
6. Comments explain the why, not just the what.
7. Checkov gate on every PR and apply, same as `satellite-tracker`'s Phase 5
   — accepted-risk findings go in `.checkov.yaml` with documented reasoning,
   not silently ignored.

---

## What NOT to Do

- Do not auto-remediate anything beyond the narrowest, most obviously-safe
  actions without explicit sign-off — a detection/response system that takes
  the wrong automated action on a false positive is worse than one that just
  alerts a human. Default to alert-only.
- Do not create a second GitHub OIDC identity provider in this account —
  `satellite-tracker`'s Phase 5 already registered one for
  `token.actions.githubusercontent.com`; reference its ARN as a hardcoded
  string (`locals.github_oidc_provider_arn` — predictable, not looked up
  via a data source, to avoid a first-apply data-source-timing problem)
  and create only new repo-scoped IAM roles here.
- Do not use static long-lived AWS access keys in GitHub secrets — OIDC role
  assumption only, matching every other project this owner maintains.
- Do not switch IaC tools — OpenTofu only.
- Do not add always-on compute — everything here should be event-driven
  (EventBridge → Lambda), matching the cost posture of the sibling projects.
- Do not enable auto-remediation actions that could lock Derek himself out of
  the account (e.g. never auto-disable the IAM user/role currently being used
  to manage this very pipeline).

---

## Current Status

### Completed
- `README.md`, `CLAUDE.md`, `DESIGN.md` — planning docs (2026-08-23)
- Confirmed via live AWS CLI check (2026-08-23): this account currently has
  **no GuardDuty detector and no CloudTrail trail** — genuinely starting
  from zero on both, not assuming.
- Phase 1 (GuardDuty, CloudTrail bucket+policy+trail, SNS topic, alert
  Lambda + IAM, EventBridge rules) and Phase 2 (CI/CD: OIDC roles,
  `.checkov.yaml`, `plan.yml`/`apply.yml`) written 2026-08-23, all as a
  single batch, pushed to a PR.
- `pytest tests/` passes locally (4 tests: GuardDuty finding formatting,
  watched-event formatting, root-login's no-`arn`-key shape, subject
  truncation) — run via moto's SNS→SQS subscription pattern (same as
  `satellite-tracker`'s alerts tests) to assert actual delivered message
  content, not just a status code.
- Two things verified live against real AWS docs before writing any of
  this, specifically because they'd have been silent, hard-to-debug bugs
  if guessed wrong: (1) CloudTrail-sourced events require an active Trail
  to reach EventBridge at all — GuardDuty findings do not; (2) console
  sign-in events use a different `source`/`detail-type` pair
  (`aws.signin` / "AWS Console Sign In via CloudTrail") than general API
  calls (`aws.cloudtrail` / "AWS API Call via CloudTrail").
- The current CloudTrail S3 bucket policy shape (with the `aws:SourceArn`
  condition) was pulled from AWS's own current docs, not memory — AWS has
  tightened this policy's recommended shape over time.

### Phase 1 + Phase 2 — deployed and verified live, 2026-08-24
Local `tofu` was blocked the entire time (endpoint security "Application
Control policy has blocked this file" — same class of issue logged in
`satellite-tracker`'s own memory), so every step from first plan through
final apply went through GitHub Actions/OIDC, with a real
"AccessDenied afternoon" along the way — expected, per `satellite-tracker`'s
own Phase 5 precedent, not a sign anything was wrong.

**The chicken-and-egg bootstrap problem, solved:** `detect-respond-gha-plan`/
`-apply` didn't exist yet, so CI couldn't assume a role that doesn't exist
to create that very role — no existing pipeline to fall back on the way
`satellite-tracker` sessions could. Fixed by creating the 2 roles + 2
policies + 3 attachments directly via AWS CLI (matching the `.tf` exactly),
then a one-time `bootstrap-import.yml` workflow (`workflow_dispatch` only,
deleted after use — see git history if it's ever needed again) imported
them into state so the real `apply.yml` reconciled cleanly.

**Real gaps found and fixed against live `AccessDenied` errors** (not
guessed preemptively — each one only surfaced once the resource ahead of
it in the graph actually got created):
- `iam:CreateServiceLinkedRole` — GuardDuty's first-ever `CreateDetector`
  in an account needs to create its own service-linked role.
- The AWS provider's own drift-detection read-back on the S3 bucket needed
  several more sub-config `Get*` actions (CORS, website, accelerate,
  request-payment, logging, replication, object-lock) than the resources
  this project's own code actually configures — same shape as
  `satellite-tracker`'s own already-proven S3BucketRead list, reused
  wholesale instead of rediscovering each one.
- `cloudtrail:DescribeTrails` needed `Resource = "*"` — confirmed live that
  scoping it to the trail ARN still failed; it doesn't support
  resource-level scoping at all, same constraint as `logs:DescribeLogGroups`.
- Both the S3 bucket and the CloudTrail trail got marked "tainted" after a
  read-after-write step failed on each (fixed by the gaps above) — resolved
  with `tofu untaint` for the bucket specifically (to avoid granting
  `s3:DeleteBucket` to the ongoing CI role just to route around a
  since-fixed transient failure); the trail's replace went through cleanly
  since `cloudtrail:DeleteTrail` was already granted from the start.

**Verified live, end-to-end, after the apply succeeded** — not just "the
apply exited 0": `aws guardduty list-detectors` shows an active detector,
`aws cloudtrail get-trail-status` confirms `detect-respond-trail` is
actively logging (multi-region), both EventBridge rules show `ENABLED`,
and `aws lambda invoke` with a synthetic GuardDuty-Finding-shaped payload
against the real deployed `detect-respond-alert` function returned
`{"published": true}`.

**Still outstanding:** no email subscription on the SNS topic yet (owner
task, out-of-band, same pattern as `satellite-tracker`'s `alerts.tf`:
`aws sns subscribe --topic-arn <alerts_topic_arn output> --protocol email
--notification-endpoint <address>`) — until that's added, alerts publish
successfully but have nowhere to actually land.

### Owner Prerequisites (not build tasks)
- GitHub repo `MacGotHub/aws-detect-respond` — done, created 2026-08-23
  (created on Derek's behalf, with explicit permission, unlike
  `satellite-tracker` where repo creation was left to Derek — confirm this
  precedent before assuming it applies to future projects too)

### Known Dependencies
- Phase 3 (dashboarding) needs Phase 1's findings actually flowing before a
  dashboard has anything to show
- Phase 4 (auto-remediation) is deliberately sequenced last and should be
  revisited/re-scoped once Phase 1 has been running long enough to know
  what a real, common, safe-to-automate finding actually looks like on this
  account — not designed speculatively up front
