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
├── opentofu/                  # All IaC (TODO — not created yet)
│   ├── backend.tf             # Remote state — reuse the shared
│   │                          #   351668480009-opentofu-state bucket,
│   │                          #   new key (e.g. detect-respond/pipeline)
│   ├── providers.tf
│   ├── main.tf                # GuardDuty detector, CloudTrail trail, EventBridge rules
│   ├── locals.tf
│   ├── lambda_alert.tf        # Alert-processing Lambda + IAM
│   ├── cicd_oidc.tf           # New repo-scoped IAM roles ONLY — the GitHub
│   │                          #   OIDC provider itself already exists in this
│   │                          #   account (created by satellite-tracker's
│   │                          #   Phase 5); reference it as a data source,
│   │                          #   do not create a second one for the same URL
│   └── outputs.tf
├── src/                       # Lambda source (Python) — TODO, not created yet
│   └── alert/                 # Parses GuardDuty findings / CloudTrail events, publishes to SNS
├── tests/                     # pytest unit tests — TODO
└── .github/
    └── workflows/             # plan/apply pipelines — TODO
```

Do not create TODO directories until their phase actually starts.

---

## Architecture Overview

```
GuardDuty (threat detection: compromised creds, unusual API calls, etc.)
    ↓ (finding events, default EventBridge bus)
CloudTrail (management events — most already flow to the default
    EventBridge bus without a custom Trail; a Trail is still created for
    its own durable S3-backed audit log, not because EventBridge needs it)
    ↓
EventBridge rules (GuardDuty findings + specific high-value CloudTrail
    events: root login, CreateAccessKey, admin-policy attachment,
    StopLogging/DeleteTrail, etc.)
    ↓
Lambda (parse, classify severity, format human-readable message)
    ↓
SNS topic → email (Phase 1); Slack webhook and/or safe auto-remediation
    actions are later phases, not Phase 1
```

### Phases (initial scoping — refine as work starts)

| Phase | Scope |
|---|---|
| 1 — Foundation & alerting | Enable GuardDuty, create a CloudTrail trail, EventBridge rules on GuardDuty findings + a small set of high-value CloudTrail events, one Lambda that formats and publishes to SNS (email). No auto-remediation. |
| 2 — CI/CD | GitHub Actions + OIDC (reusing the existing provider, new repo-scoped roles), Checkov gate — matching `satellite-tracker`'s Phase 5 exactly. |
| 3 — Dashboarding | CloudWatch dashboard summarizing findings over time (counts by severity/type). |
| 4 — Safe auto-remediation | Only for extremely high-confidence, low-blast-radius actions (e.g. disabling an access key GuardDuty explicitly flagged as compromised) — deliberately conservative; alerting-only is the safe default until specific remediation actions are individually reasoned through. |

Estimates intentionally not pre-committed yet — this project hasn't started building, unlike `satellite-tracker`'s CLAUDE.md which carried real evening/weekend estimates from day one.

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
  `token.actions.githubusercontent.com`; reference it as a data source and
  create only new repo-scoped IAM roles here.
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

### Not Started
- Everything else. Phase 1 has not been built.

### Owner Prerequisites (not build tasks)
- GitHub repo `MacGotHub/aws-detect-respond` — done, created 2026-08-23
  (created on Derek's behalf, with explicit permission, unlike
  `satellite-tracker` where repo creation was left to Derek — confirm this
  precedent before assuming it applies to future projects too)

### Known Dependencies
- Phase 2 (CI/CD) needs Phase 1's resources to exist first (nothing to
  plan/apply otherwise)
- Phase 3 (dashboarding) needs Phase 1's findings actually flowing before a
  dashboard has anything to show
- Phase 4 (auto-remediation) is deliberately sequenced last and should be
  revisited/re-scoped once Phase 1 has been running long enough to know
  what a real, common, safe-to-automate finding actually looks like on this
  account — not designed speculatively up front
