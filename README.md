# aws-detect-respond

A cloud security detection & automated response pipeline: AWS GuardDuty
findings and high-value CloudTrail events flow through EventBridge into a
Lambda that alerts (and, later, auto-remediates the safest, highest-confidence
cases). Built entirely on AWS with OpenTofu and deployed via GitHub Actions
with OIDC — a DevSecOps portfolio piece that demonstrates detection
engineering and automated response, distinct from `aws-iac-lab` (network
security IaC patterns) and `satellite-tracker` (a serverless app + CI/CD
showcase).

## Where to look

| File | What it's for |
|---|---|
| [`CLAUDE.md`](CLAUDE.md) | Persistent project context — owner, tooling, conventions, current status. Read this first before making any changes. |
| [`DESIGN.md`](DESIGN.md) | Architecture and design rationale — topology, phase plan, open decisions. |

## Status

Planning stage — no infrastructure deployed yet. See CLAUDE.md for detailed
status.
