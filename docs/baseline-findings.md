# Phase 1 — Baseline Consent Posture (Findings)

**Captured:** 2026-09-29 (UTC) · **Method:** `scripts/get-consent-posture.ps1` (read-only, Graph REST)
**Tenant:** lab tenant (identifiers sanitized)

## Summary

| Area | State | Risk |
|------|-------|------|
| User consent policy | `microsoft-user-default-recommended` — users may self-consent to low-impact permissions from **verified publishers** only | 🟡 MEDIUM |
| Admin consent workflow | **Disabled**, **0** reviewers named | 🔴 HIGH |
| Standing grants | 1 delegated, 0 application | — |
| — of which HIGH risk | 1 (tenant-wide) | 🔴 HIGH |

## Finding 1 — No admin consent workflow (HIGH)
The admin consent request policy is disabled with no reviewer assigned. Consequence: if
user consent is tightened, a user's consent request has nowhere to go — it dead-ends and
no admin is notified. A hardened tenant needs the workflow **on** with at least one named
reviewer, or tightening user consent just pushes users toward risky workarounds.

## Finding 2 — Over-privileged tenant-wide grant (HIGH)
The only standing grant is **Microsoft Graph Command Line Tools** (Microsoft-published,
verified publisher), but it was consented **AllPrincipals** (organization-wide, not to a
single user) and carries high-impact delegated write scopes plus `offline_access`:

`Directory.ReadWrite.All`, `Group.ReadWrite.All`, `Application.ReadWrite.All`,
`AppRoleAssignment.ReadWrite.All`, `EntitlementManagement.ReadWrite.All`,
`AccessReview.ReadWrite.All`, `LifecycleWorkflows.ReadWrite.All`, `User.ReadWrite.All`,
`offline_access`.

**Why it matters:** this is the exact *shape* consent phishing produces —
one consent click → tenant-wide → high privilege → a refresh token that survives a
password reset and MFA. `AppRoleAssignment.ReadWrite.All` + `Application.ReadWrite.All`
together is a privilege-escalation path (an app that can grant apps more permissions).
It is benign here (first-party, verified) and required by our own tooling, so the
remediation is not "revoke" but **scope down**: change from `AllPrincipals` to a single
admin (`Principal`) and consent only the scopes actually in use.

*Root cause (honest note):* the grant accumulated because earlier labs repeatedly chose
"Consent on behalf of your organization" at the `Connect-MgGraph` prompt. That is the
end-user behavior consent-phishing defense is built to prevent.

## Finding 3 — User consent on the recommended default (MEDIUM)
`microsoft-user-default-recommended` is Microsoft's recommended posture (verified
publishers, low-impact perms only). Reasonable; phase 4 tightens toward
admin-reviewed consent for anything beyond that.

## Evidence
- `evidence/consent-policy-baseline.csv`
- `evidence/standing-grants-baseline.csv`
- `evidence/high-risk-grants.csv`
