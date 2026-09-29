# OAuth Consent Governance in Microsoft Entra ID — Attack, Detect, Harden

> I stood up an OAuth consent-phishing scenario in a Microsoft Entra ID tenant I own,
> detected the illicit consent grant from the audit log (MITRE **T1528**), then hardened
> the tenant with PowerShell + Microsoft Graph — closing two HIGH-risk gaps and proving
> it with before/after evidence.

`Entra ID` · `PowerShell 7` · `Microsoft Graph (REST)` · `OAuth 2.0 / consent` · `KQL` · `MITRE ATT&CK T1528` · `SC-300` · `SC-200`

---

## Results at a glance

| Control | Before | After |
|---|---|---|
| User consent policy | Users could self-consent to apps (recommended default) | **Admin-only** — all consent routed to a reviewer |
| Admin consent workflow | Disabled, **0** reviewers | **Enabled**, 1 reviewer, notifications + reminders, 30-day TTL |
| Illicit consent grant | Undetected | **Detected** and mapped to MITRE T1528 |
| High-risk standing grants | 2 (incl. a planted lure) | **1** (lure removed; remaining grant documented as accepted risk) |

---

## Problem (Situation)
Consent phishing skips the password entirely. A user is shown a genuine Microsoft consent
screen for an attacker-registered app, clicks **Accept**, and hands over an OAuth token —
often with `offline_access`, so it survives a password reset and MFA. Microsoft Entra ID
tenants are exposed by default when user consent is permissive and no admin review gate
exists. I wanted to prove I could measure that exposure, catch the attack, and shut it down.

## Objective (Task)
In a tenant I own, and with no impact to any real user:
1. Baseline the tenant's consent posture and risk-score every standing grant.
2. Generate a controlled, benign consent event as a detection target.
3. Detect the illicit grant from the audit log and map it to MITRE ATT&CK.
4. Harden the tenant, then re-baseline to prove the gaps closed.

## Tools & Environment
- Microsoft Entra ID (P2), PowerShell 7, Microsoft Graph REST via `Invoke-MgGraphRequest`
- All Graph calls use least-privilege scopes; every change script has `-WhatIf` and a rollback path
- Detection: Entra `directoryAudits` (Graph) + a deploy-ready Sentinel KQL rule

## What I did (Action)

**1 — Baseline (`get-consent-posture.ps1`, read-only).**
Captured the user-consent policy, the admin consent workflow state, and every delegated /
application grant, risk-scored HIGH/MEDIUM/LOW. Two HIGH findings: no admin consent
workflow, and a tenant-wide (`AllPrincipals`) grant to *Microsoft Graph Command Line Tools*
holding high-impact write scopes + `offline_access`.

**2 — Generate a detection target (`new-lab-consent-app.ps1`).**
Registered one clearly-labelled multi-tenant app (`LAB-ConsentPhish-Target`) requesting
`Mail.Read` + `offline_access` — the silhouette of a real lure — and consented to it via the
standard Microsoft consent screen. No credentials harvested, no other user involved.

**3 — Detect (`find-consent-events.ps1` + `queries/detect-consent-grant.kql`).**
Hunted the directory audit log for `Consent to application` / permission-grant events,
parsed each event's admin-consent flag and requested scopes, and triaged by blast radius +
scope sensitivity. The lab app surfaced as **SUSPICIOUS** (tenant-wide consent to high-risk
scopes), tagged **MITRE T1528 — Steal Application Access Token**. The KQL is the same logic
as a Sentinel analytics rule (see note on ingestion below).

**4 — Harden (`set-consent-hardening.ps1`).**
Enabled the admin consent workflow with a named reviewer *first*, then restricted user
consent to admin-only — order chosen so a blocked request always has a review path.
Then removed the lab app and re-baselined.

## Results (with numbers)
- **2 HIGH gaps → 0.** User consent LOW/admin-only; admin workflow enabled with 1 reviewer.
- **Illicit grant detected** and mapped to T1528, with a full timeline of the attack→detect sequence.
- **High-risk standing grants 2 → 1.** The planted lure was removed; the remaining grant
  (our own admin CLI client) is documented as accepted risk with a remediation plan.
- Before/after evidence captured in `evidence/` (`*-before.csv` vs `*-after.csv`).

## Lessons learned & what I'd improve next
- **Hardening ≠ remediation.** Tightening the consent *policy* stops the next attack but does
  nothing to the grants already present. Both are required — I proved it with the grant count.
- **The verb encodes intent.** `adminConsentRequestPolicy` only updates with `PUT` (full
  replace), not `PATCH`; the wrong verb 404s. `authorizationPolicy` is a `PATCH`.
- **Order de-risks change.** Enabling the review gate before restricting consent meant two
  mid-run failures never left users stranded.
- **Next:** (1) move admin automation off the shared *Microsoft Graph Command Line Tools*
  client onto a dedicated app registration with certificate auth and minimal scopes;
  (2) stand up a Log Analytics workspace so the KQL runs as a live Sentinel analytics rule;
  (3) add a scheduled access review of all consent grants.

## Skills demonstrated
- **SC-300:** application consent settings, admin consent workflow, app registrations &
  service principals, least-privilege Graph scopes, identity governance.
- **SC-200:** consent-grant detection, audit-log hunting, MITRE ATT&CK mapping (T1528).
- **Engineering:** PowerShell 7, Microsoft Graph REST, `-WhatIf`/rollback safety, idempotent
  changes, evidence sanitization.

## Detection ingestion note
The Sentinel KQL (`queries/detect-consent-grant.kql`) requires Entra AuditLogs to be exported
to a Log Analytics workspace, which needs an Azure subscription. The lab tenant is Entra ID P2
only, so detection was proven via the Graph `directoryAudits` API and the KQL is provided as a
validated, deploy-ready analytics rule.

## Repo structure
```
OAuth Consent Governance (Entra ID)/
├── README.md
├── scripts/
│   ├── get-consent-posture.ps1        # phase 1 & 4 — baseline / re-baseline (read-only)
│   ├── new-lab-consent-app.ps1        # phase 2 — benign detection target (+ -Remove rollback)
│   ├── find-consent-events.ps1        # phase 3 — audit-log hunt (T1528)
│   └── set-consent-hardening.ps1      # phase 4 — restrict consent + enable workflow (+ -Rollback)
├── queries/
│   └── detect-consent-grant.kql       # Sentinel analytics rule (deploy-ready)
├── docs/
│   ├── lab-plan.md
│   ├── baseline-findings.md
│   └── troubleshooting.md
└── evidence/
    ├── consent-policy-before.csv  / consent-policy-after.csv
    ├── standing-grants-before.csv / standing-grants-after.csv
    ├── high-risk-grants-before.csv / high-risk-grants-after.csv
    └── consent-detection-results.csv
```

*Lab performed in a tenant I own. All identifiers (tenant, UPNs, app/object IDs) are sanitized.*
