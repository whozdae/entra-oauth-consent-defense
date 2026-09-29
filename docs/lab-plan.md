# OAuth Consent Governance (Entra ID) — Lab Plan

**Goal:** prove I can detect an illicit OAuth consent grant and harden a tenant so
consent-phishing can't land. Attack → Detect → Harden, all in a tenant I own.

**Maps to:** SC-300 (application consent, admin consent workflow, app governance),
SC-200 (identity threat detection), MITRE ATT&CK **T1528 – Steal Application Access Token**.

## Threat model in one line
Consent phishing skips the password entirely: the victim is shown a *real* Microsoft
consent screen for an attacker-registered app, clicks "Accept," and hands over an OAuth
token (often with `offline_access`, so it survives a password reset and MFA).

## Phases

| # | Phase | Script / artifact | Proves |
|---|-------|-------------------|--------|
| 1 | Baseline | `get-consent-posture.ps1` | Current user-consent setting, admin-workflow state, every standing grant risk-scored |
| 2 | Target | `new-lab-consent-app.ps1` | A benign lab app + a real consent event to detect (no creds harvested, no external victim) |
| 3 | Detect | `queries/*.kql` | Illicit consent grant surfaced from `AuditLogs`, mapped to T1528, with a timeline |
| 4 | Harden | `set-consent-hardening.ps1` | User consent restricted to low-risk/verified, admin workflow enabled with a reviewer, before/after re-baseline |

## Prerequisites
- PowerShell 7, `Microsoft.Graph` module installed:
  `Install-Module Microsoft.Graph -Scope CurrentUser`
- Entra roles for the run: Global Reader (baseline/detect) is enough for read;
  Application Administrator + a role that can edit the authorization policy for hardening.
- A test tenant / dev tenant I own. **No production. No real user targeted.**

## Guardrails honored
- Every write script: `-WhatIf` first, verification step, rollback path.
- All evidence sanitized (tenant/app/UPN identifiers stripped) before it enters the repo.
- Raw captures (`*.har`, `*-RAW.*`, credential CSVs) are `.gitignore`d.
