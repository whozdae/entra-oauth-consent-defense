# Incident Timeline — Consent Phishing (Lab)

Reconstructed from the Entra directory audit log. Times UTC. Identifiers sanitized.

| Timestamp (UTC) | User | Event | Evidence | ATT&CK | Flag |
|-----------------|------|-------|----------|--------|------|
| 2026-09-29 00:52 | lab-admin | Baseline captured: user consent = recommended; admin workflow OFF; tenant-wide Graph CLI grant | `consent-policy-before.csv` | — | Recon / posture |
| 2026-09-29 ~01:29 | lab-admin | Registered `LAB-ConsentPhish-Target` (multi-tenant, unverified) requesting `Mail.Read` + `offline_access` | app registration | T1528 (setup) | Lure created |
| 2026-09-29 01:29:53 | lab-admin | **Consent to application** granted — `AllPrincipals` (tenant-wide), "consent on behalf of your organization" | `consent-detection-results.csv` | **T1528** | **SUSPICIOUS** |
| 2026-09-29 01:29:53 | lab-admin | **Add delegated permission grant** → Microsoft Graph (the underlying grant object write) | `consent-detection-results.csv` | T1528 | Correlated |
| 2026-09-29 ~01:35 | lab-admin | Hunt run: lab app surfaced as SUSPICIOUS (tenant-wide + high-risk scope) | `find-consent-events.ps1` output | T1528 | Detected |
| 2026-09-29 ~04:13 | lab-admin | Hardening: admin consent workflow enabled (1 reviewer) → user consent set admin-only | `consent-policy-after.csv` | — | Contained |
| 2026-09-29 ~04:2x | lab-admin | Remediation: lab app + service principal removed; re-baseline shows grant gone | `high-risk-grants-after.csv` | — | Remediated |

**Read as a story:** measured the tenant → planted a lure and consented org-wide → the audit
log caught it as an illicit tenant-wide grant → stood up a review gate and closed user
consent → evicted the app that was already inside. Hardening + remediation, both proven.
