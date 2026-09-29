# Troubleshooting Log

Real issues hit while building this lab, with the root cause and fix for each.

| # | Symptom | Root cause | Fix |
|---|---------|-----------|-----|
| T01 | `Get-MgPolicyAuthorizationPolicy is not recognized` after a successful `Connect-MgGraph` | Only `Microsoft.Graph.Authentication` was installed; the policy cmdlets live in the `Identity.SignIns` submodule (the full SDK is ~40 submodules) | Rewrote every call as raw REST via `Invoke-MgGraphRequest`, which ships in the Authentication module. One dependency, portable to any machine |
| T02 | `Cannot convert null to type System.ConsoleColor` | The log helper had no color mapped for the `MEDIUM`/`LOW` levels, so it passed `$null` to `-ForegroundColor` | Added the missing levels plus a default fallback color |
| T03 | User-consent verdict read "RESTRICTED" for the wrong reason | Regex `'low'` matched inside `al`**`low`**`-consent-apps`: a false positive that happened to give the right answer | Filtered to `ManagePermissionGrantsForSelf.*` entries and anchored on the exact `-legacy` / `-recommended` / `-low` policy suffixes |
| T04 | `404 Not Found` enabling the admin consent workflow (routed to `accessreviews.identitygovernance...`) | Used `PATCH`; `adminConsentRequestPolicy` is a singleton that Graph only updates with **`PUT`** (full replace) | Switched to `PUT` per Microsoft Learn. `authorizationPolicy` correctly stays `PATCH` |
| T05 | `400 Bad Request: null value for permissionGrantPoliciesAssigned` | `$x = if (...) { @() }` sends the empty array through the pipeline, which unrolls it to `$null` | Wrapped in the array subexpression `@( )`, which always returns an array (empty becomes `[]`) |
| T06 | Baseline "before" CSVs overwritten by later runs | Script wrote to fixed filenames | Added a `-Label` parameter (`-Label before` / `-Label after`); before-state restored from the captured phase-1 run output |
| T07 | Sentinel KQL could not be run live | Entra diagnostic settings require an **Azure subscription**; the lab tenant has Entra ID P2 only, so there is no Log Analytics workspace | Proved detection through Graph `directoryAudits` instead; the KQL ships as a deploy-ready analytics rule |
| T08 | `Failed to clear the persisted MSAL token cache during Disconnect-MgGraph` | Known cosmetic SDK warning emitted after the work completes | Benign; no data impact. Suppressed where possible |

**Design decision that paid off twice:** the hardening script enables the admin consent
workflow *before* it restricts user consent. When T04 and T05 failed partway through,
the tenant was never left with consent blocked and no review path.
