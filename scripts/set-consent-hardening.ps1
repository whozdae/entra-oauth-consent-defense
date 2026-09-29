#Requires -Version 7.0
#Requires -Modules Microsoft.Graph.Authentication

<#
.SYNOPSIS
    Harden a tenant against OAuth consent phishing: restrict user consent and turn on
    the admin consent workflow with a named reviewer.

.DESCRIPTION
    Closes the two HIGH gaps the baseline found:
      GAP 1 - users could self-consent to apps       -> restrict user consent
      GAP 2 - no admin consent review gate            -> enable the workflow + a reviewer

    Two config changes, both reversible:
      1. authorizationPolicy.defaultUserRolePermissions.permissionGrantPoliciesAssigned
         - 'AdminOnly'          -> [] (users cannot consent; everything goes to an admin)
         - 'VerifiedLowImpact'  -> low-impact perms from verified publishers only
      2. adminConsentRequestPolicy -> enabled, with a reviewer, notifications, reminders.

    Follows the hardening rule: tightening user consent WITHOUT a working admin workflow
    just dead-ends users, so this script does both together, in that order.

    Graph REST via Invoke-MgGraphRequest (only Microsoft.Graph.Authentication needed).
    Supports -WhatIf and -Rollback.

.PARAMETER UserConsentMode
    'AdminOnly' (default, strongest) or 'VerifiedLowImpact'.

.PARAMETER ReviewerUpn
    UPN of the admin who reviews consent requests. Defaults to the signed-in user.

.PARAMETER RequestDurationInDays
    How long a pending consent request stays open. Default 30.

.PARAMETER Rollback
    Restore the pre-hardening posture: user consent -> 'recommended', workflow -> disabled.

.EXAMPLE
    .\set-consent-hardening.ps1 -WhatIf
    Preview both changes; write nothing.

.EXAMPLE
    .\set-consent-hardening.ps1
    Restrict user consent to admin-only and enable the workflow with yourself as reviewer.

.EXAMPLE
    .\set-consent-hardening.ps1 -Rollback
    Put the tenant back the way it was.

.NOTES
    Graph scopes (least privilege, each justified):
      Policy.ReadWrite.Authorization   - write the user-consent (authorization) policy
      Policy.ReadWrite.ConsentRequest  - write the admin consent request policy
      User.Read.All                    - resolve the reviewer UPN to an object id
#>

[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
param(
    [ValidateSet('AdminOnly','VerifiedLowImpact')]
    [string]$UserConsentMode = 'AdminOnly',
    [string]$ReviewerUpn,
    [int]$RequestDurationInDays = 30,
    [switch]$Rollback
)

$ErrorActionPreference = 'Stop'
$GraphBase = 'https://graph.microsoft.com/v1.0'

function Write-Log {
    param([string]$Msg, [string]$Level = 'INFO')
    $c = @{ INFO='Gray'; OK='Green'; WARN='Yellow'; HIGH='Red' }[$Level]; if (-not $c) { $c = 'Gray' }
    Write-Host ("[{0}] {1}" -f $Level, $Msg) -ForegroundColor $c
}

$LowImpactPolicy = 'ManagePermissionGrantsForSelf.microsoft-user-default-low'
$RecommendedPolicy = 'ManagePermissionGrantsForSelf.microsoft-user-default-recommended'

try {
    Connect-MgGraph -Scopes 'Policy.ReadWrite.Authorization','Policy.ReadWrite.ConsentRequest','User.Read.All' -NoWelcome
    $ctx = Get-MgContext
    Write-Log ("Connected. Tenant {0} as {1}" -f $ctx.TenantId, $ctx.Account) 'OK'
}
catch { Write-Log "Graph connect failed: $($_.Exception.Message)" 'HIGH'; throw }

# =========================================================== ROLLBACK
if ($Rollback) {
    if ($PSCmdlet.ShouldProcess('authorizationPolicy', "Restore user consent -> recommended")) {
        $body = @{ defaultUserRolePermissions = @{ permissionGrantPoliciesAssigned = @($RecommendedPolicy) } }
        Invoke-MgGraphRequest -Method PATCH -Uri "$GraphBase/policies/authorizationPolicy" -Body ($body | ConvertTo-Json -Depth 5) | Out-Null
        Write-Log 'User consent restored to recommended.' 'OK'
    }
    if ($PSCmdlet.ShouldProcess('adminConsentRequestPolicy', 'Disable admin consent workflow')) {
        $body = @{ isEnabled = $false; notifyReviewers = $false; remindersEnabled = $false; requestDurationInDays = 30; reviewers = @() }
        Invoke-MgGraphRequest -Method PUT -Uri "$GraphBase/policies/adminConsentRequestPolicy" -Body ($body | ConvertTo-Json -Depth 5) | Out-Null
        Write-Log 'Admin consent workflow disabled.' 'OK'
    }
    Disconnect-MgGraph *> $null
    return
}

# =========================================================== HARDEN
# --- Resolve the reviewer (default: the signed-in admin) ---
if (-not $ReviewerUpn) { $ReviewerUpn = $ctx.Account }
$reviewer = Invoke-MgGraphRequest -Method GET -Uri "$GraphBase/users/$([System.Uri]::EscapeDataString($ReviewerUpn))?`$select=id,userPrincipalName" -OutputType PSObject
if (-not $reviewer.id) { throw "Could not resolve reviewer '$ReviewerUpn'." }
Write-Log ("Reviewer: {0}" -f $reviewer.userPrincipalName)

# --- GAP 2 FIRST: enable the admin consent workflow (the safety net) ---
# Order matters: stand up the review gate BEFORE restricting consent, so a user whose
# consent is now blocked has somewhere for the request to go instead of dead-ending.
if ($PSCmdlet.ShouldProcess('adminConsentRequestPolicy', "Enable workflow, reviewer=$($reviewer.userPrincipalName)")) {
    $body = @{
        isEnabled             = $true
        notifyReviewers       = $true
        remindersEnabled      = $true
        requestDurationInDays = $RequestDurationInDays
        reviewers             = @(@{ query = "/users/$($reviewer.id)"; queryType = 'MicrosoftGraph' })
    }
    Invoke-MgGraphRequest -Method PUT -Uri "$GraphBase/policies/adminConsentRequestPolicy" -Body ($body | ConvertTo-Json -Depth 6) | Out-Null
    Write-Log 'GAP 2 closed: admin consent workflow enabled with a named reviewer.' 'OK'
}

# --- GAP 1 SECOND: restrict user consent (now safe - the gate exists) ---
# @( ) forces an array. A bare `if` returning @() unrolls to $null through the pipeline,
# and Graph rejects null here ("does not allow null values"). Empty array = admin-only.
$policyValue = @(if ($UserConsentMode -ne 'AdminOnly') { $LowImpactPolicy })
$modeLabel   = if ($UserConsentMode -eq 'AdminOnly') { 'admin-only (no user self-consent)' } else { 'verified publishers + low-impact only' }
if ($PSCmdlet.ShouldProcess('authorizationPolicy', "Set user consent -> $modeLabel")) {
    $body = @{ defaultUserRolePermissions = @{ permissionGrantPoliciesAssigned = $policyValue } }
    Invoke-MgGraphRequest -Method PATCH -Uri "$GraphBase/policies/authorizationPolicy" -Body ($body | ConvertTo-Json -Depth 5) | Out-Null
    Write-Log "GAP 1 closed: user consent set to $modeLabel." 'OK'
}

# =========================================================== VERIFY
if (-not $WhatIfPreference) {
    Write-Log ''
    Write-Log '=== VERIFY ==='
    $ap  = Invoke-MgGraphRequest -Method GET -Uri "$GraphBase/policies/authorizationPolicy" -OutputType PSObject
    $now = @($ap.defaultUserRolePermissions.permissionGrantPoliciesAssigned)
    Write-Log ("User consent policies now : {0}" -f (($now | Where-Object {$_}) -join ', ' | ForEach-Object { if($_){$_}else{'(none = admin-only)'} }))
    $acrp = Invoke-MgGraphRequest -Method GET -Uri "$GraphBase/policies/adminConsentRequestPolicy" -OutputType PSObject
    Write-Log ("Admin workflow enabled     : {0} | reviewers: {1}" -f $acrp.isEnabled, @($acrp.reviewers).Count) $(if($acrp.isEnabled){'OK'}else{'HIGH'})
    Write-Log ''
    Write-Log 'Re-run get-consent-posture.ps1 to capture the hardened baseline (before/after evidence).' 'WARN'
}

Disconnect-MgGraph *> $null
