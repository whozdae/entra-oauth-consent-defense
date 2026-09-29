#Requires -Version 7.0
#Requires -Modules Microsoft.Graph.Authentication

<#
.SYNOPSIS
    Baseline audit of a tenant's OAuth application-consent exposure in Microsoft Entra ID.

.DESCRIPTION
    Read-only. Captures the three things that decide whether a consent-phishing
    attack succeeds in a tenant, and risk-scores every existing grant:

      1. User consent policy    - can a normal user consent to third-party apps, and to what?
      2. Admin consent workflow  - is there a review gate, and does it name a reviewer?
      3. Standing grants         - every delegated OAuth2PermissionGrant plus every
                                   application-permission (app role) assignment, risk-scored.

    Talks to Microsoft Graph via Invoke-MgGraphRequest (raw REST), so the ONLY module
    required is Microsoft.Graph.Authentication - no ~40-submodule meta-install, and it
    runs the same on any machine. Changes nothing. This is "measure before you harden."

.PARAMETER EvidencePath
    Folder for the CSV evidence. Defaults to ..\evidence relative to the script.

.PARAMETER TopRiskyOnly
    If set, the console table shows only HIGH/MEDIUM grants (CSV still holds everything).

.EXAMPLE
    .\get-consent-posture.ps1
    Full read-only baseline; writes evidence CSVs.

.EXAMPLE
    .\get-consent-posture.ps1 -TopRiskyOnly
    Same, but console shows only the grants a reviewer would care about.

.NOTES
    Graph scopes (all READ-ONLY, least privilege):
      Policy.Read.All      - read authorizationPolicy (user consent) + adminConsentRequestPolicy
      Directory.Read.All   - read oauth2PermissionGrants, servicePrincipals, appRoleAssignments
    No write scopes are requested: this script cannot modify consent settings.
#>

[CmdletBinding()]
param(
    [string]$EvidencePath = (Join-Path $PSScriptRoot '..' 'evidence'),
    [switch]$TopRiskyOnly,
    [string]$Label = (Get-Date -Format 'yyyyMMdd-HHmmss')   # e.g. -Label before / -Label after
)

$ErrorActionPreference = 'Stop'
if (-not (Test-Path $EvidencePath)) { New-Item -ItemType Directory -Path $EvidencePath -Force | Out-Null }
$GraphBase = 'https://graph.microsoft.com/v1.0'

function Write-Log {
    param([string]$Msg, [string]$Level = 'INFO')
    $color = @{ INFO='Gray'; OK='Green'; WARN='Yellow'; HIGH='Red'; MEDIUM='Yellow'; LOW='Gray' }[$Level]
    if (-not $color) { $color = 'Gray' }
    Write-Host ("[{0}] {1}" -f $Level, $Msg) -ForegroundColor $color
}

# Follow @odata.nextLink and return the accumulated .value array
function Get-GraphAll {
    param([string]$Uri)
    $items = @()
    $next  = $Uri
    while ($next) {
        $resp  = Invoke-MgGraphRequest -Method GET -Uri $next -OutputType PSObject
        if ($null -ne $resp.value) { $items += $resp.value }
        $next = $resp.'@odata.nextLink'
    }
    return $items
}

# --- High-risk delegated scopes: what a consent-phishing lure actually wants ---
# Mail read/send = inbox exfiltration + BEC. Files/Sites = data theft. Directory/User.Read.All
# = recon. offline_access = a refresh token that outlives the phish (survives a password reset).
$HighRiskScopes = @(
    'Mail.Read','Mail.ReadWrite','Mail.Send','MailboxSettings.ReadWrite',
    'Files.Read.All','Files.ReadWrite.All','Sites.Read.All','Sites.ReadWrite.All',
    'User.Read.All','User.ReadWrite.All','Directory.Read.All','Directory.ReadWrite.All',
    'Group.ReadWrite.All','offline_access','full_access_as_user','EWS.AccessAsUser.All',
    'Contacts.Read','Notes.Read.All','Chat.Read','ChannelMessage.Read.All'
)
$MediumRiskPattern = 'ReadWrite|\.Send|Manage'

function Get-ScopeRisk {
    param([string]$Scope)
    if ([string]::IsNullOrWhiteSpace($Scope)) { return 'LOW' }
    $scopes = $Scope -split '\s+' | Where-Object { $_ }
    if ($scopes | Where-Object { $HighRiskScopes -contains $_ }) { return 'HIGH' }
    if ($scopes | Where-Object { $_ -match $MediumRiskPattern })  { return 'MEDIUM' }
    return 'LOW'
}

# ---------------------------------------------------------------------------
try {
    Write-Log 'Connecting to Microsoft Graph (read-only consent scopes)...'
    Connect-MgGraph -Scopes 'Policy.Read.All','Directory.Read.All' -NoWelcome
    $ctx = Get-MgContext
    Write-Log ("Connected. Tenant {0} as {1}" -f $ctx.TenantId, $ctx.Account) 'OK'
}
catch {
    Write-Log "Graph connect failed: $($_.Exception.Message)" 'HIGH'
    throw
}

# ===========================================================================
# 1. USER CONSENT POLICY
# ===========================================================================
Write-Log ''
Write-Log '=== 1. USER CONSENT POLICY ==='
$authPolicy    = Invoke-MgGraphRequest -Method GET -Uri "$GraphBase/policies/authorizationPolicy" -OutputType PSObject
$grantPolicies = @($authPolicy.defaultUserRolePermissions.permissionGrantPoliciesAssigned)

# Only the ManagePermissionGrantsForSelf.* entries govern USER self-consent.
# Match the built-in policy token exactly - matching a bare 'low' would false-positive
# on 'al-low-consent-apps', so anchor on the '-legacy' / '-recommended' / '-low' suffix.
$selfPolicies = @($grantPolicies | Where-Object { $_ -like 'ManagePermissionGrantsForSelf*' })
$selfJoined   = ($selfPolicies -join ';')
$userConsentState =
    if ($selfPolicies.Count -eq 0)        { 'DISABLED - users cannot consent; all consent is routed to admins' }
    elseif ($selfJoined -match '-legacy')      { 'OPEN - users can consent to ANY app / any permission (highest risk)' }
    elseif ($selfJoined -match '-recommended') { 'RECOMMENDED - users can consent to low-impact perms from verified publishers only' }
    elseif ($selfJoined -match '-low')         { 'RESTRICTED - users can consent only to low-impact permissions' }
    else { "CUSTOM self-consent policy: $selfJoined" }
$userRisk = switch -Wildcard ($userConsentState) {
    'OPEN*'        { 'HIGH';   break }
    'RECOMMENDED*' { 'MEDIUM'; break }
    'RESTRICTED*'  { 'MEDIUM'; break }
    'DISABLED*'    { 'LOW';    break }
    default        { 'MEDIUM' }
}
$policyLabel = if ($grantPolicies -and $grantPolicies[0]) { $grantPolicies -join ', ' } else { '(none)' }
Write-Log ("Assigned grant policies : {0}" -f $policyLabel) $userRisk
Write-Log ("Interpretation          : {0}" -f $userConsentState) $userRisk

# ===========================================================================
# 2. ADMIN CONSENT WORKFLOW
# ===========================================================================
Write-Log ''
Write-Log '=== 2. ADMIN CONSENT WORKFLOW ==='
$acrp = Invoke-MgGraphRequest -Method GET -Uri "$GraphBase/policies/adminConsentRequestPolicy" -OutputType PSObject
$reviewerCount = @($acrp.reviewers).Count
$acRisk = if (-not $acrp.isEnabled) { 'HIGH' } elseif ($reviewerCount -eq 0) { 'HIGH' } else { 'OK' }
Write-Log ("Workflow enabled : {0}" -f $acrp.isEnabled) $acRisk
Write-Log ("Reviewers named  : {0}" -f $reviewerCount) $acRisk
Write-Log ("Notify reviewers : {0} | Reminders: {1} | Request TTL(days): {2}" -f $acrp.notifyReviewers, $acrp.remindersEnabled, $acrp.requestDurationInDays)
if (-not $acrp.isEnabled) {
    Write-Log 'No admin consent workflow: if user consent is blocked, the request dead-ends and admins never see it - the gap that nudges users back toward risky self-consent.' 'WARN'
}

[pscustomobject]@{
    CapturedUtc            = (Get-Date).ToUniversalTime().ToString('o')
    UserConsentPolicies    = ($grantPolicies -join '|')
    UserConsentState       = $userConsentState
    UserConsentRisk        = $userRisk
    AdminWorkflowEnabled   = $acrp.isEnabled
    AdminWorkflowReviewers = $reviewerCount
    AdminWorkflowRisk      = $acRisk
} | Export-Csv (Join-Path $EvidencePath "consent-policy-$Label.csv") -NoTypeInformation
Write-Log "Wrote consent-policy-$Label.csv" 'OK'

# ===========================================================================
# 3. STANDING GRANTS
# ===========================================================================
Write-Log ''
Write-Log '=== 3. STANDING GRANTS (delegated + application) ==='

# Pull all service principals once; index by id for name + appRole lookups
Write-Log 'Loading service principals...'
$allSps = Get-GraphAll "$GraphBase/servicePrincipals?`$select=id,displayName,appId,verifiedPublisher,appRoles&`$top=999"
$spById = @{}
foreach ($sp in $allSps) { $spById[$sp.id] = $sp }
function Get-SpName    { param($Id) if ($Id -and $spById.ContainsKey($Id)) { $spById[$Id].displayName } else { $Id } }
function Get-SpPublisher { param($Id) if ($Id -and $spById.ContainsKey($Id) -and $spById[$Id].verifiedPublisher.displayName) { $spById[$Id].verifiedPublisher.displayName } else { 'NONE' } }

# --- 3a. Delegated grants (the consent-phishing vector) ---
Write-Log 'Enumerating delegated OAuth2 permission grants...'
$delegated = Get-GraphAll "$GraphBase/oauth2PermissionGrants"
$delegatedRows = foreach ($g in $delegated) {
    $risk = Get-ScopeRisk $g.scope
    if ($g.consentType -eq 'AllPrincipals' -and $risk -eq 'MEDIUM') { $risk = 'HIGH' }  # tenant-wide is worse
    [pscustomobject]@{
        GrantType   = 'Delegated'
        ClientApp   = Get-SpName $g.clientId
        VerifiedPub = Get-SpPublisher $g.clientId
        ConsentType = $g.consentType          # AllPrincipals = whole tenant; Principal = one user
        Scopes      = ($g.scope).Trim()
        Risk        = $risk
    }
}

# --- 3b. Application permissions (app roles held by service principals) ---
Write-Log 'Enumerating application-permission (app role) assignments...'
$appRows = foreach ($sp in $allSps) {
    $assignments = Get-GraphAll "$GraphBase/servicePrincipals/$($sp.id)/appRoleAssignments"
    foreach ($a in $assignments) {
        $resource  = if ($spById.ContainsKey($a.resourceId)) { $spById[$a.resourceId] } else { $null }
        $roleValue = if ($resource) { ($resource.appRoles | Where-Object { $_.id -eq $a.appRoleId }).value } else { $null }
        $risk = Get-ScopeRisk $roleValue
        if ($risk -ne 'LOW') { $risk = 'HIGH' }   # app perms run with NO signed-in user
        [pscustomobject]@{
            GrantType   = 'Application'
            ClientApp   = $sp.displayName
            VerifiedPub = if ($sp.verifiedPublisher.displayName) { $sp.verifiedPublisher.displayName } else { 'NONE' }
            ConsentType = 'AdminConsented'
            Scopes      = $roleValue
            Risk        = $risk
        }
    }
}

$allGrants = @($delegatedRows) + @($appRows)
$allGrants | Export-Csv (Join-Path $EvidencePath "standing-grants-$Label.csv") -NoTypeInformation
Write-Log ("Wrote standing-grants-$Label.csv ({0} grants: {1} delegated, {2} application)" -f $allGrants.Count, @($delegatedRows).Count, @($appRows).Count) 'OK'

$high = $allGrants | Where-Object { $_.Risk -eq 'HIGH' }
$high | Export-Csv (Join-Path $EvidencePath "high-risk-grants-$Label.csv") -NoTypeInformation
Write-Log ("Wrote high-risk-grants-$Label.csv ({0} HIGH-risk grants)" -f @($high).Count) $(if(@($high).Count){'HIGH'}else{'OK'})

# ===========================================================================
# CONSOLE SUMMARY
# ===========================================================================
Write-Log ''
Write-Log '=== POSTURE SUMMARY ==='
$show = if ($TopRiskyOnly) { $allGrants | Where-Object { $_.Risk -in 'HIGH','MEDIUM' } } else { $allGrants }
$show | Sort-Object @{e={switch($_.Risk){'HIGH'{0}'MEDIUM'{1}default{2}}}}, GrantType |
    Format-Table GrantType, ClientApp, VerifiedPub, ConsentType, Risk, Scopes -AutoSize -Wrap

Write-Log ("User consent      : {0}" -f $userRisk) $userRisk
Write-Log ("Admin workflow    : {0}" -f $acRisk) $acRisk
Write-Log ("HIGH-risk grants  : {0}" -f @($high).Count) $(if(@($high).Count){'HIGH'}else{'OK'})
Write-Log ''
Write-Log 'Baseline captured. Nothing was modified. Evidence CSVs are in the evidence folder.' 'OK'
Write-Log 'NEXT: sanitize the CSVs (strip tenant/app/UPN identifiers) before they go in the repo.' 'WARN'

Disconnect-MgGraph *> $null
