#Requires -Version 7.0
#Requires -Modules Microsoft.Graph.Authentication

<#
.SYNOPSIS
    Detect illicit-consent-grant activity in the Entra ID directory audit log.
    MITRE ATT&CK: T1528 - Steal Application Access Token.

.DESCRIPTION
    Read-only. Pulls "Consent to application" and delegated-permission-grant events
    from Entra's native directory audit log (via Graph REST), then flags each one the
    way a SOC analyst would triage it:

      - Was it ADMIN consent (tenant-wide / AllPrincipals)?  -> blast radius = everyone
      - Did it request HIGH-risk scopes (Mail, offline_access, Directory, Files)?
      - Who consented, to what app, and when?

    This is the "hunt" half of the lab: it should surface the LAB-ConsentPhish-Target
    event created in phase 2. Directory audit is native to Entra, so this works with no
    Sentinel/Log Analytics dependency. (The Sentinel KQL version lives in
    queries/detect-consent-grant.kql - same logic, for tenants that export AuditLogs.)

.PARAMETER HoursBack
    How far back to hunt. Default 24.

.PARAMETER EvidencePath
    Folder for the CSV evidence. Defaults to ..\evidence.

.EXAMPLE
    .\find-consent-events.ps1
    Hunt the last 24h of consent activity and flag the risky grants.

.EXAMPLE
    .\find-consent-events.ps1 -HoursBack 2
    Narrow to the last 2h (useful right after triggering the lab event).

.NOTES
    Graph scopes (READ-ONLY): AuditLog.Read.All, Directory.Read.All
#>

[CmdletBinding()]
param(
    [int]$HoursBack = 24,
    [string]$EvidencePath = (Join-Path $PSScriptRoot '..' 'evidence')
)

$ErrorActionPreference = 'Stop'
if (-not (Test-Path $EvidencePath)) { New-Item -ItemType Directory -Path $EvidencePath -Force | Out-Null }
$GraphBase = 'https://graph.microsoft.com/v1.0'

function Write-Log {
    param([string]$Msg, [string]$Level = 'INFO')
    $c = @{ INFO='Gray'; OK='Green'; WARN='Yellow'; HIGH='Red' }[$Level]; if (-not $c) { $c = 'Gray' }
    Write-Host ("[{0}] {1}" -f $Level, $Msg) -ForegroundColor $c
}

function Get-GraphAll {
    param([string]$Uri)
    $items = @(); $next = $Uri
    while ($next) {
        $resp = Invoke-MgGraphRequest -Method GET -Uri $next -OutputType PSObject
        if ($null -ne $resp.value) { $items += $resp.value }
        $next = $resp.'@odata.nextLink'
    }
    return $items
}

$HighRiskScopes = @(
    'Mail.Read','Mail.ReadWrite','Mail.Send','MailboxSettings.ReadWrite',
    'Files.Read.All','Files.ReadWrite.All','Sites.Read.All','Sites.ReadWrite.All',
    'User.Read.All','Directory.Read.All','Directory.ReadWrite.All','Group.ReadWrite.All',
    'offline_access','full_access_as_user','EWS.AccessAsUser.All'
)

try {
    Connect-MgGraph -Scopes 'AuditLog.Read.All','Directory.Read.All' -NoWelcome
    $ctx = Get-MgContext
    Write-Log ("Connected. Tenant {0} as {1}" -f $ctx.TenantId, $ctx.Account) 'OK'
}
catch { Write-Log "Graph connect failed: $($_.Exception.Message)" 'HIGH'; throw }

# --- Time bound (explicit, UTC) - a hunt ALWAYS states its window ---
$since = (Get-Date).ToUniversalTime().AddHours(-$HoursBack).ToString('yyyy-MM-ddTHH:mm:ssZ')
Write-Log ("Hunting consent activity since {0} (UTC), last {1}h" -f $since, $HoursBack)

# --- Pull consent-related directory audit events in the window ---
# activityDisplayName is the reliable anchor; category ApplicationManagement holds these.
$filter = "activityDateTime ge $since and category eq 'ApplicationManagement'"
$uri = "$GraphBase/auditLogs/directoryAudits?`$filter=$([System.Uri]::EscapeDataString($filter))&`$top=100"
$events = Get-GraphAll $uri | Where-Object {
    $_.activityDisplayName -match 'consent|permission grant|delegated'
}
Write-Log ("Consent-related events in window: {0}" -f @($events).Count)

$rows = foreach ($e in $events) {
    # actor: user UPN or app
    $actor = if ($e.initiatedBy.user.userPrincipalName) { $e.initiatedBy.user.userPrincipalName }
             elseif ($e.initiatedBy.app.displayName)     { $e.initiatedBy.app.displayName }
             else { 'unknown' }

    # target app name + parse modifiedProperties for admin-consent flag and scope list
    $app = ($e.targetResources | Select-Object -First 1).displayName
    $isAdmin = $false; $scopeText = ''
    foreach ($t in $e.targetResources) {
        foreach ($mp in $t.modifiedProperties) {
            switch -Wildcard ($mp.displayName) {
                '*IsAdminConsent*' { if ($mp.newValue -match 'true') { $isAdmin = $true } }
                '*Permissions*'    { $scopeText += " $($mp.newValue)" }
                '*ConsentAction*'  { $scopeText += " $($mp.newValue)" }
            }
        }
    }

    $hitScopes = @($HighRiskScopes | Where-Object { $scopeText -match [regex]::Escape($_) })
    $verdict = if ($isAdmin -and $hitScopes) { 'SUSPICIOUS - admin(tenant-wide) consent to high-risk scopes' }
               elseif ($isAdmin)             { 'REVIEW - tenant-wide consent' }
               elseif ($hitScopes)           { 'REVIEW - high-risk scopes (single user)' }
               else                          { 'INFO' }

    [pscustomobject]@{
        TimestampUtc = $e.activityDateTime
        Actor        = $actor
        Activity     = $e.activityDisplayName
        TargetApp    = $app
        AdminConsent = $isAdmin
        HighRiskHits = ($hitScopes -join ';')
        Result       = $e.result
        Verdict      = $verdict
        MITRE        = 'T1528'
    }
}

$rows = @($rows) | Sort-Object TimestampUtc -Descending
$rows | Export-Csv (Join-Path $EvidencePath 'consent-detection-results.csv') -NoTypeInformation
Write-Log ("Wrote consent-detection-results.csv ({0} rows)" -f @($rows).Count) 'OK'

Write-Log ''
Write-Log '=== HUNT RESULTS (T1528) ==='
$rows | Format-Table TimestampUtc, Actor, Activity, TargetApp, AdminConsent, HighRiskHits, Verdict -AutoSize -Wrap

$flagged = @($rows | Where-Object { $_.Verdict -like 'SUSPICIOUS*' })
Write-Log ''
Write-Log ("SUSPICIOUS grants (admin consent + high-risk scope): {0}" -f $flagged.Count) $(if($flagged.Count){'HIGH'}else{'OK'})
if ($flagged.Count) {
    Write-Log 'These are the illicit-consent-grant signature. In the real world: revoke the grant, disable the SP, and hunt the refresh-token usage.' 'HIGH'
}

Disconnect-MgGraph *> $null
