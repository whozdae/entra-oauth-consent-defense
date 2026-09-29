#Requires -Version 7.0
#Requires -Modules Microsoft.Graph.Authentication

<#
.SYNOPSIS
    Stand up a benign, clearly-labelled lab app so a REAL consent event exists to detect.

.DESCRIPTION
    Registers one app registration in the operator's OWN tenant that requests delegated
    Microsoft Graph scopes shaped like a consent-phishing lure (Mail.Read + offline_access),
    creates its service principal, and prints the standard Microsoft consent URL.

    When the operator signs in and clicks Accept, Entra writes a "Consent to application"
    audit event and a delegated OAuth2PermissionGrant - the exact artifact phase 3 hunts for.

    This is NOT phishing. The app:
      - is named "LAB-*" so it is unmistakably a test object,
      - lives in a tenant the operator owns,
      - harvests no credentials, targets no other user, and hosts no lure content.
    It is a controlled way to generate a detectable event, nothing more.

    All Graph calls go through Invoke-MgGraphRequest (REST), so only
    Microsoft.Graph.Authentication is required. Supports -WhatIf and -Remove (rollback).

.PARAMETER AppName
    Display name of the lab app. Must start with 'LAB-' (guardrail against touching real apps).

.PARAMETER RequestedScopes
    Delegated Microsoft Graph scopes to request. Default mimics a lure: read mail + a
    refresh token that outlives the session.

.PARAMETER RedirectUri
    OAuth redirect. Defaults to a localhost placeholder (nothing actually listens there;
    the consent event fires before the redirect completes).

.PARAMETER Remove
    Rollback: delete the lab app registration and its service principal.

.EXAMPLE
    .\new-lab-consent-app.ps1 -WhatIf
    Show what would be created without touching the tenant.

.EXAMPLE
    .\new-lab-consent-app.ps1
    Create the lab app + SP and print the consent URL to paste into a browser.

.EXAMPLE
    .\new-lab-consent-app.ps1 -Remove
    Tear the lab app back down when the lab is finished.

.NOTES
    Graph scope: Application.ReadWrite.All - create/delete the app registration + SP.
                 (Write scope, justified: this phase intentionally creates an app object.)
#>

[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Medium')]
param(
    [ValidatePattern('^LAB-')]
    [string]$AppName = 'LAB-ConsentPhish-Target',

    [string[]]$RequestedScopes = @('User.Read','Mail.Read','offline_access','openid'),

    [string]$RedirectUri = 'https://localhost/consent-lab',

    [switch]$Remove
)

$ErrorActionPreference = 'Stop'
$GraphBase = 'https://graph.microsoft.com/v1.0'
$GraphAppId = '00000003-0000-0000-c000-000000000000'   # Microsoft Graph resource

function Write-Log {
    param([string]$Msg, [string]$Level = 'INFO')
    $c = @{ INFO='Gray'; OK='Green'; WARN='Yellow'; HIGH='Red' }[$Level]; if (-not $c) { $c = 'Gray' }
    Write-Host ("[{0}] {1}" -f $Level, $Msg) -ForegroundColor $c
}

try {
    Connect-MgGraph -Scopes 'Application.ReadWrite.All' -NoWelcome
    $ctx = Get-MgContext
    Write-Log ("Connected. Tenant {0} as {1}" -f $ctx.TenantId, $ctx.Account) 'OK'
}
catch { Write-Log "Graph connect failed: $($_.Exception.Message)" 'HIGH'; throw }

# --------------------------------------------------------------------- REMOVE
if ($Remove) {
    $existing = (Invoke-MgGraphRequest -Method GET -Uri "$GraphBase/applications?`$filter=displayName eq '$AppName'" -OutputType PSObject).value
    if (-not $existing) { Write-Log "No app named '$AppName' found - nothing to remove." 'WARN'; Disconnect-MgGraph *> $null; return }
    foreach ($app in $existing) {
        if ($PSCmdlet.ShouldProcess($AppName, 'DELETE app registration + service principal')) {
            $sp = (Invoke-MgGraphRequest -Method GET -Uri "$GraphBase/servicePrincipals?`$filter=appId eq '$($app.appId)'" -OutputType PSObject).value
            foreach ($s in $sp) { Invoke-MgGraphRequest -Method DELETE -Uri "$GraphBase/servicePrincipals/$($s.id)" | Out-Null }
            Invoke-MgGraphRequest -Method DELETE -Uri "$GraphBase/applications/$($app.id)" | Out-Null
            Write-Log "Removed '$AppName' (app + SP)." 'OK'
        }
    }
    Disconnect-MgGraph *> $null
    return
}

# --------------------------------------------------------------- CREATE
# Resolve requested scope NAMES to their delegated permission IDs from the Graph SP.
$graphSp = (Invoke-MgGraphRequest -Method GET -Uri "$GraphBase/servicePrincipals?`$filter=appId eq '$GraphAppId'&`$select=id,appId,oauth2PermissionScopes" -OutputType PSObject).value[0]
$resourceAccess = foreach ($name in $RequestedScopes) {
    $scopeObj = $graphSp.oauth2PermissionScopes | Where-Object { $_.value -eq $name }
    if (-not $scopeObj) { Write-Log "Scope '$name' not found on Microsoft Graph - skipping." 'WARN'; continue }
    @{ id = $scopeObj.id; type = 'Scope' }
}
if (-not $resourceAccess) { throw 'No valid scopes resolved; aborting.' }

$body = @{
    displayName            = $AppName
    signInAudience         = 'AzureADMultipleOrgs'          # multi-tenant: the shape a real lure uses
    web                    = @{ redirectUris = @($RedirectUri) }
    requiredResourceAccess = @(@{ resourceAppId = $GraphAppId; resourceAccess = @($resourceAccess) })
}

if ($PSCmdlet.ShouldProcess($AppName, "CREATE multi-tenant app requesting: $($RequestedScopes -join ', ')")) {
    $app = Invoke-MgGraphRequest -Method POST -Uri "$GraphBase/applications" -Body ($body | ConvertTo-Json -Depth 6) -OutputType PSObject
    Write-Log ("Created app '{0}' (appId {1})" -f $app.displayName, $app.appId) 'OK'

    $sp = Invoke-MgGraphRequest -Method POST -Uri "$GraphBase/servicePrincipals" -Body (@{ appId = $app.appId } | ConvertTo-Json) -OutputType PSObject
    Write-Log ("Created service principal (objectId {0})" -f $sp.id) 'OK'

    # Build the consent URL. Graph delegated scopes must be resource-qualified for the v2.0 endpoint.
    $scopeParam = (($RequestedScopes | Where-Object { $_ -notin 'openid','offline_access','profile' } |
                   ForEach-Object { "https://graph.microsoft.com/$_" }) + ($RequestedScopes | Where-Object { $_ -in 'openid','offline_access','profile' })) -join ' '
    $enc = [System.Uri]::EscapeDataString($scopeParam)
    $encRedir = [System.Uri]::EscapeDataString($RedirectUri)
    $consentUrl = "https://login.microsoftonline.com/$($ctx.TenantId)/oauth2/v2.0/authorize?client_id=$($app.appId)&response_type=code&redirect_uri=$encRedir&response_mode=query&scope=$enc&prompt=consent&state=consentlab"

    Write-Log '' 
    Write-Log '=== NEXT: trigger the consent event ===' 'WARN'
    Write-Log 'Paste this URL into a browser signed in to THIS tenant, then click Accept:' 'WARN'
    Write-Host ''
    Write-Host $consentUrl -ForegroundColor Cyan
    Write-Host ''
    Write-Log 'The redirect to https://localhost will show a browser error - that is expected.' 'INFO'
    Write-Log 'The "Consent to application" audit event fires BEFORE the redirect, so the event is captured regardless.' 'INFO'
    Write-Log 'Then run the phase-3 detection query. Roll back later with:  .\new-lab-consent-app.ps1 -Remove' 'INFO'
}

Disconnect-MgGraph *> $null
