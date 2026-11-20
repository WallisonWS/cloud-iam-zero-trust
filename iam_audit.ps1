<#
.SYNOPSIS
    Multi-Cloud IAM Zero-Trust Auditor for Windows PowerShell (Azure / Entra ID, GCP & AWS)
.EXAMPLE
    .\iam_audit.ps1 -PolicyJson '{"actions":["*","Microsoft.Authorization/roleAssignments/write"],"assignableScopes":["/"]}'
#>
param(
    [Parameter(Mandatory = $false)]
    [string]$PolicyJson,
    [Parameter(Mandatory = $false)]
    [string]$Path
)

if ($Path -and (Test-Path $Path)) {
    $PolicyJson = Get-Content -Path $Path -Raw
}
if (-not $PolicyJson) {
    throw "Provide either -PolicyJson or -Path to an IAM JSON policy file."
}

$rules = @(
    @{ Id="GCP-IAM-001"; Cloud="GCP"; Title="Primitive Owner/Editor Role"; Weight=30; Rx='"roles/(owner|editor)"' },
    @{ Id="GCP-IAM-002"; Cloud="GCP"; Title="Service Account Impersonation (actAs)"; Weight=25; Rx='iam\.serviceAccounts\.(actAs|getAccessToken|signBlob|implicitDelegation)' },
    @{ Id="GCP-IAM-003"; Cloud="GCP"; Title="Public Binding (allUsers)"; Weight=35; Rx='"(allUsers|allAuthenticatedUsers)"' },
    @{ Id="AZURE-IAM-001"; Cloud="Azure"; Title="Wildcard Action Permission (*)"; Weight=35; Rx='"actions"\s*:\s*\[[^\]]*"\*"' },
    @{ Id="AZURE-IAM-002"; Cloud="Azure"; Title="Role Assignment Write Escalation"; Weight=30; Rx='Microsoft\.Authorization/roleAssignments/write' },
    @{ Id="AZURE-IAM-003"; Cloud="Azure"; Title="Root Tenant/Subscription Scope (/)"; Weight=20; Rx='"assignableScopes"\s*:\s*\[[^\]]*"/"' },
    @{ Id="AWS-IAM-001"; Cloud="AWS"; Title="Wildcard Action (*)"; Weight=35; Rx='"Action"\s*:\s*("\*"|\[\s*"\*"\s*\])' },
    @{ Id="AWS-IAM-002"; Cloud="AWS"; Title="IAM PassRole / AttachRolePolicy Escalation"; Weight=30; Rx='iam:(PassRole|CreatePolicyVersion|AttachRolePolicy|PutUserPolicy)' }
)

$hits = @()
$penalty = 0
foreach ($r in $rules) {
    if ($PolicyJson -match $r.Rx) {
        $penalty += $r.Weight
        $hits += [ordered]@{ rule_id = $r.Id; cloud = $r.Cloud; title = $r.Title; severity = if ($r.Weight -ge 30) { "CRITICAL" } else { "HIGH" } }
    }
}
$score = [Math]::Max(0, 100 - $penalty)
[ordered]@{
    zero_trust_score = $score
    grade            = if ($score -ge 90) { "A" } elseif ($score -ge 70) { "B" } elseif ($score -ge 50) { "C" } else { "F" }
    findings         = $hits
} | ConvertTo-Json -Depth 4
