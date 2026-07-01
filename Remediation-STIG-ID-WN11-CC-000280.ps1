<#
.SYNOPSIS
    This PowerShell script ensures Remote Desktop Services always prompts a client for a password upon connection.
.NOTES
    Author          : Mohamed Yagoub
    LinkedIn        : linkedin.com/in/mohamed-yagoub/
    GitHub          : github.com/goubx
    Date Created    : 2026-06-29
    Last Modified   : 2026-06-29
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN11-CC-000280
    Documentation   : https://stigaview.com/products/win11/v2r7/WN11-CC-000280/
.TESTED ON
    Date(s) Tested  : 
    Tested By       : 
    Systems Tested  : 
    PowerShell Ver. : 
.USAGE
    Run this script in an elevated PowerShell session on the target Windows 11 host.
    After execution, run 'gpupdate /force' and rescan with Tenable Nessus to validate.
    Example syntax:
    PS C:\> .\__remediation_template(STIG-ID-WN11-CC-000280).ps1
#>

# STIG WN11-CC-000280: Remote Desktop Services must always prompt a client for passwords upon connection
$RegPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
$Name    = 'fPromptForPassword'
$Desired = 1   # 1 = Enabled (always prompt for password on RDP connection)

# Create the registry path if it does not exist
if (-not (Test-Path $RegPath)) {
    New-Item -Path $RegPath -Force | Out-Null
    Write-Host "Created registry path: $RegPath"
}

# Apply the fPromptForPassword value
Set-ItemProperty -Path $RegPath -Name $Name -Value $Desired -Type DWord -Force
Write-Host "Set $Name to $Desired in $RegPath"

# Verify
$Current = (Get-ItemProperty -Path $RegPath -Name $Name).$Name
if ($Current -eq $Desired) {
    Write-Host "Compliant: $Name = $Current"
} else {
    Write-Warning "Non-compliant: $Name = $Current, expected $Desired"
}
