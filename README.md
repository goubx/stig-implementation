# STIG-Implementation

## Initial scan results 

The initial scan found that 147 audits failed out of 263.

The failed plugin i will be remediating is:

> WN11-CC-000280 - Remote Desktop Services must always prompt a client for passwords upon connection.

[image]

 This is important because if an RDP connection was ever successful, to ensure integrity, a password must be entered correctly.

 ## Research 

 Upon doing research, I found the plugin ID on STIGviewer.com

 [image]

 The manual solution provided here is that I must:

 ```
Check Text (C-253404r1051052_chk)
If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\

Value Name: fPromptForPassword

Value Type: REG_DWORD
Value: 1
Fix Text (F-56807r829295_fix)
Configure the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> Remote Desktop Services >> Remote Desktop Session Host >> Security >> "Always prompt for password upon connection" to "Enabled".
```

## Manual remediation 

I am now going to go into the VM, and being the manual remediation, after doing so, I will run another scan to confirm that the remediation was successful.

First, I have to enter the registry editor to see if prompting for the password exists by
1. How to Check (The Audit)

```
* Opening the Registry Editor.

* Navigate to the following path: HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\

* Look for a registry value named fPromptForPassword.

* Analyze the result:

* If fPromptForPassword exists, its type is REG_DWORD, and its value is 1, the system is compliant (Secure).

* If the value is 0, or if the fPromptForPassword key doesn't exist at all, this is a finding (Vulnerable).

```

[image]

As you can see above, this is a confirmed vulnerability within the computer because it has not been set up.

Now I will move on to group policy to enable the password upon RDP connection.

[image]

As you can see above, I have enabled the settings for:

```
Always prompt for password upon connection.
```

And now, when I go back to the Registry Editor and look at the settings within Terminal Services, there is now a registry value for prompt for password.

## Now I will commence the second scan to confirm the manual remediation was successful

[image]

As you can see above, the scan result shows that the plugin WN11-CC-000280 has now passed the audit.

I will now begin the removal of the manual remediation and rescan to confirm this, so I can begin the pragmatic remediation.

[image]

As you can see above, the manual remediation was successfully removed, and now the scan is showing a failed audit.


## Pragmatic Remediation

Below is a PowerShell script I curated through claude, that I plan to run that will enable the prompt for a password upon successful connection through RDP

```powershell

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

```
[image]

I have run this in PowerShell ISE and will confirm with a scan to confirm the pragmatic solution was successful.

## Scan results after pragmatic remediation 

[image]

As you can see above, the PowerShell script was successfully executed, resulting in a pass for the audit.
