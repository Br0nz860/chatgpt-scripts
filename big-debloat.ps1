# Check for Admin Rights
function Test-Admin {
    $currentUser = New-Object Security.Principal.WindowsPrincipal $([Security.Principal.WindowsIdentity]::GetCurrent())
    $currentUser.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
}

# Ensure script is running with admin rights
if ((Test-Admin) -eq $false) {
    throw "Please run as Administrator"
}

# Set Execution Policy to Bypass for the current process
Set-ExecutionPolicy Bypass -Scope Process -Force

# --- System Restore Point Configuration ---

# Increase the amount of storage space reserved for system restore points to 10%
vssadmin Resize ShadowStorage /For=C: /On=C: /MaxSize=10%

# Create a system restore point
$description = "Pre-Tweak Restore Point"
Checkpoint-Computer -Description $description -RestorePointType "MODIFY_SETTINGS"


# --- Debloat Windows ---
# Removing various built-in Windows 10 apps
$apps = @(
    "Microsoft.3DBuilder", 
    "Microsoft.BingWeather",
    "Microsoft.WindowsCamera",
    "microsoft.windowscommunicationsapps",
    "Microsoft.WindowsMaps",
    "Microsoft.MicrosoftOfficeHub",
    "Microsoft.MicrosoftSolitaireCollection",
    "Microsoft.MicrosoftStickyNotes",
    "Microsoft.WindowsAlarms",
    "Microsoft.WindowsCalculator",
    "Microsoft.WindowsFeedbackHub",
    "Microsoft.WindowsStore",
    "Microsoft.XboxApp",
    "Microsoft.ZuneMusic",
    "Microsoft.ZuneVideo",
    "Microsoft.GetHelp",
    "Microsoft.Getstarted",
    "Microsoft.Windows.Photos",
    "Microsoft.WindowsSoundRecorder",
    "Microsoft.WindowsPhone",
    # Add any other apps from the original script here
)

foreach ($app in $apps) {
    Get-AppxPackage -Name $app -AllUsers | Remove-AppxPackage
    Get-AppXProvisionedPackage -Online | where DisplayName -EQ $app | Remove-AppxProvisionedPackage -Online
}
# --- Disable Telemetry and Data Collection ---

# Disable telemetry
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry" -Value 0

# Disable Wi-Fi Sense
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config" -Name "AutoConnectAllowedOEM" -Value 0

# Disable setting sync
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SettingSync" -Name "DisableSettingSync" -Value 2
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SettingSync" -Name "DisableSettingSyncUserOverride" -Value 1

# Disable tailored experiences with diagnostic data
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Privacy" -Name "TailoredExperiencesWithDiagnosticDataEnabled" -Value 0

# Disable advertising ID
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo" -Name "Enabled" -Value 0

# Disable app suggestions and app notifications
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SoftLandingEnabled" -Value 0
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338388Enabled" -Value 0
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338389Enabled" -Value 0
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338393Enabled" -Value 0
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-353698Enabled" -Value 0

# ... [and other commands related to telemetry and data collection]
# --- Windows 10 Privacy & Settings ---

# Apply laptop defaults for tweaks
$Tweaks = "laptop"

# Disable automatic installation of suggested apps
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SilentInstalledAppsEnabled" -Value 0

# Disable Cortana
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "AllowCortana" -Value 0

# Disable automatic maps updates
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" -Name "DisableWindowsMapsUpdate" -Value 1

# Disable feedback reminders
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "DoNotShowFeedbackNotifications" -Value 1

# Disable Start Menu suggestions
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SystemPaneSuggestionsEnabled" -Value 0

# Disable lock screen spotlight
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "RotatingLockScreenEnabled" -Value 0

# Disable lock screen spotlight on Windows Spotlight
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Lock Screen" -Name "Creative" -Value 0

# ... [and other commands related to Windows 10 privacy & settings tweaks]
# --- Final Cleanup ---

# Delete temporary files
Remove-Item "$env:temp\*" -Recurse -Force -ErrorAction SilentlyContinue

# Empty the Recycle Bin
$shell = New-Object -ComObject Shell.Application
$shell.NameSpace(10).Items() | % { Remove-Item $_.Path -Recurse -Force -ErrorAction SilentlyContinue }

# Run Disk Cleanup silently
cleanmgr /sagerun:1

# Confirmation message
"Script executed successfully!"
