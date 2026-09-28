<#
.TITLE
Upgrade to Windows 11 25H2 Using Microsoft Intune Proactive Remediation Detection Script

.SYNOPSIS
Detects Windows devices eligible for an upgrade to Windows 11 25H2 and triggers Intune Proactive Remediation when remediation is required.

.DESCRIPTION
This detection script is designed for use with Microsoft Intune Proactive Remediations to identify Windows devices that are eligible for an upgrade to Windows 11 25H2.

The script performs the following actions:

- Verifies that Windows Autopilot Enrollment Status Page (ESP) is not currently running.
- Collects operating system build information.
- Retrieves the latest Windows Update scan timestamp.
- Checks for the presence of the Windows PC Health Check application.
- Validates Windows 11 hardware requirements including:
  - TPM 2.0
  - Secure Boot
  - 64-bit processor architecture
  - Minimum 4 GB RAM
  - Minimum available disk space (default: 45 GB)
- Creates the registry value HKCU:\Software\Microsoft\PCHC\UpgradeEligibility=1 to bypass the Windows PC Health Check eligibility verification where applicable.
- Determines whether the device requires remediation to upgrade to Windows 11 25H2.
- Returns an exit code compatible with Microsoft Intune Proactive Remediation:
  - Exit -1 = Remediation required
  - Exit 0 = No remediation required
  - Exit 1 = Detection failed or device is currently in Autopilot ESP

The script writes detailed operational logging to:

C:\ProgramData\Microsoft\IntuneManagementExtension\Logs\Upgrade_To_Win11_25H2.log

.AUTHOR
Hank Stephen

.VERSION
1.0

.CHANGELOG
Version 1.0
- Initial release.
- Added Windows 11 25H2 build detection.
- Added TPM 2.0 validation.
- Added Secure Boot validation.
- Added CPU architecture validation.
- Added RAM requirement validation.
- Added disk space validation.
- Added Windows PC Health Check detection.
- Added registry creation for UpgradeEligibility.
- Added Intune-compatible exit codes.
- Added detailed logging support.
- Added Autopilot ESP detection safeguard.

.LASTUPDATE
2026-09-22

.EXAMPLE
Scenario 1: Intune Proactive Remediation Detection

1. Upload the script as the Detection Script in Intune.
2. Assign the remediation package to Windows 11 23H2 or 24H2 devices.
3. Devices meeting Windows 11 requirements but not currently on Windows 11 25H2 return Exit -1.
4. Intune automatically launches the remediation script to begin the upgrade process.

.EXAMPLE
Scenario 2: Manual Execution

PowerShell.exe -ExecutionPolicy Bypass -File .\Detect-Win11-25H2Upgrade.ps1

Expected Results:
- Exit -1 = Device eligible for upgrade and remediation required.
- Exit 0 = Device already compliant or ineligible.
- Exit 1 = Detection error or Autopilot ESP is active.

.NOTES
Purpose:
Used as the Detection Script component of an Intune Proactive Remediation package to automate Windows 11 25H2 readiness validation and upgrade initiation.

Supported Operating Systems:
- Windows 11 23H2
- Windows 11 24H2

Target Upgrade Version:
- Windows 11 25H2 (Build 26200)

Log File:
C:\ProgramData\Microsoft\IntuneManagementExtension\Logs\Upgrade_To_Win11_25H2.log

Registry Information:
HKCU:\Software\Microsoft\PCHC
Value Name : UpgradeEligibility
Value Type : DWORD
Value Data : 1

Exit Codes:
-1 = Remediation required
 0 = Compliant / No action required
 1 = Detection failure or ESP active

Deployment Method:
Microsoft Intune Proactive Remediations

Prerequisites:
- TPM 2.0 enabled
- Secure Boot enabled
- 64-bit processor
- Minimum 4 GB RAM
- Minimum 45 GB free disk space
- Intune Management Extension installed

#>

#========================User Input Section========

$DiskSpace = "45"

#==================================================


$error.clear() ## this is the clear error history 
clear
#Set-ExecutionPolicy -ExecutionPolicy 'ByPass' -Force
$ErrorActionPreference = 'SilentlyContinue'

# Initialize Logging
$LogPath = "C:\ProgramData\Microsoft\IntuneManagementExtension\Logs\Upgrade_To_Win11_25H2.log"         
Function Write-Log {
    Param([string]$Message)
    "$((Get-Date).ToString('yyyy-MM-dd HH:mm:ss')) - $Message" | Out-File -FilePath $LogPath  -Append
}
Write-Log "====================== Upgrading Windows 11 23H2 or 24H2 to Windows 11 25H2 Using Intune Proactive Detection Script $(Get-Date -Format 'yyyy/MM/dd') ==================="

$HostName = hostname
# Check if ESP is running
$ESP = Get-Process -ProcessName CloudExperienceHostBroker -ErrorAction SilentlyContinue
If ($ESP) {
    #Write-Host "Windows Autopilot ESP Running"
    Write-Log "Windows Autopilot ESP Running"
    Exit 1 
     }
Else {
    #Write-Host "Windows Autopilot ESP Not Running"
    Write-Log "Windows Autopilot ESP Not Running"
    
     }

Write-Log "Checking Machine :- $HostName OS Version"
$OSBuild = ([System.Environment]::OSVersion.Version).Build

IF (!($OSBuild)) {
    Write-Log 'Failed to Find Build Info'
    Exit 1
} else{
    Write-Log "Machine :- $HostName OS Version is $OSBuild"
}
$CheckForUpdateA = Get-WinEvent -FilterHashtable @{
    LogName   = 'Microsoft-Windows-WindowsUpdateClient/Operational'
 }
$TopA = $CheckForUpdateA | Select-Object -First 1

Write-Log "Last Check for Update date and time is:- $($TopA.TimeCreated)"

#Checking Windows PC Health Check installation status

$AppName = "Windows PC Health Check"

$App = Get-WmiObject -Class Win32_Product | Where-Object { $_.Name -eq $AppNmae } 

if ($App.IdentifyingNumber -eq $null)
{
    Write-Log "'$AppName' application not installed"
}
else
{
    Write-Log "'$AppName' application already installed"
}

Write-Log "Checking if the system meets Windows 11 hardware requirements..."

# Check TPM version
$tpmInfo = tpmtool getdeviceinformation
$tpmVersion = ($tpmInfo | Where-Object { $_ -match "TPM Version" }) -replace ".*TPM Version:\s*", ""
if ($tpmVersion) {
    if ($tpmVersion -ge "2.0") {
        Write-Log "TPM version 2.0 is present.OK"
    } else {
        Write-Log "TPM version is below 2.0 — required for Windows 11."
        
    }
} else {
    Write-Log "No TPM detected on this system."
    
}

# Check Secure Boot
$firmwareInfo = Confirm-SecureBootUEFI

if ($firmwareInfo -eq "True") {
    Write-Log "Secure Boot is Enable.OK"
} else {
    Write-Log "Secure Boot is disabled — this is a Windows 11 requirement."
    }

# Check processor architecture
$cpuInfo = Get-WmiObject -Class Win32_Processor
if ($cpuInfo) {
    if ($cpuInfo.Architecture -eq 9) {
        Write-Log "Processor is 64-bit.OK."
    } else {
        Write-Log "Processor is not 64-bit — Windows 11 needs a 64-bit CPU."
     }
}

# Check RAM
$systemSpecs = Get-WmiObject -Class Win32_ComputerSystem
if ($systemSpecs.TotalPhysicalMemory -ge 4GB) {
    Write-Log "System has 4GB or more of RAM.OK"
} else {
    Write-Log "RAM is below 4GB — not sufficient for Windows 11."
 }

# Check storage space
$localDrives = Get-WmiObject -Class Win32_LogicalDisk | Where-Object { $_.DriveType -eq 3 }
$availableSpaceGB = [math]::round($localDrives.FreeSpace / 1GB, 2)
if ($availableSpaceGB -ge $DiskSpace) {
    Write-Log "Available disk space is at least $DiskSpace GB.OK"
} else {
    Write-Log "Not enough disk space — Windows 11 needs a minimum of $DiskSpace GB."
}


# Check if system is not on Windows 11 25H2 and meets hardware requirements
if ($OSBuild -lt 26200 -and `
    $tpmVersion -ge "2.0" -and `
    $firmwareInfo -eq "true" -and `
    $cpuInfo.Architecture -eq 9 -and `
    $systemSpecs.TotalPhysicalMemory -ge 4GB -and `
    $availableSpaceGB -ge $DiskSpace) 
{
##Setting Registery to skip Windows PC Health Check status
         Write-log "Setting Registery to skip "PC Health Check tool" to check Upgrade Eligibility Status"
         # Define the registry path
                $regPath = "HKCU:\Software\Microsoft\PCHC"

                    # Create the key if it doesn't exist
                        if (-not (Test-Path $regPath)) {
                         New-Item -Path $regPath -Force | Out-Null
                            }

                            # Set the DWORD value
                    Set-ItemProperty -Path $regPath -Name "UpgradeEligibility" -Value 1 -Type DWord

                    # Confirm the change
                    $Reg = Get-ItemProperty -Path $regPath | Select-Object UpgradeEligibility
                    Write-log "Preparing the device for a Windows 11 upgrade by creating a registry entry to skip the 'PC Health Check Tool' eligibility checks. This is done by creating the registry path HKCU:\Software\Microsoft\PCHC and setting the UpgradeEligibility value (DWORD) to 1."

    Write-Log 'System is not on Windows 11 25H2 and meets hardware requirements. Initiating Proactive Remediation...'
    Write-Host 'System is not on Windows 11 25H2 and meets hardware requirements. Initiating Proactive Remediation...'
    Exit -1
}
elseif ($OSBuild-lt 26200) {
    Write-Log 'System is not on Windows 11 25H2 but does not meet hardware requirements. Skipping upgrade.'
    Write-Host 'System is not on Windows 11 25H2 but does not meet hardware requirements. Skipping upgrade.'
    Exit 0
}
else {
    Write-Log 'System is already on Windows 11 25H2. No remediation needed.'
    Write-Host 'System is already on Windows 11 25H2. No remediation needed.'
    Exit 0
}

