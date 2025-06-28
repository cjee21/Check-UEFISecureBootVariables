# Created by github.com/cjee21 
# License: MIT

# Check for admin
Write-Host "Checking for Administrator permission..."
if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Warning "Insufficient permissions to run this script. Please run as administrator."
    Break
} else {
    Write-Host "Running as administrator - continuing execution..."
}

# Check for Secure Boot status
Write-Host "Checking Secure Boot status..."
$SecureBootStatus = Confirm-SecureBootUEFI
if ($SecureBootStatus -eq $true) {
    Write-Host "Secure Boot status: Enabled - continuing execution...`n"
} elseif ($SecureBootStatus -eq $false) {
    Write-Warning "Secure Boot status: Disable - continuing execution...`n"
} else {
    Write-Warning "Secure Boot status: Not supported. The computer does not support Secure Boot or is a BIOS (non-UEFI) computer."
    Break
}

# Print computer info
Get-Date -Format 'dd MMMM yyyy'
$computer = Get-WmiObject Win32_ComputerSystem
$bios = Get-WmiObject Win32_BIOS
"Manufacturer: " + $computer.Manufacturer
"Model: " + $computer.Model
$biosinfo = $bios.Manufacturer , $bios.Name , $bios.SMBIOSBIOSVersion , $bios.Version -join ", "
"BIOS: " + $biosinfo
$v = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
"Windows version: {0} (Build {1}.{2}) `n" -f $v.DisplayVersion, $v.CurrentBuildNumber, $v.UBR

$bold = "$([char]0x1b)[1m"
$reset = "$([char]0x1b)[0m"
$check = "$([char]0x1b)[92m$([char]8730)$reset"
$cross =  "$([char]0x1b)[91mX$reset"

# Check whether it is ARM architecture
$IsArm = $false
try {
    $arch = (Get-WmiObject Win32_Processor -ErrorAction Stop).Architecture
    # 0 = x86, 9 = x64, 5 = ARM, 12 = ARM64
    if ($arch -eq 5 -or $arch -eq 12) {
        $IsArm = $true
        Write-Host "Detected Windows on ARM architecture!`n"
    }
} catch {
    Write-Warning "Unable to determine CPU architecture, proceeding with defaults (x64).`n"
}

function Show-UEFICertIsPresent {
    param (
        [Parameter(Mandatory)]
        [string]$SecureBootUEFIVar,
        [Parameter(Mandatory)]
        [string]$CertName
    )
    try {
        if ([System.Text.Encoding]::ASCII.GetString((Get-SecureBootUEFI $SecureBootUEFIVar -ErrorAction Stop).bytes) -match $CertName) {
            $revoked = $false
            try {
                $revoked = [System.Text.Encoding]::ASCII.GetString((Get-SecureBootUEFI dbx -ErrorAction Stop).bytes) -match $CertName
            } catch {
                $revoked = $false
            }
            Write-Host "$check $CertName (revoked: $revoked)"
        } else {
            Write-Host "$cross $CertName"
        }
    } catch {
        Write-Warning "Failed to query UEFI variable '$SecureBootUEFIVar' for cert '$CertName'"
    }
}

Write-Host $bold'Current UEFI KEK'$reset
Show-UEFICertIsPresent -SecureBootUEFIVar KEK -CertName 'Microsoft Corporation KEK CA 2011'
Show-UEFICertIsPresent -SecureBootUEFIVar KEK -CertName 'Microsoft Corporation KEK 2K CA 2023'

Write-Host ""
Write-Host $bold'Default UEFI KEK'$reset
if ($IsArm) {
    Write-Warning "Some ARM-based Windows devices can't retrieve default UEFI variables."
}
Show-UEFICertIsPresent -SecureBootUEFIVar KEKDefault -CertName 'Microsoft Corporation KEK CA 2011'
Show-UEFICertIsPresent -SecureBootUEFIVar KEKDefault -CertName 'Microsoft Corporation KEK 2K CA 2023'

Write-Host ""
Write-Host $bold'Current UEFI DB'$reset
Show-UEFICertIsPresent -SecureBootUEFIVar db -CertName 'Microsoft Windows Production PCA 2011'
Show-UEFICertIsPresent -SecureBootUEFIVar db -CertName 'Microsoft Corporation UEFI CA 2011'
Show-UEFICertIsPresent -SecureBootUEFIVar db -CertName 'Windows UEFI CA 2023'
Show-UEFICertIsPresent -SecureBootUEFIVar db -CertName 'Microsoft UEFI CA 2023'
Show-UEFICertIsPresent -SecureBootUEFIVar db -CertName 'Microsoft Option ROM UEFI CA 2023'

Write-Host ""
Write-Host $bold'Default UEFI DB'$reset
if ($IsArm) {
    Write-Warning "Some ARM-based Windows devices can't retrieve default UEFI variables."
}
Show-UEFICertIsPresent -SecureBootUEFIVar dbDefault -CertName 'Microsoft Windows Production PCA 2011'
Show-UEFICertIsPresent -SecureBootUEFIVar dbDefault -CertName 'Microsoft Corporation UEFI CA 2011'
Show-UEFICertIsPresent -SecureBootUEFIVar dbDefault -CertName 'Windows UEFI CA 2023'
Show-UEFICertIsPresent -SecureBootUEFIVar dbDefault -CertName 'Microsoft UEFI CA 2023'
Show-UEFICertIsPresent -SecureBootUEFIVar dbDefault -CertName 'Microsoft Option ROM UEFI CA 2023'

Write-Host ""
Write-Host $bold'Current UEFI DBX (only the latest one is needed to be secure)'$reset

function Show-CheckDBX {
    param(
        [Parameter(Mandatory)][string]$Label,
        [Parameter(Mandatory)][string]$File
    )
    Write-Host "$Label : " -NoNewline
    try {
        $oldPreference = $ErrorActionPreference
        $ErrorActionPreference = 'Stop'
        & "$PSScriptRoot\Check-Dbx-Simplified.ps1" "$File"
        $ErrorActionPreference = $oldPreference
    } catch {
        Write-Host "FAIL: Check DBX failed" -ForegroundColor Red
    }
}

if ($IsArm) {
    Show-CheckDBX "2025-02-25 (v1.4.0)" "$PSScriptRoot\arm64_DBXUpdate_02252025.bin"
} else {
    Show-CheckDBX "2023-03-14         " "$PSScriptRoot\x64_DBXUpdate_03142023.bin"
    Show-CheckDBX "2023-05-09         " "$PSScriptRoot\x64_DBXUpdate_05092023.bin"
    Show-CheckDBX "2025-01-14 (v1.3.1)" "$PSScriptRoot\x64_DBXUpdate_01142025.bin"
    Show-CheckDBX "2025-06-11 (v1.5.0)" "$PSScriptRoot\x64_DBXUpdate_06112025.bin"
}
