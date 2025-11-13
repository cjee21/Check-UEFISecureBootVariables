# Created by github.com/cjee21 
# License: MIT

# Check for admin
Write-Host "Checking for Administrator permission..."
if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Warning "Insufficient permissions to run this script. Please run as administrator."
    Break
} else {
    Write-Host "Running as administrator - continuing execution...`n"
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
"Windows version: {0} (Build {1}.{2})`n" -f $v.DisplayVersion, $v.CurrentBuildNumber, $v.UBR

# Check for Secure Boot status
Write-Host "Secure Boot status: " -NoNewLine
try {
    $status = Confirm-SecureBootUEFI -ErrorAction Stop
    if ($status -eq $True) {
        Write-Host "$([char]0x1b)[92mEnabled$([char]0x1b)[0m`n"
    }
    elseif ($status -eq $False) {
        Write-Host "$([char]0x1b)[91mDisabled$([char]0x1b)[0m`n"
    }
}
catch [System.PlatformNotSupportedException] {
    Write-Host "$([char]0x1b)[91mNot available$([char]0x1b)[0m`n"
    Break
}
catch {
    Write-Host "$([char]0x1b)[91mUnknown$([char]0x1b)[0m`n"
    Break
}

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

Import-Module "$PSScriptRoot\Get-UEFIDatabaseSignatures.ps1"

Write-Host $bold'Current UEFI PK'$reset
try {
    $pk = Get-SecureBootUEFI -Name pk | Get-UEFIDatabaseSignatures
    $pk.SignatureList.SignatureData.Subject | ForEach-Object {
        $pk_name = [regex]::Match($_, 'CN=([^,]+)').Groups[1].Value
        Write-Host "$check $pk_name"
    }
} catch {
    Write-Warning "Failed to query UEFI variable PK"
}

Write-Host ""
Write-Host $bold'Default UEFI PK'$reset
if ($IsArm) {
    Write-Warning "Some ARM-based Windows devices can't retrieve default UEFI variables."
}
try {
    $pk_default = Get-SecureBootUEFI -Name PKDefault | Get-UEFIDatabaseSignatures
    $pk_default.SignatureList.SignatureData.Subject | ForEach-Object {
        $pk_name = [regex]::Match($_, 'CN=([^,]+)').Groups[1].Value
        Write-Host "$check $pk_name"
    }
} catch {
    Write-Warning "Failed to query UEFI variable PKDefault"
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

function Show-UEFICertOthers {
    param (
        [Parameter(Mandatory)]
        [string]$SecureBootUEFIVar,
        [Parameter(Mandatory)]
        [Array]$KnownCerts
    )
    try {
        $certs = Get-SecureBootUEFI -Name $SecureBootUEFIVar | Get-UEFIDatabaseSignatures
        $cert_names = @()
        $certs.SignatureList.SignatureData.Subject | ForEach-Object {
            $cert_names += [regex]::Match($_, 'CN=([^,]+)').Groups[1].Value
        }
        $cert_names | ForEach-Object {
            if ($KnownCerts -notcontains $_) {
                $revoked = $false
                try {
                    $revoked = [System.Text.Encoding]::ASCII.GetString((Get-SecureBootUEFI dbx -ErrorAction Stop).bytes) -match $_
                } catch {
                    $revoked = $false
                }
                Write-Host "$check $_ (revoked: $revoked)"
            }
        }
    } catch {
        Write-Warning "Failed to query UEFI variable '$SecureBootUEFIVar'"
    }
}

$KEKCerts = @(
    'Microsoft Corporation KEK CA 2011'
    'Microsoft Corporation KEK 2K CA 2023'
)

Write-Host ""
Write-Host $bold'Current UEFI KEK'$reset
$KEKCerts | ForEach-Object {
    Show-UEFICertIsPresent -SecureBootUEFIVar kek -CertName $_
}
Show-UEFICertOthers -SecureBootUEFIVar kek -KnownCerts $KEKCerts

Write-Host ""
Write-Host $bold'Default UEFI KEK'$reset
if ($IsArm) {
    Write-Warning "Some ARM-based Windows devices can't retrieve default UEFI variables."
}
$KEKCerts | ForEach-Object {
    Show-UEFICertIsPresent -SecureBootUEFIVar KEKDefault -CertName $_
}
Show-UEFICertOthers -SecureBootUEFIVar KEKDefault -KnownCerts $KEKCerts

$DBCerts = @(
    'Microsoft Windows Production PCA 2011'
    'Microsoft Corporation UEFI CA 2011'
    'Windows UEFI CA 2023'
    'Microsoft UEFI CA 2023'
    'Microsoft Option ROM UEFI CA 2023'
)

Write-Host ""
Write-Host $bold'Current UEFI DB'$reset
$DBCerts  | ForEach-Object {
    Show-UEFICertIsPresent -SecureBootUEFIVar db -CertName $_
}
Show-UEFICertOthers -SecureBootUEFIVar db -KnownCerts $DBCerts

Write-Host ""
Write-Host $bold'Default UEFI DB'$reset
if ($IsArm) {
    Write-Warning "Some ARM-based Windows devices can't retrieve default UEFI variables."
}
$DBCerts  | ForEach-Object {
    Show-UEFICertIsPresent -SecureBootUEFIVar dbDefault -CertName $_
}
Show-UEFICertOthers -SecureBootUEFIVar DBDefault -KnownCerts $DBCerts

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
    Show-CheckDBX "2025-02-25 (v1.4.0)" "$PSScriptRoot\..\dbx_bin\arm64_DBXUpdate_2025-02-25.bin"
} else {
  # Show-CheckDBX "2023-03-14         " "$PSScriptRoot\..\dbx_bin\x64_DBXUpdate_2023-03-14.bin"
  # Show-CheckDBX "2023-05-09         " "$PSScriptRoot\..\dbx_bin\x64_DBXUpdate_2023-05-09.bin"
  # Show-CheckDBX "2025-01-14 (v1.3.1)" "$PSScriptRoot\..\dbx_bin\x64_DBXUpdate_2025-01-14.bin"
    Show-CheckDBX "2025-06-11 (v1.5.1)" "$PSScriptRoot\..\dbx_bin\x64_DBXUpdate_2025-06-11.bin"
    Show-CheckDBX "2025-10-14 (v1.6.0)" "$PSScriptRoot\..\dbx_bin\x64_DBXUpdate_2025-10-14.bin"
}
