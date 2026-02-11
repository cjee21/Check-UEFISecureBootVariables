# Created by github.com/cjee21
# License: MIT
# Repository: https://github.com/cjee21/Check-UEFISecureBootVariables

# Check for admin
Write-Host "Checking for Administrator permission..."
if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Warning "Insufficient permissions to run this script. Please run as administrator."
    Break
} else {
    Write-Host "Running as administrator - continuing execution...`n"
}

# Check files
if (-not ((Test-Path -Path "$PSScriptRoot\Check-Dbx-Simplified.ps1" -PathType Leaf) -and `
    (Test-Path -Path "$PSScriptRoot\Get-UEFIDatabaseSignatures.ps1" -PathType Leaf) -and `
    (Test-Path -Path "$PSScriptRoot\..\dbx_bin\*.bin") -and `
    (Test-Path -Path "$PSScriptRoot\..\dbx_info\*.json"))) {
    Write-Warning "Some required files are missing. Please re-obtain a copy from https://github.com/cjee21/Check-UEFISecureBootVariables."
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
"Windows version: {0} (Build {1}.{2})`n" -f $v.DisplayVersion, $v.CurrentBuildNumber, $v.UBR

# Check architecture
$IsArm = $false
$Is64bit = $true
try {
    $arch = (Get-WmiObject Win32_Processor -ErrorAction Stop).Architecture
    # 0 = x86, 9 = x64, 5 = ARM, 12 = ARM64
    if ($arch -eq 5 -or $arch -eq 12) {
        $IsArm = $true
    }
    # Windows and UEFI bit-ness should always match on officially supported installs
    $Is64bit = [Environment]::Is64BitOperatingSystem
} catch {
    $IsArm = $false
    $Is64bit = $true
    Write-Warning "Unable to determine system architecture, proceeding with defaults (x64).`n"
}
$arch = if (-not $IsArm -and $Is64bit) {
        "x64"
    } elseif ($IsArm -and $Is64bit) {
        "arm64"
    } elseif (-not $IsArm -and -not $Is64bit) {
        "x86"
    } else {
        "arm"
    }
Write-Host "Detected $arch UEFI architecture. Ensure that this is correct for valid DBX results.`n"

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
            if ($CertName) {
                $revoked = $false
                try {
                    $revoked = [System.Text.Encoding]::ASCII.GetString((Get-SecureBootUEFI dbx -ErrorAction Stop).bytes) -match $CertName
                } catch {
                    $revoked = $false
                }
                Write-Host "$check $CertName (revoked: $revoked)"
            } else {
                Write-Host "$check $CertName (revoked: Unknown)"
            }
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
                if ($_) {
                    $revoked = $false
                    try {
                        $revoked = [System.Text.Encoding]::ASCII.GetString((Get-SecureBootUEFI dbx -ErrorAction Stop).bytes) -match $_
                    } catch {
                        $revoked = $false
                    }
                    Write-Host "$check $_ (revoked: $revoked)"
                } else {
                    Write-Host "$check $_ (revoked: Unknown)"
                }
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
Write-Host $bold'Current UEFI DBX'$reset

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
        Write-Host "ERROR: An exception has occurred while checking DBX" -ForegroundColor Red
    }
}

if ($arch -eq "x64") {
  # Show-CheckDBX "2023-03-14         " "$PSScriptRoot\..\dbx_bin\x64_DBXUpdate_2023-03-14.bin"
  # Show-CheckDBX "2023-05-09         " "$PSScriptRoot\..\dbx_bin\x64_DBXUpdate_2023-05-09.bin"
  # Show-CheckDBX "2025-01-14 (v1.3.1)" "$PSScriptRoot\..\dbx_bin\x64_DBXUpdate_2025-01-14.bin"
  # Show-CheckDBX "2025-06-11 (v1.5.1)" "$PSScriptRoot\..\dbx_bin\x64_DBXUpdate_2025-06-11.bin"
    Show-CheckDBX "2025-10-14 (v1.6.0) [$arch]  " "$PSScriptRoot\..\dbx_bin\x64_DBXUpdate_2025-10-14.bin"
} elseif ($arch -eq "arm64") {
    Show-CheckDBX "2025-02-25 (v1.4.0) [$arch]" "$PSScriptRoot\..\dbx_bin\arm64_DBXUpdate_2025-02-25.bin"
} elseif ($arch -eq "x86") {
    Show-CheckDBX "2025-10-14 (v1.6.0) [$arch]  " "$PSScriptRoot\..\dbx_bin\x86_DBXUpdate_2025-10-14.bin"
} else {
    Show-CheckDBX "2025-02-25 (v1.4.0) [$arch]  " "$PSScriptRoot\..\dbx_bin\arm_DBXUpdate_2025-02-25.bin"
}

$svn_latest_dbx = "10_14_25"
$svn_json = Get-Content -Path "$PSScriptRoot\..\dbx_info\dbx_info_msft_$svn_latest_dbx.json" -Raw | ConvertFrom-Json
$svn_bootmgr_latest = [version]($svn_json.svns | Where-Object { $_.guid -eq "{9d132b61-59d5-4388-1cab-185c3cb2eb92} == EFI_BOOTMGR_DBXSVN_GUID" }).version
$svn_cdboot_latest = [version]($svn_json.svns | Where-Object { $_.guid -eq "{e8f82e9d-e127-4158-88a4-4c18abe2f284} == EFI_CDBOOT_DBXSVN_GUID" }).version
$svn_wdsmgfw_latest = [version]($svn_json.svns | Where-Object { $_.guid -eq "{c999cac2-7ffe-496f-2781-9e2a8a535976} == EFI_WDSMGR_DBXSVN_GUID" }).version
$dbx_bytes = (Get-SecureBootUEFI dbx).Bytes
$dbx_hex = ($dbx_bytes | ForEach-Object {'{0:x2}' -f $_}) -join ''

function Get-VersionFromHexString {
    # SVN_DATA value:
    # Byte[0] is the UINT8 version of the SVN_DATA structure.
    # Bytes[1...16] are the GUID of the application being revoked. Little endian.
    # Bytes[17...18] are the Minor SVN number. Litte endian UINT16.
    # Bytes[19...20] are the Major SVN number. Litte endian UINT16.
    # Bytes[21...31] are 11 zero bytes padding.
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$HexString
    )
    $byteArray = -split ($HexString -replace '..', '$& ') | ForEach-Object { 
        [System.Convert]::ToByte($_, 16) 
    }
    $MinorBytes = $byteArray[17..18]
    $svn_ver_minor = [System.BitConverter]::ToInt16($MinorBytes, 0)
    $MajorBytes = $byteArray[19..20]
    $svn_ver_major = [System.BitConverter]::ToInt16($MajorBytes, 0)
    return [version]::new($svn_ver_major, $svn_ver_minor)
}

Write-Host "Windows Bootmgr SVN         : " -NoNewline
$svn_bootmgr = [Regex]::Matches($dbx_hex,'01612B139DD5598843AB1C185C3CB2EB92........0000000000000000000000', [System.Text.RegularExpressions.RegexOptions]::IgnoreCase).Value

if ($svn_bootmgr.Count) {
    $svn_bootmgr_vers = $svn_bootmgr | ForEach-Object {
        Get-VersionFromHexString($_)
    }
    $svn_bootmgr_ver = ($svn_bootmgr_vers | Measure-Object -Maximum).Maximum
    if ($svn_bootmgr_ver -ge $svn_bootmgr_latest) {
        Write-Host $svn_bootmgr_ver -ForegroundColor Green
    } else {
        Write-Host $svn_bootmgr_ver -ForegroundColor Red
    }
} else {
    Write-Host 'None' -ForegroundColor Red
}
Write-Host "Windows cdboot SVN          : " -NoNewline
$svn_cdboot = [Regex]::Matches($dbx_hex,'019D2EF8E827E15841A4884C18ABE2F284........0000000000000000000000', [System.Text.RegularExpressions.RegexOptions]::IgnoreCase).Value
if ($svn_cdboot.Count) {
    $svn_cdboot_vers = $svn_cdboot | ForEach-Object {
        Get-VersionFromHexString($_)
    }
    $svn_cdboot_ver = ($svn_cdboot_vers | Measure-Object -Maximum).Maximum
    if ($svn_cdboot_ver -ge $svn_cdboot_latest) {
        Write-Host $svn_cdboot_ver -ForegroundColor Green
    } else {
        Write-Host $svn_cdboot_ver -ForegroundColor Red
    }
} else {
    Write-Host 'None' -ForegroundColor Red
}
Write-Host "Windows wdsmgfw SVN         : " -NoNewline
$svn_wdsmgfw = [Regex]::Matches($dbx_hex,'01C2CA99C9FE7F6F4981279E2A8A535976........0000000000000000000000', [System.Text.RegularExpressions.RegexOptions]::IgnoreCase).Value
if ($svn_wdsmgfw.Count) {
    $svn_wdsmgfw_vers = $svn_wdsmgfw | ForEach-Object {
        Get-VersionFromHexString($_)
    }
    $svn_wdsmgfw_ver = ($svn_wdsmgfw_vers | Measure-Object -Maximum).Maximum
    if ($svn_wdsmgfw_ver -ge $svn_wdsmgfw_latest) {
        Write-Host $svn_wdsmgfw_ver -ForegroundColor Green
    } else {
        Write-Host $svn_wdsmgfw_ver -ForegroundColor Red
    }
} else {
    Write-Host 'None' -ForegroundColor Red
}
