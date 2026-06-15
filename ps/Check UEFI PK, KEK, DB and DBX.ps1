# Created by github.com/cjee21
# License: MIT
# Repository: https://github.com/cjee21/Check-UEFISecureBootVariables

# Check for admin
if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Warning "Insufficient permissions to run this script. Please run as administrator."
    Break
}

# Check files
if (-not ((Test-Path -Path "$PSScriptRoot\Check-Dbx-Simplified.ps1" -PathType Leaf) -and `
    (Test-Path -Path "$PSScriptRoot\Get-UEFIDatabaseSignatures.psm1" -PathType Leaf) -and `
    (Test-Path -Path "$PSScriptRoot\..\dbx_bin\*.bin") -and `
    (Test-Path -Path "$PSScriptRoot\..\dbx_info\*.json"))) {
    Write-Warning "Some required files are missing. Please re-obtain a copy from https://github.com/cjee21/Check-UEFISecureBootVariables."
    Break
}

# Print computer info
Import-Module $PSScriptRoot\Get-SystemOverview.psm1 -Force
Show-DeviceOverview
Write-Host

# Check architecture
$IsArm = $false
$Is64bit = $true
try {
    $cpuArch = (Get-CimInstance -ClassName Win32_Processor -ErrorAction Stop).Architecture
    # 0 = x86, 9 = x64, 5 = ARM, 12 = ARM64
    if ($cpuArch -eq 5 -or $cpuArch -eq 12) {
        $IsArm = $true
    }
    # Windows and UEFI bit-ness should always match on officially supported installs
    # since UEFI doesn't support cross-platform boot as of https://learn.microsoft.com/en-us/windows/deployment/windows-deployment-scenarios-and-tools#windows-support-for-uefi
    $Is64bit = [Environment]::Is64BitOperatingSystem
} catch {
    $IsArm = $false
    $Is64bit = $true
    Write-Warning "Unable to determine system architecture, proceeding with defaults (x64).`n"
    $cpuArch = 9 # default x64
}
$arch = if ($Is64bit -and $cpuArch -eq 9) { # CPU arch x64
        "amd64"
    } elseif ($Is64bit -and $cpuArch -eq 12) { # CPU arch ARM64
        "arm64"
    } elseif (-not $Is64bit -and ($cpuArch -eq 0 -or $cpuArch -eq 9)) {
        "x86" # CPU arch can be x86 or x64, but Windows/EFI arch is x86, thus the one we need.
    } elseif (-not $Is64bit -and $IsArm) { # cpu arch check with $IsArm above
        "arm"
    } else { # any other unsupported CPU architecture
        "unsupported"
    }

Write-Host "Detected $(Resolve-ArchName($arch)) UEFI architecture. Ensure that this is correct for valid DBX results.`n"

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

Import-Module -Force "$PSScriptRoot\Get-UEFIDatabaseSignatures.psm1"

Write-Host $bold'Current UEFI PK'$reset
try {
    $pk = Get-SecureBootUEFI -Name pk | Get-UEFIDatabaseSignatures
    $pk.SignatureList.SignatureData.Subject | ForEach-Object {
        $pk_name = [regex]::Match($_, 'CN=([^,]+)').Groups[1].Value
        Write-Host "$check $pk_name"
    }
} catch {
    Write-Warning "Failed to query UEFI variable PK: $($_.Exception.Message)"
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
    Write-Warning "Failed to query UEFI variable PKDefault: $($_.Exception.Message)"
}

function Is-CertThumbprintRevoked {
    param (
        [Parameter(Mandatory)]
        [string]$CertThumbprint,
        [Parameter()]
        [PSCustomObject]$DBX
    )
    $revoked = 'false'
    if ($DBX) {
        foreach ($SignatureList in $DBX) {
            if ($SignatureList.SignatureType -eq 'EFI_CERT_X509_GUID') {
                foreach ($Signature in $SignatureList.SignatureList) {
                    if ($Signature.SignatureData.Thumbprint -eq $CertThumbprint) {
                        $revoked = 'true'
                    }
                }
            }
        }
    } else {
        $revoked = 'unknown'
    }
    $revoked
}

function Show-UEFICertIsPresent {
    param (
        [Parameter(Mandatory)]
        [PSCustomObject]$UEFISignatureDatabase,
        [Parameter(Mandatory)]
        [string]$CertThumbprint,
        [Parameter(Mandatory)]
        [string]$CertName,
        [Parameter()]
        [PSCustomObject]$DBX
    )
    $found = $false
    foreach ($SignatureList in $UEFISignatureDatabase) {
        if ($SignatureList.SignatureType -eq 'EFI_CERT_X509_GUID') {
            foreach ($Signature in $SignatureList.SignatureList) {
                if ($Signature.SignatureData.Thumbprint -eq $CertThumbprint) {
                    $found = $true
                }
            }
        }
    }
    $revoked = Is-CertThumbprintRevoked -CertThumbprint $CertThumbprint -DBX $DBX
    if ($found) {
        Write-Host "$check $CertName (revoked: $revoked)"
    } else {
        Write-Host "$cross $CertName (revoked: $revoked)"
    }
}

function Show-UEFICertOthers {
    param (
        [Parameter(Mandatory)]
        [PSCustomObject]$UEFISignatureDatabase,
        [Parameter(Mandatory)]
        [Array]$KnownCerts,
        [Parameter()]
        [PSCustomObject]$DBX
    )
    $cert_names = [ordered]@{}
    foreach ($SignatureList in $UEFISignatureDatabase) {
        if ($SignatureList.SignatureType -eq 'EFI_CERT_X509_GUID') {
            foreach ($Signature in $SignatureList.SignatureList) {
                $revoked = Is-CertThumbprintRevoked -CertThumbprint $Signature.SignatureData.Thumbprint -DBX $DBX
                $common_name = [regex]::Match($Signature.SignatureData.Subject, 'CN=([^,]+)').Groups[1].Value
                if ([string]::IsNullOrWhiteSpace($common_name)) {
                    $common_name = $Signature.SignatureData.Thumbprint # Show Thumbprint if cert has no CN
                }
                $cert_names[$Signature.SignatureData.Thumbprint] = $common_name + " (revoked: $revoked)"
            }
        }
        elseif ($SignatureList.SignatureType -eq 'EFI_CERT_SHA256_GUID') {
            foreach ($Signature in $SignatureList.SignatureList) {
                $cert_names[$Signature.SignatureData] = "SHA256: $($Signature.SignatureData)"
                # Note: Hashes are not checked for revocations at the moment
            }
        }
    }
    foreach ($Key in $cert_names.Keys) {
        if ($Key -notin $KnownCerts.Keys) {
            Write-Host "$check $($cert_names[$Key])"
        }
    }
}

try {
    $dbx = Get-SecureBootUEFI dbx -ErrorAction Stop | Get-UEFIDatabaseSignatures -ErrorAction Stop
} catch {
    $dbx = $null
}

$KEKCerts = [ordered]@{
    '31590BFD89C9D74ED087DFAC66334B3931254B30' = 'Microsoft Corporation KEK CA 2011'
    '459AB6FB5E284D272D5E3E6ABC8ED663829D632B' = 'Microsoft Corporation KEK 2K CA 2023'
}

Write-Host ""
Write-Host $bold'Current UEFI KEK'$reset
try {
    $kek = Get-SecureBootUEFI kek -ErrorAction Stop | Get-UEFIDatabaseSignatures -ErrorAction Stop
    foreach ($Cert in $KEKCerts.GetEnumerator()) {
        Show-UEFICertIsPresent -UEFISignatureDatabase $kek -CertThumbprint $Cert.Key -CertName $Cert.Value -DBX $dbx
    }
    Show-UEFICertOthers -UEFISignatureDatabase $kek -KnownCerts $KEKCerts -DBX $dbx
} catch {
    Write-Warning "Failed to query UEFI variable KEK: $($_.Exception.Message)"
}

Write-Host ""
Write-Host $bold'Default UEFI KEK'$reset
if ($IsArm) {
    Write-Warning "Some ARM-based Windows devices can't retrieve default UEFI variables."
}
try {
    $kekDefault = Get-SecureBootUEFI kekDefault -ErrorAction Stop | Get-UEFIDatabaseSignatures -ErrorAction Stop
    foreach ($Cert in $KEKCerts.GetEnumerator()) {
        Show-UEFICertIsPresent -UEFISignatureDatabase $kekDefault -CertThumbprint $Cert.Key -CertName $Cert.Value -DBX $dbx
    }
    Show-UEFICertOthers -UEFISignatureDatabase $kekDefault -KnownCerts $KEKCerts -DBX $dbx
} catch {
    Write-Warning "Failed to query UEFI variable KEKDefault: $($_.Exception.Message)"
}

$DBCerts = [ordered]@{
    '580A6F4CC4E4B669B9EBDC1B2B3E087B80D0678D' = 'Microsoft Windows Production PCA 2011'
    '46DEF63B5CE61CF8BA0DE2E6639C1019D0ED14F3' = 'Microsoft Corporation UEFI CA 2011'
    '45A0FA32604773C82433C3B7D59E7466B3AC0C67' = 'Windows UEFI CA 2023'
    'B5EEB4A6706048073F0ED296E7F580A790B59EAA' = 'Microsoft UEFI CA 2023'
    '3FB39E2B8BD183BF9E4594E72183CA60AFCD4277' = 'Microsoft Option ROM UEFI CA 2023'
}

Write-Host ""
Write-Host $bold'Current UEFI DB'$reset
try {
    $db = Get-SecureBootUEFI db -ErrorAction Stop | Get-UEFIDatabaseSignatures -ErrorAction Stop
    foreach ($Cert in $DBCerts.GetEnumerator()) {
        Show-UEFICertIsPresent -UEFISignatureDatabase $db -CertThumbprint $Cert.Key -CertName $Cert.Value -DBX $dbx
    }
    Show-UEFICertOthers -UEFISignatureDatabase $db -KnownCerts $DBCerts -DBX $dbx
} catch {
    Write-Warning "Failed to query UEFI variable DB: $($_.Exception.Message)"
}

Write-Host ""
Write-Host $bold'Default UEFI DB'$reset
if ($IsArm) {
    Write-Warning "Some ARM-based Windows devices can't retrieve default UEFI variables."
}
try {
    $dbDefault = Get-SecureBootUEFI dbDefault -ErrorAction Stop | Get-UEFIDatabaseSignatures -ErrorAction Stop
    foreach ($Cert in $DBCerts.GetEnumerator()) {
        Show-UEFICertIsPresent -UEFISignatureDatabase $dbDefault -CertThumbprint $Cert.Key -CertName $Cert.Value -DBX $dbx
    }
    Show-UEFICertOthers -UEFISignatureDatabase $dbDefault -KnownCerts $DBCerts -DBX $dbx
} catch {
    Write-Warning "Failed to query UEFI variable DBDefault: $($_.Exception.Message)"
}

Write-Host ""
Write-Host $bold'Current UEFI DBX'$reset

try {
    $dbx_raw = Get-SecureBootUEFI dbx -ErrorAction Stop
} catch {
    Write-Host "Exception: $($_.Exception.Message)" -ForegroundColor Red
    Break # No need to continue with remaining DBX-related checks of script if failed to obtain DBX data
}

$colWidth = 27
function Show-CheckDBX {
    param(
        [Parameter(Mandatory)][string]$Label,
        [Parameter(Mandatory)][string]$File
    )
    Write-Host ($Label.PadRight($colWidth) + " : ") -NoNewline
    try {
        $oldPreference = $ErrorActionPreference
        $ErrorActionPreference = 'Stop'
        & "$PSScriptRoot\Check-Dbx-Simplified.ps1" "$File"
        $ErrorActionPreference = $oldPreference
    } catch {
        Write-Host "ERROR: An exception has occurred while checking DBX" -ForegroundColor Red
    }
}

# select the proper bin file for the DBX Update.
# files are copied from https://github.com/microsoft/secureboot_objects/tree/main/PostSignedObjects/DBX
if ($arch -eq "amd64") {
  # Show-CheckDBX "2023-03-14         " "$PSScriptRoot\..\dbx_bin\x64_DBXUpdate_2023-03-14.bin"
  # Show-CheckDBX "2023-05-09         " "$PSScriptRoot\..\dbx_bin\x64_DBXUpdate_2023-05-09.bin"
  # Show-CheckDBX "2025-01-14 (v1.3.1)" "$PSScriptRoot\..\dbx_bin\x64_DBXUpdate_2025-01-14.bin"
  # Show-CheckDBX "2025-06-11 (v1.5.1)" "$PSScriptRoot\..\dbx_bin\x64_DBXUpdate_2025-06-11.bin"
  # Show-CheckDBX "2025-10-14 (v1.6.0) [$($arch.ToUpper())]" "$PSScriptRoot\..\dbx_bin\x64_DBXUpdate_2025-10-14.bin"
    Show-CheckDBX "2026-06-09 [$($arch.ToUpper())]" "$PSScriptRoot\..\dbx_bin\x64_DBXUpdate_2026-06-09.bin"
} elseif ($arch -eq "arm64") {
    Show-CheckDBX "2025-02-25 (v1.4.0) [$($arch.ToUpper())]" "$PSScriptRoot\..\dbx_bin\arm64_DBXUpdate_2025-02-25.bin"
} elseif ($arch -eq "x86") {
  # Show-CheckDBX "2025-10-14 (v1.6.0) [$($arch.ToUpper())]" "$PSScriptRoot\..\dbx_bin\x86_DBXUpdate_2025-10-14.bin"
    Show-CheckDBX "2026-04-14 [$($arch.ToUpper())]" "$PSScriptRoot\..\dbx_bin\x86_DBXUpdate_2026-04-14.bin"
} elseif ($arch -eq "arm") {
    Show-CheckDBX "2025-02-25 (v1.4.0) [$($arch.ToUpper())]" "$PSScriptRoot\..\dbx_bin\arm_DBXUpdate_2025-02-25.bin"
} else {
    Write-Warning "[$($arch.ToUpper())] architecture."
}
# Show-CheckDBX "Current Windows staged" "C:\Windows\System32\SecureBootUpdates\dbxupdate.bin"

Import-Module -Force "$PSScriptRoot\Get-SVNfromDBX.psm1"

$svn_json = Get-Content -Path "$PSScriptRoot\..\dbx_info\dbx_info_msft_latest.json" -Raw | ConvertFrom-Json
$svn_bootmgr_latest = [version]($svn_json.svns | Where-Object { $_.guid -eq "{$EFI_BOOTMGR_DBXSVN_GUID} == EFI_BOOTMGR_DBXSVN_GUID" }).version
$svn_cdboot_latest = [version]($svn_json.svns | Where-Object { $_.guid -eq "{$EFI_CDBOOT_DBXSVN_GUID} == EFI_CDBOOT_DBXSVN_GUID" }).version
$svn_wdsmgfw_latest = [version]($svn_json.svns | Where-Object { $_.guid -eq "{$EFI_WDSMGR_DBXSVN_GUID} == EFI_WDSMGR_DBXSVN_GUID" }).version

$dbx_list = $dbx_raw | Get-UEFIDatabaseSignatures
$dbx_size = $dbx_raw.Bytes.Length
$dbx_hashes = @($dbx_list | Where-Object { $_.SignatureType -eq 'EFI_CERT_SHA256_GUID' } | ForEach-Object { $_.SignatureList.SignatureData }).Count
$dbx_certs = @($dbx_list | Where-Object { $_.SignatureType -eq 'EFI_CERT_X509_GUID' } | ForEach-Object { $_.SignatureList.SignatureData }).Count
$dbx_svns = @($dbx_list | Where-Object { $_.SignatureType -eq 'EFI_CERT_SHA256_GUID' } | ForEach-Object { $_.SignatureList | Where-Object { $_.SignatureOwner -eq [guid]$SVN_OWNER_GUID } } | ForEach-Object { $_.SignatureData }).Count
$dbx_hashes -= $dbx_svns

$components = [ordered]@{
    BootMgr = @{ Name="Windows BootMgr SVN"; JSON=$svn_bootmgr_latest }
    CDBoot  = @{ Name="Windows CDBoot SVN"; JSON=$svn_cdboot_latest }
    WDSMgFw = @{ Name="Windows WDSMgFw SVN"; JSON=$svn_wdsmgfw_latest }
}

if ([System.IntPtr]::Size -eq 4 -and $env:PROCESSOR_ARCHITEW6432) {
    $WinSysPath = "$env:SystemRoot\Sysnative"
} else {
    $WinSysPath = "$env:SystemRoot\System32"
}
$svn_list = Get-SVNfromDBX $dbx_list
try {
    $StagedSVNbytes = [IO.File]::ReadAllBytes("$WinSysPath\SecureBootUpdates\DBXUpdateSVN.bin")
    $svn_staged = Get-SVNfromDBX (Get-UEFIDatabaseSignatures -BytesIn $StagedSVNbytes)
} catch {
    $svn_staged = $null
}

foreach ($key in $components.Keys) {
    Write-Host -NoNewline "$($components[$key].Name.PadRight($colWidth)) : "

    if (-not $svn_list.$key) {
        Write-Host "Not applied" -ForegroundColor Red
        continue
    }

    $json       = $components[$key].JSON
    $current    = $svn_list.$key.Version
    $staged     = if ($svn_staged) { $svn_staged.$key.Version } else { [version]0.0 }

    $target = if ($json -ge $staged) { $json } else { $staged }
    $isUpdated = ($current -ge $target)
    $color = if ($isUpdated) { "Green" } else { "Red" }
    $text = if ($isUpdated) { "$current" } else { "$current (Target: $target)" }
    Write-Host $text -ForegroundColor $color
}

Write-Host ("Statistics".PadRight($colWidth) + " : $dbx_size Bytes, $dbx_hashes SHA256 hashes, $dbx_certs X.509 certs, $dbx_svns SVNs")
