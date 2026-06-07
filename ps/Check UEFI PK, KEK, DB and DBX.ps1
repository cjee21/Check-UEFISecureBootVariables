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

do {
# Print computer info
Import-Module $PSScriptRoot\Get-SystemOverview.psm1 -Force
Show-DeviceOverview
Write-Host

# Check architecture
$arch = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\Servicing\DeviceAttributes").OSArchitecture

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
    Write-Warning "Failed to query UEFI variable PK"
}

Write-Host ""
Write-Host $bold'Default UEFI PK'$reset
if ($arch -match '^arm') {
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
        $certs | ForEach-Object {
            if ($_.SignatureType -eq 'EFI_CERT_X509_GUID') {
                $_.SignatureList.SignatureData.Subject | ForEach-Object {
                    $cert_names += [regex]::Match($_, 'CN=([^,]+)').Groups[1].Value
                }
            }
            elseif ($_.SignatureType -eq 'EFI_CERT_SHA256_GUID') {
                $_.SignatureList.SignatureData | ForEach-Object {
                    $cert_names += "SHA256: $_"
                }
            }
        }
        
        $cert_names | ForEach-Object {
            if ($KnownCerts -notcontains $_) {
                # List out all other certs found other than those in known list
                # No check for revocation since not all certs have unique CNs and we do not check by thumbprint
                Write-Host "$check $_"
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
if ($arch -match '^arm') {
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
if ($arch -match '^arm') {
    Write-Warning "Some ARM-based Windows devices can't retrieve default UEFI variables."
}
$DBCerts  | ForEach-Object {
    Show-UEFICertIsPresent -SecureBootUEFIVar dbDefault -CertName $_
}
Show-UEFICertOthers -SecureBootUEFIVar DBDefault -KnownCerts $DBCerts

Write-Host ""
Write-Host $bold'Current UEFI DBX'$reset

try {
    $dbx_raw = Get-SecureBootUEFI dbx -ErrorAction Stop
} catch {
    Write-Host "Exception: $($_.Exception.Message)" -ForegroundColor Red
    Break # No need to continue with remaining DBX-related checks of script if failed to obtain DBX data
}

$colWidth = 20
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

# Read metadata (Date, Version, Arch) from bin file name
function Get-DbxMetadata {
    param([string]$name)

    if ($name -notmatch '^DBXUpdate_([^_]+)_(\d{4}-\d{2}-\d{2})_([^.]+)\.bin$') { return $null }

    return [pscustomobject]@{
        Version = $matches[1]
        Date    = [datetime]::ParseExact($matches[2], "yyyy-MM-dd", $null)
        Arch    = $matches[3]
        Name    = $name
    }
}

# Published DBX bin for arch
$dbxFolder = "$PSScriptRoot\..\dbx_bin"
$publishedDBX = Get-ChildItem $dbxFolder -Filter "DBXUpdate_*.bin" |
    ForEach-Object { Get-DbxMetadata $_.Name } |
    Where-Object { $_ -ne $null -and $_.Arch -eq $arch } | 
    Sort-Object Date -Descending | 
    Select-Object -First 1
if (-not $publishedDBX) { throw "No published DBX file found for architecture: $arch" }

# Staged DBX bin
$stagedPath = "C:\Windows\System32\SecureBootUpdates\dbxupdate.bin"
$stagedDate = if (Test-Path $stagedPath) { (Get-Item $stagedPath).LastWriteTime } else { $null }

# Check DBX against latest DBX revocations
if ($stagedDate -and ($stagedDate -ge $publishedDBX.Date)) {
    Show-CheckDBX ("Staged ({0})" -f $stagedDate.ToString('dd MMM yyyy')) $stagedPath
} else {
    $label = "{0} ({1})" -f `
        $publishedDBX.Version,
        $publishedDBX.Date.ToString('dd MMM yyyy')
    Show-CheckDBX $label "$dbxFolder\$($publishedDBX.Name)"
}

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
    BootMgr = @{ Name="FirmwareSVN BootMgr"; JSON=$svn_bootmgr_latest }
    CDBoot  = @{ Name="FirmwareSVN CDBoot"; JSON=$svn_cdboot_latest }
    WDSMgFw = @{ Name="FirmwareSVN WDSMgFw"; JSON=$svn_wdsmgfw_latest }
}

$svn_firmware = Get-SVNfromDBX $dbx_list
$StagedSVNbytes = [IO.File]::ReadAllBytes('C:\Windows\System32\SecureBootUpdates\DBXUpdateSVN.bin')
$svn_staged = Get-SVNfromDBX (Get-UEFIDatabaseSignatures -BytesIn $StagedSVNbytes)

foreach ($key in $components.Keys) {
    Write-Host -NoNewline "$($components[$key].Name.PadRight($colWidth)) : "

    if (-not $svn_firmware.$key) {
        Write-Host "Not applied" -ForegroundColor Red
        continue
    }

    $json       = $components[$key].JSON
    $current    = $svn_firmware.$key.Version
    $staged     = $svn_staged.$key.Version

    $target = if ($json -ge $staged) { $json } else { $staged }
    $isUpdated = ($current -ge $target)
    $color = if ($isUpdated) { "Green" } else { "Red" }
    $text = if ($isUpdated) { "$current" } else { "$current (Target: $target)" }
    Write-Host $text -ForegroundColor $color
}

Write-Host ("Statistics".PadRight($colWidth) + " : $dbx_size Bytes, $dbx_hashes SHA256 hashes, $dbx_certs X.509 certs, $dbx_svns SVNs")

Write-Host
Read-Host "Press ENTER to refresh"

} while ($true)
