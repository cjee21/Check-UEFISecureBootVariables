# Created for cjee21/Check-UEFISecureBootVariables
# Purpose: Walk EFI binaries and warn if they match revocations via:
#   - file hash (Authenticode hash if you wire it in later)
#   - signer certificate match (X509 DER match) against current DBX (EFI_CERT_X509_GUID)
# Also supports checking against microsoft/secureboot_objects dbx_info_msft_latest.json.

[CmdletBinding()]
param(
    # Root directories to scan for .efi files (optional)
    [string[]] $Paths,

    # If set, will mount ESP to S: (mountvol s: /s) and scan it (default: true)
    [switch] $ScanESP = $true,

    # Helper flag: scan common OS paths too (default: false)
    [switch] $ScanDefaultPaths = $false,

    # Which revocation source(s) to match against
    [ValidateSet('CurrentDbx','MsftJson','Both')]
    [string] $MatchMode = 'CurrentDbx',

    # Optional: local path to dbx_info_msft_latest.json
    [string] $MsftJsonPath,

    # Optional: URL to download dbx_info_msft_latest.json
    [string] $MsftJsonUrl
)

$ErrorActionPreference = 'Stop'

Import-Module "$PSScriptRoot\Get-UEFIDatabaseSignatures.ps1" -Force
Import-Module "$PSScriptRoot\Get-EfiSignatures.ps1" -Force

function Get-FileSha256Hex {
    param([Parameter(Mandatory)][string] $FilePath)
    (Get-FileHash -Algorithm SHA256 -LiteralPath $FilePath).Hash.ToUpperInvariant()
}

function Get-CertDerHex {
    param([Parameter(Mandatory)][System.Security.Cryptography.X509Certificates.X509Certificate2] $Cert)
    ([System.BitConverter]::ToString($Cert.RawData) -replace '-', '').ToUpperInvariant()
}

function Get-DbxSetsFromCurrentDbx {
    # Returns:
    # - HashSet of SHA256 hex strings (EFI_CERT_SHA256_GUID)
    # - HashSet of X509 DER hex strings (EFI_CERT_X509_GUID)
    $dbx = Get-SecureBootUEFI -Name dbx
    $parsed = $dbx | Get-UEFIDatabaseSignatures

    $sha256Set = New-Object 'System.Collections.Generic.HashSet[string]'
    $x509DerSet = New-Object 'System.Collections.Generic.HashSet[string]'

    foreach ($list in $parsed) {
        foreach ($entry in $list.SignatureList) {
            if ($list.SignatureType -eq 'EFI_CERT_SHA256_GUID') {
                [void]$sha256Set.Add(($entry.SignatureData.ToString().ToUpperInvariant()))
            } elseif ($list.SignatureType -eq 'EFI_CERT_X509_GUID') {
                $derHex = Get-CertDerHex -Cert $entry.SignatureData
                [void]$x509DerSet.Add($derHex)
            }
        }
    }

    [PSCustomObject]@{
        Name = 'CurrentDbx'
        Sha256Set = $sha256Set
        X509DerSet = $x509DerSet
    }
}

function Get-DbxSetsFromMsftJson {
    param(
        [string] $Path,
        [string] $Url
    )

    $jsonText = $null
    if ($Path) {
        if (-not (Test-Path -LiteralPath $Path)) {
            throw "MsftJsonPath not found: $Path"
        }
        $jsonText = Get-Content -LiteralPath $Path -Raw
    } elseif ($Url) {
        # Download to memory
        $jsonText = (Invoke-WebRequest -UseBasicParsing -Uri $Url).Content
    } else {
        throw "MatchMode requires -MsftJsonPath or -MsftJsonUrl."
    }

    $j = $jsonText | ConvertFrom-Json

    # MSFT JSON structure: { "images": { "x64": [ { authenticodeHash, flatHash, ... }, ... ], "arm64": [ ... ] } }
    $sha256Set = New-Object 'System.Collections.Generic.HashSet[string]'

    foreach ($archProp in $j.images.PSObject.Properties) {
        $archName = $archProp.Name
        $items = $archProp.Value
        foreach ($img in $items) {
            if ($img.authenticodeHash -and $img.authenticodeHash.Trim()) {
	        #Focus on authenticodeHash for matches as most reliable
                [void]$sha256Set.Add($img.authenticodeHash.Trim().ToUpperInvariant())
            }
        }
    }

    # MSFT JSON does not directly provide DER blobs for revoked cert entries (at least in the snippet provided),
    # so in MsftJson mode we can only do hash-based checks unless you add a mapping of signer certs separately.
    $x509DerSet = New-Object 'System.Collections.Generic.HashSet[string]'

    [PSCustomObject]@{
        Name = 'MsftJson'
        Sha256Set = $sha256Set
        X509DerSet = $x509DerSet
    }
}

function Get-EfiFilesUnderPaths {
    param([Parameter(Mandatory)][string[]] $RootPaths)

    $all = New-Object System.Collections.Generic.List[string]
    foreach ($root in $RootPaths) {
        if (-not (Test-Path -LiteralPath $root)) { continue }
        Get-ChildItem -LiteralPath $root -Recurse -File -ErrorAction SilentlyContinue |
            Where-Object { $_.Extension -ieq '.efi' } |
            ForEach-Object { $all.Add($_.FullName) | Out-Null }
    }
    $all
}

# Build scan roots
$scanRoots = New-Object System.Collections.Generic.List[string]

$didMountEsp = $false
if ($ScanESP) {
    try {
        mountvol s: /s | Out-Null
        $didMountEsp = $true
        $scanRoots.Add('S:\') | Out-Null
    } catch {
        Write-Warning "Could not mount ESP to S:. Run as Administrator? Continuing..."
    }
}

if ($ScanDefaultPaths) {
    # Common locations where EFI binaries may exist on the OS volume.
    $scanRoots.Add("$env:SystemRoot\Boot\EFI") | Out-Null
    $scanRoots.Add("$env:SystemDrive\EFI") | Out-Null
    $scanRoots.Add("$env:SystemDrive\Boot") | Out-Null
}

if ($Paths) {
    foreach ($p in $Paths) { $scanRoots.Add($p) | Out-Null }
}

if ($scanRoots.Count -eq 0) {
    throw "No scan roots specified and ESP mount failed. Provide -Paths or run elevated."
}

# Load revocation sets
$revocationSets = New-Object System.Collections.Generic.List[object]

if ($MatchMode -eq 'CurrentDbx' -or $MatchMode -eq 'Both') {
    Write-Host "Loading current DBX..." -ForegroundColor Cyan
    $revocationSets.Add((Get-DbxSetsFromCurrentDbx)) | Out-Null
}

if ($MatchMode -eq 'MsftJson' -or $MatchMode -eq 'Both') {
    Write-Host "Loading Microsoft DBX JSON..." -ForegroundColor Cyan
    $revocationSets.Add((Get-DbxSetsFromMsftJson -Path $MsftJsonPath -Url $MsftJsonUrl)) | Out-Null
}

foreach ($s in $revocationSets) {
    Write-Host ("Loaded {0}: SHA256-like={1}, X509={2}" -f $s.Name, $s.Sha256Set.Count, $s.X509DerSet.Count)
}

Write-Host "Scanning for EFI binaries..." -ForegroundColor Cyan
$efiFiles = Get-EfiFilesUnderPaths -RootPaths $scanRoots.ToArray()
Write-Host ("Found {0} EFI file(s)." -f $efiFiles.Count)

$warnCount = 0
$idx = 0

foreach ($file in $efiFiles) {
    $idx++
    Write-Progress -Activity "Checking EFI files" -Status $file -PercentComplete (($idx / [Math]::Max(1, $efiFiles.Count)) * 100)

    $fileSha = $null

    # Signer cert DER hexes (may be empty)
    $signerDerHexes = @()
    $signerThumbprints = @()
    try {
        $sigs = Get-EfiSignatures -FilePath $file
    	$fileSha =  $sigs.Authentihash
	foreach ($sig in $sigs.Signatures) {
            if ($sig.Signer -and $sig.Signer.RawData) {
                $signerDerHexes += (Get-CertDerHex -Cert $sig.Signer)
                $signerThumbprints += $sig.Signer.Thumbprint
		$thumb = (Get-FileHash -Algorithm SHA1 -InputStream ([IO.MemoryStream]::new($sig.Signer.RawData))).Hash.ToLowerInvariant()
            }
        }
    } catch {}

    $matches = @()

    foreach ($set in $revocationSets) {
        # Hash match
        if ($fileSha -and $set.Sha256Set.Contains($fileSha)) {
            $matches += [PSCustomObject]@{ Source=$set.Name; Type='Hash'; Detail='SHA256(Authenticode) matches revocation list' }
        }

        # Cert match (only meaningful for CurrentDbx unless you add cert data to MsftJson mode)
        if ($signerDerHexes.Count -gt 0 -and $set.X509DerSet.Count -gt 0) {
            foreach ($derHex in $signerDerHexes) {
                if ($set.X509DerSet.Contains($derHex)) {
                    $matches += [PSCustomObject]@{ Source=$set.Name; Type='SignerCert'; Detail='Signer certificate DER matches DBX X509 revocation' }
                    break
                }
            }
        }
    }

    if ($matches.Count -gt 0) {
        $warnCount++
        Write-Host ""
        Write-Host "WARNING: EFI file matches revocation list(s)" -ForegroundColor Yellow
        Write-Host ("  Path: {0}" -f $file)
        if ($fileSha) { Write-Host ("  SHA256 (Authenticode): {0}" -f $fileSha) }
        if ($signerThumbprints.Count -gt 0) {
            Write-Host ("  Signer thumbprint(s): {0}" -f ($signerThumbprints -join ', '))
        }

        foreach ($m in $matches) {
            Write-Host ("  Match: [{0}] {1} - {2}" -f $m.Source, $m.Type, $m.Detail) -ForegroundColor Yellow
        }
    }
}

Write-Host ""
Write-Host ("Scan complete. Warnings: {0}" -f $warnCount) -ForegroundColor Cyan

if ($didMountEsp) {
    try { mountvol s: /d | Out-Null } catch {}
}