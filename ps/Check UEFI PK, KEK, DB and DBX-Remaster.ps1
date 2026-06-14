# Created by github.com/jcoester
# License: MIT
# Repository: https://github.com/cjee21/Check-UEFISecureBootVariables

# Tracking vulnerable certificate presence
$script:vulnerableCertPresentDB = $null
$script:vulnerableCertPresentDBDefault = $null

# ANSI colors
$reset = "$([char]0x1b)[00m"
$white = "$([char]0x1b)[97m"
$yellow = "$([char]0x1b)[93m"
$green = "$([char]0x1b)[92m"
$red   = "$([char]0x1b)[91m"
$gray   = "$([char]0x1b)[90m"

# Check for admin
if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Warning "Insufficient permissions to run this script. Please run as administrator."
    Break
}

function Get-SignatureCN {
    param([string]$s)

    if (-not $s) { return $null }
    ($s -split ',')[0].Trim() -replace '^CN\s*=\s*', ''
}

function Get-SignatureOrg {
    param([string]$s)

    if (-not $s) { return $null }
    ($s -split ',')[1].Trim() -replace '^O\s*=\s*', ''
}

function Get-LatestJsonBySVN {
    param(
        [object]$FirstJson,
        [object]$SecondJson # Default
    )

    $firstMoreRecent = $False

    $first = $FirstJson.svns.version | ForEach-Object { [version]$_ }
    $second = $SecondJson.svns.version | ForEach-Object { [version]$_ }

    # Compare amount of SVNs
    if ($first.Count -gt $second.Count) {
        $firstMoreRecent = $True
    } else {
        # Compare SVN values
        for ($i = 0; $i -lt $first.Count; $i++) {
            # Immediately determine on first difference
            if ($first[$i] -gt $second[$i]) {
                $firstMoreRecent = $True
                break
            } elseif ($second[$i] -gt $first[$i]) { 
                break 
            }
        }
    }

    if ($firstMoreRecent) {
        return $FirstJson # First if more recent
    } 
    
    return $SecondJson # Default
}

function Split-SVNEntry {
    param([string]$hex)
    
    # Reference: https://github.com/microsoft/secureboot_objects/blob/main/PreSignedObjects/DBX/HashesJsonSchema.json
    # Byte[0] is the UINT8 version of the SVN_DATA structure. 
    # Bytes[1...16] are the GUID of the application being revoked. Little endian. 
    # Bytes[17...18] are the Minor SVN number. Litte endian UINT16.
    # Bytes[19...20] are the Major SVN number. Litte endian UINT16.
    # Bytes[21...31] are 11 zero bytes padding."

    # Interpretation: 1 Byte = 2 Hex Digits
    # Sample: 00|1.............GUID............16|1718|1920|21......Padding.....31
    # Sample: 01|612B139DD5598843AB1C185C3CB2EB92|0000|0900|0000000000000000000000
    # Sample interpretated as "Windows Bootmgr SVN 9.0"
    
    $b = for ($i = 0; $i -lt $hex.Length; $i += 2) { [Convert]::ToByte($hex.Substring($i,2),16) }

    $applications = @{
        "612B139DD5598843AB1C185C3CB2EB92" = "Windows Bootmgr SVN"
        "9D2EF8E827E15841A4884C18ABE2F284" = "Windows cdboot SVN"
        "C2CA99C9FE7F6F4981279E2A8A535976" = "Windows wdsmgfw SVN"
    }

    $applicationHash = ($b[1..16] | ForEach-Object { $_.ToString("X2") }) -join ''
    
    $application = $applications[$applicationHash]
    if (-not $application) { $application = $applicationHash } # Return the hash if name not recognized

    $minor = [BitConverter]::ToUInt16($b, 17)
    $major = [BitConverter]::ToUInt16($b, 19)

    [PSCustomObject]@{
        ApplicationName = $application
        ApplicationHash = $applicationHash
        SVN = [version]"$major.$minor"
    }
}

function Get-TimeUntilExpiration {
    param(
        [datetime]$validTo,
        [string]$Key
    )

    # Skip for Default PK, KEK, DB. Only Current
    if ($Key -like "*Default*") { return "" }
        
    $now = Get-Date
    $time = [math]::Floor(($validTo - $now).TotalDays)
    
    # Not expired yet
    if ($now -le $validTo) {
        if ($time -lt 365) { 
            $suffix = if ($time -eq 1) { "" } else { "s" }
            return "$yellow$time day$suffix$reset" # Less than a year: n day(s)
        } else { 
            $time = [int]($time / 365)
            $suffix = if ($time -eq 1) { "" } else { "s" }
            return "$green$time year$suffix$reset" # Longer than a year: n year(s)
        }
    # Already expired
    } else {
        $text = "Expired"
        return "$yellow$text$reset"
    }
}

function Show-UEFICerts {
    param(
        [string]$Title,
        [array]$Baseline,
        [string]$Key
    )

    # Title
    if ($UEFI_Values[$Key]) { 
        Write-Host "$white$Title"
    } else {
        Write-Host "$yellow$Title not available"
        return 
    }

    # Lookup DBX / DBXDefault 
    if ($Key -like "*Default*") { $reference = "DBXDefault" } else { $reference = "DBX" }

    # UEFI values
    $Values = $UEFI_Values[$Key]

    # Check against Microsoft baseline
    foreach ($entry in $Baseline) {
        
        $name = $entry.Name # Cert CN
        $tag = "$reset$($entry.Tag)$reset" # MS Baseline identification tag, ensure length as other tags

        # Found match
        $match = $Values | Where-Object { (Get-SignatureCN $_.Subject) -eq $name }
        $present = $null -ne $match
        
        # Display Microsoft PK baseline only if present. Since there can only be one PK.
        if (($Key -eq "PK" -or $Key -eq "PKDefault") -and -not $match) { continue }

        # Verify SignatureOwner to be Microsoft
        if ($present -and (-not ($Values.SignatureOwner -eq $SignatureOwnerMicrosoft))) {
            Write-Host $red"SignatureOwner not Microsoft, the certificate might impersonate one."
        }

        # Check if revoked in reference: DBX or DBXDefault
        $revoked = $UEFI_Values[$reference] | Where-Object {
            $_.SignatureOwner -eq $match.SignatureOwner -and
            $_.Subject -eq $match.Subject
        }

        # Assign text and color
        if ($revoked) {
            $state = "REVOKED"
            $color = $red
        } elseif ($present) {
            $state = "PRESENT"
            $color = $green
        } else {
            $state = "ABSENT"
            $color = $gray
        }

        # Add asterix if cert is marked vulnerable in Microsoft JSON.
        $vulnerable = $json.certificates | Where-Object { (Get-SignatureCN $_.subjectName) -eq $name }
        if ($vulnerable) {
            $name = switch ($state) {
                "ABSENT"  { "$name$gray*$reset" } # Recommended state for vulnerable cert
                "REVOKED" { "$name$gray*$reset" } # Recommended state for vulnerable cert
                "PRESENT" { "$name$red*$reset"; # CAUTION state for vulnerable cert
                    if ($reference -eq "DBX") { 
                        $script:vulnerableCertPresentDB = $True 
                    } else { 
                        $script:vulnerableCertPresentDBDefault = $True 
                    }
                }
            } 
        } else { $name = "$name$reset$reset" } # Reserve same space without revocation asterix

        "{0,-17} {1,-48} {2} {3}" -f 
            "$color$state$reset", $name, "[$tag]", (Get-TimeUntilExpiration $entry.ValidTo $Key)
    }

    # Remaining certs, outside of Microsoft Baseline
    $remaining = $Values | Where-Object { (Get-SignatureCN $_.Subject) -notin ($Baseline | ForEach-Object { $_.Name }) }
    foreach ($entry in $remaining) {

        $name = Get-SignatureCN $entry.Subject # Cert CN
        $tag = "$gray$(Get-SignatureOrg $entry.Subject)$reset" # Cert O

        # Check if revoked in reference: DBX or DBXDefault
        $revoked = $UEFI_Values[$reference] | Where-Object {
            $_.SignatureOwner -eq $match.SignatureOwner -and
            $_.Subject -eq $match.Subject
        }

        # Assign text and color
        if ($revoked) {
            $state = "REVOKED"
            $color = $red
        } else {
            $state = "PRESENT"
            $color = $green
        } 

        "{0,-17} {1,-48} {2} {3}" -f 
            "$color$state$reset", "$name$reset$reset", "[$tag]", (Get-TimeUntilExpiration $entry.ValidTo $Key)
    }
}

function Show-UEFIDBX {
    param(
        [Parameter(Mandatory)]
        [string]$Title,

        [Parameter(Mandatory)]
        [string]$Key
    )

    # Title
    if ($UEFI_Values[$Key]) { 
        Write-Host "$white$Title"
    } else {
        Write-Host "$yellow$Title not available"
        return 
    }

    # EFI images (All Hashes excluding SVN hashes)
    $UEFI_DBX_EFI_SET = @{}; $UEFI_Values[$Key].Where({ $_.SignatureOwner -ne "9d132b6c-59d5-4388-ab1c-185cfcb2eb92" }) | 
        ForEach-Object { if ($_.Hash) { $UEFI_DBX_EFI_SET[$_.Hash] = $True }}
    # Certificates
    $UEFI_DBX_CERT_SET = @{}; $UEFI_Values[$Key] | ForEach-Object { if ($_.Subject) { $UEFI_DBX_CERT_SET[$_.Subject] = $True }}
    # SVN hashes
    $UEFI_DBX_SVN_SET = @{}; $UEFI_Values[$Key].Where({ $_.SignatureOwner -eq "9d132b6c-59d5-4388-ab1c-185cfcb2eb92" }) | 
        ForEach-Object { if ($_.Hash) { $UEFI_DBX_SVN_SET[$_.Hash] = $True }}
    # Apps derived SVN hashes
    $UEFI_DBX_SVN_APPS = @{}; foreach ($entry in $UEFI_DBX_SVN_SET.GetEnumerator()) {
        if (($appHash = (Split-SVNEntry $entry.Name).ApplicationHash)) { $UEFI_DBX_SVN_APPS[$appHash] = $True}
    }

    # --- EFI Images ---
    # Check against mandatory JSON revocations
    $DBX_Mandatory_Matches = @() 
    $DBX_Mandatory_Missing = @()
    foreach ($hash in $JSON_DBX_MANDATORY_HASHSET.Keys) { 
        if ($UEFI_DBX_EFI_SET.ContainsKey($hash)) { 
            $DBX_Mandatory_Matches += $hash 
        } else { 
            $DBX_Mandatory_Missing += $hash 
        } 
    }
    #  Display mandatory revocation results
    Write-Host ("{0,-20} : " -f "Main revocations") -NoNewline    
    if ($DBX_Mandatory_Missing.Count -eq 0) {
        $label = "SUCCESS: $($DBX_Mandatory_Matches.Count) successes." 
        Write-Host "$green$label" 
    } else {
        $label = "FAIL: $($DBX_Mandatory_Missing.Count) missing, $($DBX_Mandatory_Matches.Count) successes." 
        Write-Host "$red$label"
    }

    # Check against optional JSON revocations (matters only if vulnerable cert is present)
    Write-Host ("{0,-20} : " -f "Optional revocations") -NoNewline
    if (($script:vulnerableCertPresentDB -and $Key -eq "DBX") -or
        ($script:vulnerableCertPresentDBDefault -and $Key -eq "DBXDefault")) {

        $DBX_Optional_Matches = @()
        $DBX_Optional_Missing = @()
        foreach ($hash in $JSON_DBX_OPTIONAL_HASHSET.Keys) { 
            if ($UEFI_DBX_EFI_SET.ContainsKey($hash)) { 
                $DBX_Optional_Matches += $hash 
            } else { 
                $DBX_Optional_Missing += $hash } 
        }
        # Display optional revocations results
        if ($DBX_Optional_Missing.Count -eq 0) { 
            $label = "SUCCESS: $($DBX_Optional_Matches.Count) successes." 
            Write-Host "$green$label" 
        } else { 
            $label = "FAIL: $($DBX_Optional_Missing.Count) missing, $($DBX_Optional_Matches.Count) successes." 
            Write-Host "$red$label" 
        }

    } else {
        $label = "Only applicable if vulnerable certificate present."
        Write-Host "$gray$label$reset"
    }
    
    # --- SVNs ---
    # Determine high UEFI SVNs for each application, e.g. Bootmgr might have multiple historical entries with increasing SVN.
    $UEFI_SVN_LOOKUP = @{}
    foreach ($entry in $UEFI_DBX_SVN_SET.GetEnumerator()) {
        $obj = Split-SVNEntry $entry.Name
        if (-not $UEFI_SVN_LOOKUP.ContainsKey($obj.ApplicationHash) -or $obj.SVN -gt $UEFI_SVN_LOOKUP[$obj.ApplicationHash].SVN) { 
            $UEFI_SVN_LOOKUP[$obj.ApplicationHash] = $obj }
    }

    # Check UEFI SVNs against Microsoft JSON baseline
    foreach ($entry in $json.svns) {
        $json = Split-SVNEntry $entry.Value
        $fw = $UEFI_SVN_LOOKUP[$json.ApplicationHash]

        Write-Host ("{0,-20} : " -f $json.ApplicationName) -NoNewline
        # UEFI SVN applied 
        if ($fw) {
            # UEFI meets JSON Baseline
            if ($fw.SVN -ge $json.SVN) {
                Write-Host $green$($fw.SVN)
            # UEFI fails JSON Baseline: Show JSON target SVN
            } else {
                Write-Host "$red$($fw.SVN) (Target $($json.SVN))"
            }
        # UEFI SVN not applied
        } else {
            $label = "Not applied"
            Write-Host $red$label
        }
    }

    ("{0,-20} : {1} EFI images, {2} certificates, {3} SVNs for {4} apps") -f 
        "Revocation summary", 
        $UEFI_DBX_EFI_SET.Count, 
        $UEFI_DBX_CERT_SET.Count,
        $UEFI_DBX_SVN_SET.Count, 
        $UEFI_DBX_SVN_APPS.Count
}

# Read Secure Boot UEFI once; 'dbt' and 'dbtDefault' not used.
$UEFI_Keys = @("SecureBoot","SetupMode","PK","PKDefault","KEK","KEKDefault","db","dbDefault","dbx","dbxDefault")
$UEFI_Values = @{}
foreach ($Key in $UEFI_Keys) {
    try {
        $UEFI_Values[$Key] = Get-SecureBootUEFI -Name $Key -Decoded -ErrorAction Stop
    }
    catch {
        $UEFI_Values[$Key] = $null
    }
}

# Print computer info
Import-Module $PSScriptRoot\Get-SystemOverview.psm1 -Force
Show-DeviceOverview
Spacer

# Microsoft JSON baseline from GitHub https://raw.githubusercontent.com/microsoft/secureboot_objects/refs/heads/main/PreSignedObjects/DBX/dbx_info_msft_latest.json
$baselineJson = Get-Content "$PSScriptRoot\..\dbx_info\dbx_info_msft_latest.json" -Raw | ConvertFrom-Json

# Microsoft JSON baseline from local Windows Update rollout
$localJsonPath = (Join-Path (Split-Path (Get-Command Get-SecureBootUEFI).DLL -Parent) "hashes.json") 
$localJson = Get-Content $localJsonPath -Raw | ConvertFrom-Json

# Determine most recent JSON (from GitHub, or local Windows Update rollout)
$json = Get-LatestJsonBySVN $localJson $baselineJson # Second = Default

# MS Signature for certificate verification
$SignatureOwnerMicrosoft = "77fa9abd-0359-4d32-bd60-28f4e78f784b"

# Baseline Microsoft certs
$MicrosoftPK = @(
    @{ Name = "Windows OEM Devices PK"; Tag = "MS-PK"; ValidTo = "2038-09-18 22:28:26Z" }
)
$MicrosoftKEK = @(
    @{ Name = "Microsoft Corporation KEK CA 2011"; Tag = "MS-KEK-2011"; ValidTo = "2026-06-24 22:51:29Z" } 
    @{ Name = "Microsoft Corporation KEK 2K CA 2023"; Tag = "MS-KEK-2023"; ValidTo = "2038-03-02 21:31:35Z" } 
)
$MicrosoftDB = @(
    @{ Name = "Microsoft Windows Production PCA 2011"; Tag = "MS-Windows-2011"; ValidTo = "2026-10-19 20:51:42Z" } 
    @{ Name = "Windows UEFI CA 2023"; Tag = "MS-Windows-2023"; ValidTo = "2035-06-13 21:08:29Z" } 
    @{ Name = "Microsoft Option ROM UEFI CA 2023"; Tag = "MS-OptionROM-2023"; ValidTo = "2038-10-26 21:12:20Z" } 
    @{ Name = "Microsoft Corporation UEFI CA 2011"; Tag = "MS-ThirdParty-2011"; ValidTo = "2026-06-27 23:32:45Z" } 
    @{ Name = "Microsoft UEFI CA 2023"; Tag = "MS-ThirdParty-2023"; ValidTo = "2038-06-13 21:31:47Z" } 
)

# --- Secure Boot Summary ---
# SB-SetupMode
Write-Host "SB :" -NoNewLine
try {
    if ($UEFI_Values["SetupMode"].Value) { 
        Write-Host "$yellow Setup Mode" 
    } else { 
        Write-Host "$white User Mode" 
    }
} catch {
    Write-Host "$red Unknown SetupMode status"
}

# SB-Enabled/Disabled
Write-Host "SB :" -NoNewLine
try {
    if ($UEFI_Values["SecureBoot"].Value) { 
        Write-Host "$green Enabled"
    } else { 
        Write-Host "$red Disabled" 
        # Check for GPT partition style, as MBR will prevent enablement of UEFI/Secure Boot
        Show-PartitionStyleDisclaimer
    }
} catch {
    Write-Host "$red Unknown Secure Boot status"
}

# Show Secure Boot servicing flags, parsed and color-coded
Show-UEFICA2023Status "SB : " 
Show-WindowsUEFICA2023Capable "SB : "
Show-AvailableUpdates "SB : "
Spacer

# Determine arch for the correct EFI revocation hashes
$archWin = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\Servicing\DeviceAttributes" -ErrorAction SilentlyContinue).OSArchitecture
$archMap = @{
    "amd64" = "x64"
    "x86"   = "ia32"
    "arm64" = "aarch64"
    "arm"   = "arm"
}
$archJson = $archMap[$archWin]

# Mandatory revocations
$JSON_DBX_MANDATORY_HASHSET = @{}; $json.images.$archJson | 
    Where-Object { -not $_.PSObject.Properties['isOptional']} | 
    ForEach-Object { $JSON_DBX_MANDATORY_HASHSET[$_.authenticodeHash] = $True }

# Optional revocations (likely for certificates that are expected to be revoked)
$JSON_DBX_OPTIONAL_HASHSET = @{}; $json.images.$archJson | 
    Where-Object { $_.PSObject.Properties['isOptional']} | 
    ForEach-Object { $JSON_DBX_OPTIONAL_HASHSET[$_.authenticodeHash] = $True }

# Display PK, KEK, DB, DBX
Show-UEFICerts -Title "Current PK"   -Baseline $MicrosoftPK   -Key "PK"
Write-Host
Show-UEFICerts -Title "Default PK"   -Baseline $MicrosoftPK   -Key "PKDefault"
Write-Host
Show-UEFICerts -Title "Current KEK"  -Baseline $MicrosoftKEK  -Key "KEK"
Write-Host
Show-UEFICerts -Title "Default KEK"  -Baseline $MicrosoftKEK  -Key "KEKDefault"
Write-Host
Show-UEFICerts -Title "Current DB"   -Baseline $MicrosoftDB   -Key "DB"

# Certificate revocation disclaimer
if ($script:vulnerableCertPresentDB) {
    Write-Host ("{0}*CAUTION: Vulnerable certificate recommended to be ABSENT or REVOKED." -f $red, $gray)
} else {
    Write-Host ("{0}*Vulnerable certificate in recommended state." -f $gray)
}

Write-Host
Show-UEFICerts -Title "Default DB"   -Baseline $MicrosoftDB   -Key "DBDefault"
Write-Host
Show-UEFIDBX -Title "Current DBX"  -Key "dbx"
Write-Host
Show-UEFIDBX -Title "Default DBX"  -Key "dbxDefault"
