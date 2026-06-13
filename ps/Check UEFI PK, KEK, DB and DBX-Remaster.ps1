# Created by github.com/jcoester
# License: MIT
# Repository: https://github.com/cjee21/Check-UEFISecureBootVariables

# Tracking vulnerable certificate presence for Optional Revocations checks
$script:vulnerableCertPresentDB = $null
$script:vulnerableCertPresentDBDefault = $null

# ANSI colors
$reset = "$([char]0x1b)[0m"
$white = "$([char]0x1b)[97m"
$cyan = "$([char]0x1b)[96m"
$yellow = "$([char]0x1b)[93m"
$green = "$([char]0x1b)[92m"
$red   = "$([char]0x1b)[91m"
$gray   = "$([char]0x1b)[90m"

# Check for admin
if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Warning "Insufficient permissions to run this script. Please run as administrator."
    Break
}

function Get-SignatureCN([string]$s) {
    if (-not $s) { return $null }
    ($s -split ',')[0].Trim() -replace '^CN\s*=\s*', ''
}

function Get-SignatureOrg([string]$s) {
    if (-not $s) { return $null }
    ($s -split ',')[1].Trim() -replace '^O\s*=\s*', ''
}

function Get-LatestJsonBySVN {
    param(
        [object]$LocalJson,
        [object]$BaselineJson
    )

    $localMoreRecent = $False

    $local = $LocalJson.svns.version | ForEach-Object { [version]$_ }
    $baseline = $BaselineJson.svns.version | ForEach-Object { [version]$_ }

    # Compare amount of SVNs
    if ($local.Count -gt $baseline.Count) {
        $localMoreRecent = $True
    } else {
        # Compare SVN values
        for ($i = 0; $i -lt $local.Count; $i++) {
            # Immediately determine from first difference
            if ($local[$i] -gt $baseline[$i]) {
                $localMoreRecent = $True
                break
            } elseif ($baseline[$i] -gt $local[$i]) { 
                break 
            }
        }
    }

    # Return latest JSON
    if ($localMoreRecent) {
        return $LocalJson
    } 
    
    return $BaselineJson
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
    
    $b = for ($i = 0; $i -lt $hex.Length; $i += 2) {
        [Convert]::ToByte($hex.Substring($i,2),16)
    }

    $applications = @{
        "612B139DD5598843AB1C185C3CB2EB92" = "Windows Bootmgr SVN"
        "9D2EF8E827E15841A4884C18ABE2F284" = "Windows cdboot SVN"
        "C2CA99C9FE7F6F4981279E2A8A535976" = "Windows wdsmgfw SVN"
    }

    $applicationHash = ($b[1..16] | ForEach-Object { $_.ToString("X2") }) -join ''
    
    $application = $applications[$applicationHash]
    if (-not $application) { $application = "UNKNOWN" }

    $minor = [BitConverter]::ToUInt16($b, 17)
    $major = [BitConverter]::ToUInt16($b, 19)

    [PSCustomObject]@{
        ApplicationName = $application
        ApplicationHash = $applicationHash
        SVN = [version]"$major.$minor"
    }
}

function Get-DaysUntilExpiration($validTo) {
    $now = Get-Date
    $validTo = [datetime]$validTo
    $isValid = $now -le $validTo
    $span = if ($validTo -ge $now) { $validTo - $now } else { $now - $validTo }
    $time = [math]::Floor($span.TotalDays)
    if ($isValid) {
        if ($time -lt 365) { 
            $suffix = if ($time -eq 1) { "" } else { "s" }
            return "$yellow$time day$suffix$reset" # Less than a year: Yellow
        } else { 
            $time = [int]($time / 365)
            $suffix = if ($time -eq 1) { "" } else { "s" }
            return "$green$time year$suffix$reset" # Longer than a year: Green
        }
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

    # Current DBX for Current lookup, Default DBX for Defaults.
    if ($Key -like "*Default*") { $reference = "DBXDefault" } else { $reference = "DBX" }

    # UEFI values
    $Values = $UEFI_Values[$Key]

    # Check against Microsoft Baseline
    foreach ($entry in $Baseline) {
        $name = $entry.Name

        # Found match
        $match = $Values | Where-Object { (Get-SignatureCN $_.Subject) -eq $name }
        $present = $null -ne $match
        
        # Display Microsoft PK only if present. Since there can only be one PK.
        if (($Key -eq "PK" -or $Key -eq "PKDefault") -and -not $match) { continue }

        # Verify SignatureOwner to be Microsoft
        if ($present -and (-not ($Values.SignatureOwner -eq $SignatureOwnerMicrosoft))) {
            Write-Host $red"SignatureOwner not Microsoft, the certificate might impersonate one."
        } 

        # Check if revoked in DBX/DBXDefault
        $revoked = $UEFI_Values[$reference] | Where-Object {
            $_.SignatureOwner -eq $match.SignatureOwner -and
            $_.Subject -eq $match.Subject
        }

        # Show expiration time for current certificates
        if ($Key -like "*Default*") { 
            $expiration = "" 
        } else { 
            $expiration = Get-DaysUntilExpiration $entry.ValidTo 
        }

        # Status text
        if ($revoked) {
            $state = "REVOKED"
        } elseif ($present) {
            $state = "PRESENT"
        } else {
            $state = "ABSENT"
        }

        # Status color
        $color = switch ($state) {
            "REVOKED" { $red }
            "PRESENT" { $green }
            "ABSENT"  { $gray }
        }

        # Add asterix if cert is marked as vulnerable in Microsoft JSON.
        $revocation = $json.certificates | Where-Object { (Get-SignatureCN $_.subjectName) -eq $name }
        if ($revocation) {
            $name = switch ($state) {
                "REVOKED" { "{0}{1}{2}{3}" -f $name, $gray, "*", $reset } # Successfully revoked
                "PRESENT" { "{0}{1}{2}{3}" -f $name, $red, "*", $reset; # Caution: Vulnerable cert present 
                    if ($reference -eq "DBX") { 
                        $script:vulnerableCertPresentDB = $True # Present in Current DB
                    } elseif ($reference -eq "DBXDefault") { 
                        $script:vulnerableCertPresentDBDefault = $True # Present in Default DB
                    }
                }
                "ABSENT"  { "{0}{1}{2}{3}" -f $name, $gray, "*", $reset } # Successfully removed, or never added
            } 
        }

        $msTag = "$($entry.Tag)$reset" # MS cert identification tag
        $status = "$color$state$reset"

        "{0,-16} {1,-38} [{2}] {3}" -f $status, $name, $msTag, $expiration
    }

    # Remaining certs, outside of Microsoft Baseline
    $remaining = $Values | Where-Object { (Get-SignatureCN $_.Subject) -notin ($Baseline | ForEach-Object { $_.Name }) }
    foreach ($entry in $remaining) {
        $name = Get-SignatureCN $entry.Subject

        # Automatically present
        $state = "PRESENT"

        # Show expiration time only for current certificates, not default
        if ($Key -like "*Default*") { 
            $expiration = "" 
        } else { 
            $expiration = Get-DaysUntilExpiration $entry.ValidTo 
        }

        $nonMsTag = "$gray$(Get-SignatureOrg $entry.Subject)$reset" # Non-MS cert organization
        $status = "{0}{1}{2}" -f $green, $state, $reset 

        "{0,-16} {1,-38} [{2}] {3}" -f $status, $name, $nonMsTag, $expiration
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

    # All UEFI DBX revocations
    $UEFI_DBX_EFI_SET = @{}; $UEFI_Values[$Key].Where({ $_.SignatureOwner -ne "9d132b6c-59d5-4388-ab1c-185cfcb2eb92" }) | 
        ForEach-Object { if ($_.Hash) { $UEFI_DBX_EFI_SET[$_.Hash] = $True }}
    $UEFI_DBX_CERT_SET = @{}; $UEFI_Values[$Key] | ForEach-Object { if ($_.Subject) { $UEFI_DBX_CERT_SET[$_.Subject] = $True }}
    $UEFI_DBX_SVN_SET = @{}; $UEFI_Values[$Key].Where({ $_.SignatureOwner -eq "9d132b6c-59d5-4388-ab1c-185cfcb2eb92" }) | 
        ForEach-Object { if ($_.Hash) { $UEFI_DBX_SVN_SET[$_.Hash] = $True }}
    $UEFI_DBX_SVN_APPS = @{}; foreach ($entry in $UEFI_DBX_SVN_SET.GetEnumerator()) {
    if (($appHash = (Split-SVNEntry $entry.Name).ApplicationHash)) {
        $UEFI_DBX_SVN_APPS[$appHash] = $True}}

    # --- EFI Images ---
    # Check against full JSON revocations # While Microsoft version is broken
    $DBX_Full_Matches = @() 
    $DBX_Full_Missing = @()
    foreach ($hash in $JSON_DBX_FULL_HASHSET.Keys) { 
        if ($UEFI_DBX_EFI_SET.ContainsKey($hash)) { 
            $DBX_Full_Matches += $hash 
        } else { 
            $DBX_Full_Missing += $hash 
        } 
    }

    #  Display mandatory revocation results
    Write-Host ("{0,-20} : " -f "Entire revocations") -NoNewline    
    if ($DBX_Full_Missing.Count -eq 0) {
        $label = "SUCCESS: $($DBX_Full_Matches.Count) revocations detected." 
        Write-Host "$green$label" 
    } else {
        $label = "FAIL: $($DBX_Full_Missing.Count) revocations missing, $($DBX_Full_Matches.Count) detected." 
        Write-Host "$red$label"
    }

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
        $label = "SUCCESS: $($DBX_Mandatory_Matches.Count) revocations detected." 
        Write-Host "$green$label" 
    } else {
        $label = "FAIL: $($DBX_Mandatory_Missing.Count) revocations missing, $($DBX_Mandatory_Matches.Count) detected." 
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
            $label = "SUCCESS: $($DBX_Optional_Matches.Count) revocations detected." 
            Write-Host "$green$label" 
        } else { 
            $label = "FAIL: $($DBX_Optional_Missing.Count) revocations missing, $($DBX_Optional_Matches.Count) detected." 
            Write-Host "$red$label" 
        }

    } else {
        $label = "Only applicable if vulnerable certificate present."
        Write-Host "$gray$label$reset"
    }
    
    # --- SVNs ---
    # Read highest UEFI SVNs for each Application, e.g. Bootmgr might have multiple historical entries with increasing SVN.
    $UEFI_SVN_LOOKUP = @{}
    foreach ($entry in $UEFI_DBX_SVN_SET.GetEnumerator()) {
        $obj = Split-SVNEntry $entry.Name
        if (-not $UEFI_SVN_LOOKUP.ContainsKey($obj.ApplicationHash) -or $obj.SVN -gt $UEFI_SVN_LOOKUP[$obj.ApplicationHash].SVN) { 
            $UEFI_SVN_LOOKUP[$obj.ApplicationHash] = $obj 
        }
    }

    # Check UEFI SVNs against Microsoft JSON baseline
    foreach ($entry in $json.svns) {
        $json = Split-SVNEntry $entry.Value
        $fw = $UEFI_SVN_LOOKUP[$json.ApplicationHash]

        Write-Host ("{0,-20} : " -f $json.ApplicationName) -NoNewline
        # UEFI SVN applied 
        if ($fw) {
            # UEFI meets JSON Baseline: Compliant
            if ($fw.SVN -ge $json.SVN) {
                Write-Host $green$($fw.SVN)
            # UEFI lower than JSON Baseline: Not compliant, Show target version
            } else {
                Write-Host "$red$($fw.SVN) (Target $($json.SVN))"
            }
        # UEFI SVN not applied
        } else {
            $label = "Not applied"
            Write-Host $red$label
        }
    }

    ("{0,-20} : {1} EFI images, {2} certificates, {3} SVNs from {4} apps") -f 
        "Revocation summary", 
        ($UEFI_DBX_EFI_SET.Count), 
        $UEFI_DBX_CERT_SET.Count,
        $UEFI_DBX_SVN_SET.Count, 
        $UEFI_DBX_SVN_APPS.Count
}

# Read UEFI once; 'dbt' and 'dbtDefault' omitted.
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

# Determine which JSON (GitHub, Local) is more recent
$json = Get-LatestJsonBySVN $localJson $baselineJson

# MS Signature
$SignatureOwnerMicrosoft = "77fa9abd-0359-4d32-bd60-28f4e78f784b"

# Expected Microsoft certs
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

# Determine arch for the correct revocation hashes
$archWin = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\Servicing\DeviceAttributes" -ErrorAction SilentlyContinue).OSArchitecture
$archMap = @{
    "amd64" = "x64"
    "x86"   = "ia32"
    "arm64" = "aarch64"
    "arm"   = "arm"
}
$archJson = $archMap[$archWin]

# Full revocations while Microsoft JSON versioning is faulty
$JSON_DBX_FULL_HASHSET = @{}; $json.images.$archJson | 
    ForEach-Object { $JSON_DBX_FULL_HASHSET[$_.authenticodeHash] = $True }

# Mandatory revocations
$JSON_DBX_MANDATORY_HASHSET = @{}; $json.images.$archJson | 
    Where-Object { -not $_.PSObject.Properties['isOptional']} | 
    ForEach-Object { $JSON_DBX_MANDATORY_HASHSET[$_.authenticodeHash] = $True }

# Optional revocations (for certificates that are expected to be revoked)
$JSON_DBX_OPTIONAL_HASHSET = @{}; $json.images.$archJson | 
    Where-Object { $_.PSObject.Properties['isOptional']} | 
    ForEach-Object { $JSON_DBX_OPTIONAL_HASHSET[$_.authenticodeHash] = $True }

# Display PK, KEK, DB, DBX
Spacer
Show-UEFICerts -Title "Current PK"   -Baseline $MicrosoftPK   -Key "PK"
Write-Host
Show-UEFICerts -Title "Default PK"   -Baseline $MicrosoftPK   -Key "PKDefault"
Spacer
Show-UEFICerts -Title "Current KEK"  -Baseline $MicrosoftKEK  -Key "KEK"
Write-Host
Show-UEFICerts -Title "Default KEK"  -Baseline $MicrosoftKEK  -Key "KEKDefault"
Spacer
Show-UEFICerts -Title "Current DB"   -Baseline $MicrosoftDB   -Key "DB"

# Certificate revocation disclaimer
if ($script:vulnerableCertPresentDB) {
    Write-Host ("{0}*CAUTION: Vulnerable certificate expected to be REVOKED or REMOVED." -f $red, $gray)
} else {
    Write-Host ("{0}*Vulnerable certificate in expected state." -f $gray)
}

Write-Host
Show-UEFICerts -Title "Default DB"   -Baseline $MicrosoftDB   -Key "DBDefault"
Spacer
Show-UEFIDBX -Title "Current DBX"  -Key "dbx"
Write-Host
Show-UEFIDBX -Title "Default DBX"  -Key "dbxDefault"
Spacer
