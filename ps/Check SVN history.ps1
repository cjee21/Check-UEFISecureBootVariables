# Created by github.com/jcoester
# License: MIT
# Repository: https://github.com/cjee21/Check-UEFISecureBootVariables

# Check for admin
if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Warning "Insufficient permissions to run this script. Please run as administrator."
    Break
}

Import-Module -Force "$PSScriptRoot\Get-SVNfromDBX.psm1"
try {
    $dbx_raw = Get-SecureBootUEFI dbx -ErrorAction Stop
} catch {
    Write-Host "Exception: $($_.Exception.Message)" -ForegroundColor Red
    Break # No need to continue with remaining DBX-related checks of script if failed to obtain DBX data
}

Import-Module -Force "$PSScriptRoot\Get-UEFIDatabaseSignatures.psm1"
$dbx_list = $dbx_raw | Get-UEFIDatabaseSignatures
$dbx_svns = @(
    $dbx_list |
    Where-Object { $_.SignatureType -eq 'EFI_CERT_SHA256_GUID' } |
    ForEach-Object {
        $_.SignatureList |
        Where-Object { $_.SignatureOwner -eq [guid]$SVN_OWNER_GUID }
    } |
    ForEach-Object { $_.SignatureData }
)

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
    # Sample: 01|612B139DD5598843AB1C185C3CB2EB92|0000|0800|0000000000000000000000
    # Sample interpretated as "Windows Bootmgr SVN 8.0"
    
    $b = for ($i = 0; $i -lt $hex.Length; $i += 2) {
        [Convert]::ToByte($hex.Substring($i,2),16)
    }

    $applications = @{
        "612B139DD5598843AB1C185C3CB2EB92" = "Windows Bootmgr"
        "9D2EF8E827E15841A4884C18ABE2F284" = "Windows cdboot"
        "C2CA99C9FE7F6F4981279E2A8A535976" = "Windows wdsmgfw"
    }
    
    $application = $applications[($b[1..16] | ForEach-Object { $_.ToString("X2") }) -join '']
    if (-not $application) { $application = "UNKNOWN" }

    $minor = [BitConverter]::ToUInt16($b, 17)
    $major = [BitConverter]::ToUInt16($b, 19)

    [PSCustomObject]@{
        Application = $application
        Major = $major
        Minor = $minor
        SVN = "$major.$minor"
	    Raw = $hex
    }
}

""
"{0} SVNs" -f $dbx_svns.Count
""

# Chronological view
$dbx_svns |
ForEach-Object { Split-SVNEntry $_ } |
Select-Object `
    @{Name="Application History"; Expression={$_.Application}}, SVN, Raw |
Format-Table -AutoSize

# Progression view
$dbx_svns |
ForEach-Object { Split-SVNEntry $_ } |
Group-Object Application |
ForEach-Object {
    $history = $_.Group |
        Sort-Object Major, Minor |
        Select-Object -ExpandProperty SVN

    [PSCustomObject]@{
        Application = $_.Name
        "SVN History" = ($history -join " > ")
        "Current SVN" = ($history | Select-Object -Last 1)
    }
} | Format-Table -AutoSize
