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
$v = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
"Windows version: {0} (Build {1}.{2})`n" -f $v.DisplayVersion, $v.CurrentBuildNumber, $v.UBR

Write-Host "UEFISecureBootEnabled    :" (Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\State).UEFISecureBootEnabled
"AvailableUpdates         : 0x{0:X4}" -f (Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot).AvailableUpdates
Write-Host "UEFICA2023Status         :" (Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\Servicing).UEFICA2023Status
Write-Host "WindowsUEFICA2023Capable : " -NoNewline
switch ((Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\Servicing).WindowsUEFICA2023Capable) {
    1 { "Windows UEFI CA 2023 cert is in DB" }
    2 { "Windows UEFI CA 2023 cert is in DB, system is starting from 2023 signed boot manager" }
    Default { "Windows UEFI CA 2023 cert is not in DB" }
}

Write-Host ""

Import-Module -Force "$PSScriptRoot\Get-BootMgrSecurityVersion.psm1"
Import-Module -Force "$PSScriptRoot\Get-EfiSignatures.psm1"

function Get-AuthenticodeSignatureSignerCertificateIssuerCN {
    param(
        [Parameter(Mandatory=$true)]
        [String]$FilePath
    )
    $Issuers = ""
    $hash_sigs = Get-EfiSignatures -FilePath $FilePath
    foreach ($sig in $hash_sigs.Signatures) {
        if ($Issuers) { 
            $Issuers += ", " 
        }
        $Issuers += [regex]::Match($sig.Signer.Issuer, 'CN=([^,]+)').Groups[1].Value
    }
    $Issuers
}

function Get-UnassignedDriveLetter {
    $used = Get-PSDrive -PSProvider FileSystem | Select-Object -ExpandProperty Name
    
    # Use drive S: if it is available
    if ('S' -notin $used) {
        return 'S:'
    }

    # Fallback: Search for an unassigned letter from the middle of the alphabet
    $alphabet = 68..90 | ForEach-Object { [char]$_ } # Search from D to Z
    $free = @($alphabet | Where-Object { $_ -notin $used })
    if ($free.Count -eq 0) {
        throw "No free drive letters to mount safely to."
    }
    $target = $free[[int]($free.Count / 2)]
    return "${target}:"
}

# Track our mounting state
$mountedByUs = $false
$targetDrive = $null

# Check if the ESP is already mounted and mount if not already mounted
$ESPMountStatus = (mountvol | Out-String) -split "`r?`n" | Where-Object { $_ -match 'EFI' } | Select-Object -Last 1
if ($ESPMountStatus -match '([A-Z]):\\') {
    $driveLetter = $Matches[1]
    $targetDrive = "${driveLetter}:"
    Write-Host "The EFI System Partition is already mounted at ${targetDrive}.`n" -ForegroundColor Cyan
} else {
    $targetDrive = Get-UnassignedDriveLetter
    Write-Host "The EFI System Partition is not mounted. Mounting to ${targetDrive}.`n" -ForegroundColor Yellow
    & mountvol "${targetDrive}" /S
    $mountedByUs = $true
}

try {

    $efiBootPath = "${targetDrive}\EFI\Microsoft\Boot"

    $bootmgfw_verinfo = (Get-Item -Path "$efiBootPath\bootmgfw.efi").VersionInfo
    $bootmgfw_sigCA_name = Get-AuthenticodeSignatureSignerCertificateIssuerCN "$efiBootPath\bootmgfw.efi"
    $bootmgfw_svn_ver = Get-BootMgrSecurityVersion -Path "$efiBootPath\bootmgfw.efi"

    $bootmgr_verinfo = (Get-Item -Path "$efiBootPath\bootmgr.efi").VersionInfo
    $bootmgr_sigCA_name = Get-AuthenticodeSignatureSignerCertificateIssuerCN "$efiBootPath\bootmgr.efi"
    $bootmgr_svn_ver = Get-BootMgrSecurityVersion -Path "$efiBootPath\bootmgr.efi"

    $memtest_verinfo = (Get-Item -Path "$efiBootPath\memtest.efi").VersionInfo
    $memtest_sigCA_name = Get-AuthenticodeSignatureSignerCertificateIssuerCN "$efiBootPath\memtest.efi"

    $bootmgfw_ver = $bootmgfw_verinfo.FileVersion
    $bootmgfw_ver_raw = $bootmgfw_verinfo.FileVersionRaw
    Write-Host "bootmgfw version         : $bootmgfw_ver"
    Write-Host "bootmgfw raw version     : $bootmgfw_ver_raw"
    Write-Host "bootmgfw signature CA    : $bootmgfw_sigCA_name"
    Write-Host "bootmgfw SVN             : $bootmgfw_svn_ver"

    Write-Host ""

    $bootmgr_ver = $bootmgr_verinfo.FileVersion
    $bootmgr_ver_raw = $bootmgr_verinfo.FileVersionRaw
    Write-Host "bootmgr version          : $bootmgr_ver"
    Write-Host "bootmgr raw version      : $bootmgr_ver_raw"
    Write-Host "bootmgr signature CA     : $bootmgr_sigCA_name"
    Write-Host "bootmgr SVN              : $bootmgr_svn_ver"

    Write-Host ""

    $memtest_ver = $memtest_verinfo.FileVersion
    $memtest_ver_raw = $memtest_verinfo.FileVersionRaw
    Write-Host "memtest version          : $memtest_ver"
    Write-Host "memtest raw version      : $memtest_ver_raw"
    Write-Host "memtest signature CA     : $memtest_sigCA_name"

    Write-Host ""

    Import-Module -Force "$PSScriptRoot\Get-UEFIDatabaseSignatures.psm1"
    Import-Module -Force "$PSScriptRoot\Get-SVNfromDBX.psm1"

    $StagedSVNbytes = [IO.File]::ReadAllBytes('C:\Windows\System32\SecureBootUpdates\DBXUpdateSVN.bin')
    $staged_svn = Get-SVNfromDBX (Get-UEFIDatabaseSignatures -BytesIn $StagedSVNbytes)

    Write-Host "Staged BootMgr SVN       : $($staged_svn.BootMgr.Version)"
    Write-Host "Staged CDBoot SVN        : $($staged_svn.CDBoot.Version)"
    Write-Host "Staged WDSMgFw SVN       : $($staged_svn.WDSMgFw.Version)"

    Write-Host ""

} catch {
    Write-Error "An exception has occured: $_"
} finally {
    # Guaranteed cleanup
    if ($mountedByUs) {
        Write-Host "Cleaning up: Unmounting the EFI System Partition from ${targetDrive} because we mounted it." -ForegroundColor Yellow
        & mountvol "${targetDrive}" /D
    } else {
        Write-Host "Cleanup skipped: The EFI System Partition was already mounted before we started." -ForegroundColor Cyan
    }
}
