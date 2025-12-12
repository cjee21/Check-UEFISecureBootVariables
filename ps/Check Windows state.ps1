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

Import-Module "$PSScriptRoot\Get-BootMgrSecurityVersion.ps1"

function Get-AuthenticodeSignatureSignerCertificateIssuer {
    param(
        [Parameter(Mandatory=$true)]
        [String]$FilePath
    )
    # $bootmgfw_sigCA = (Get-AuthenticodeSignature -FilePath $FilePath).SignerCertificate.Issuer
    # Workaround to get actual signature of bootmgfw.efi as it is also catalogue signed and Get-AuthenticodeSignature returns the catalogue signature
    # https://github.com/PowerShell/PowerShell/issues/23820
    $cert = [System.Security.Cryptography.X509Certificates.X509Certificate]::CreateFromSignedFile($FilePath)
    [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($cert).Issuer
}

function Get-SVNfromBytes {
    param(
        [Parameter(Mandatory=$true)]
        [System.Array]$SVN_bytes
    )
    $MinorBytes = $SVN_bytes[0..1]
    $svn_ver_minor = [System.BitConverter]::ToInt16($MinorBytes, 0)
    $MajorBytes = $SVN_bytes[2..3]
    $svn_ver_major = [System.BitConverter]::ToInt16($MajorBytes, 0)
    [version]::new($svn_ver_major, $svn_ver_minor)
}

mountvol s: /s

$bootmgfw_verinfo = (Get-Item -Path S:\EFI\Microsoft\Boot\bootmgfw.efi).VersionInfo
$bootmgfw_sigCA = Get-AuthenticodeSignatureSignerCertificateIssuer 'S:\EFI\Microsoft\Boot\bootmgfw.efi'
$bootmgfw_SVN_bytes = Get-BootMgrSecurityVersionBytes -Path S:\EFI\Microsoft\Boot\bootmgfw.efi

$bootmgr_verinfo = (Get-Item -Path S:\EFI\Microsoft\Boot\bootmgr.efi).VersionInfo
$bootmgr_sigCA = Get-AuthenticodeSignatureSignerCertificateIssuer 'S:\EFI\Microsoft\Boot\bootmgr.efi'
$bootmgr_SVN_bytes = Get-BootMgrSecurityVersionBytes -Path S:\EFI\Microsoft\Boot\bootmgr.efi

$memtest_verinfo = (Get-Item -Path S:\EFI\Microsoft\Boot\memtest.efi).VersionInfo
$memtest_sigCA = Get-AuthenticodeSignatureSignerCertificateIssuer 'S:\EFI\Microsoft\Boot\memtest.efi'

mountvol s: /d

$bootmgfw_ver = $bootmgfw_verinfo.FileVersion
Write-Host "bootmgfw version         : $bootmgfw_ver"
$bootmgfw_sigCA_name = [regex]::Match($bootmgfw_sigCA, 'CN=([^,]+)').Groups[1].Value
Write-Host "bootmgfw signature CA    : $bootmgfw_sigCA_name"
$bootmgfw_svn_ver = Get-SVNfromBytes $bootmgfw_SVN_bytes
Write-Host "bootmgfw SVN             : $bootmgfw_svn_ver"

Write-Host ""

$bootmgr_ver = $bootmgr_verinfo.FileVersion
Write-Host "bootmgr version          : $bootmgr_ver"
$bootmgr_sigCA_name = [regex]::Match($bootmgr_sigCA, 'CN=([^,]+)').Groups[1].Value
Write-Host "bootmgr signature CA     : $bootmgr_sigCA_name"
$bootmgr_svn_ver = Get-SVNfromBytes $bootmgr_SVN_bytes
Write-Host "bootmgr SVN              : $bootmgr_svn_ver"

Write-Host ""

$memtest_ver = $memtest_verinfo.FileVersion
Write-Host "memtest version          : $memtest_ver"
$memtest_sigCA_name = [regex]::Match($memtest_sigCA, 'CN=([^,]+)').Groups[1].Value
Write-Host "memtest signature CA     : $memtest_sigCA_name"
