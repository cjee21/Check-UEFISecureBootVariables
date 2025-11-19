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

Write-Host "UEFISecureBootEnabled :" (Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\State).UEFISecureBootEnabled
"AvailableUpdates      : 0x{0:X4}" -f (Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot).AvailableUpdates
Write-Host "UEFICA2023Status      :" (Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\Servicing).UEFICA2023Status

Write-Host ""

mountvol s: /s

# $bootmgfw_sigCA = (Get-AuthenticodeSignature -FilePath S:\EFI\Microsoft\Boot\bootmgfw.efi).SignerCertificate.Issuer
# Workaround to get actual signature of bootmgfw.efi as it is also catalogue signed and Get-AuthenticodeSignature returns the catalogue signature
# https://github.com/PowerShell/PowerShell/issues/23820
$bootmgfw_cert = [System.Security.Cryptography.X509Certificates.X509Certificate]::CreateFromSignedFile('S:\EFI\Microsoft\Boot\bootmgfw.efi')
$bootmgfw_sigCA = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($bootmgfw_cert).Issuer

mountvol s: /d

$bootmgfw_sigCA_name = [regex]::Match($bootmgfw_sigCA, 'CN=([^,]+)').Groups[1].Value
Write-Host "bootmgfw signature CA : $bootmgfw_sigCA_name"
