# Created by github.com/cjee21 
# License: MIT

# Check for admin
Write-Host "Checking for Administrator permission..."
if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Warning "Insufficient permissions to run this script. Please run as administrator."
    Break
} else {
    Write-Host "Running as administrator — continuing execution...`n"
}

# Print computer info
Get-Date -Format 'dd MMMM yyyy'
$computer = gwmi Win32_ComputerSystem
$bios = gwmi Win32_BIOS
"Manufacturer: " + $computer.Manufacturer
"Model: " + $computer.Model
$biosinfo = $bios.Manufacturer , $bios.Name , $bios.SMBIOSBIOSVersion , $bios.Version -join ", "
"BIOS: " + $biosinfo
$v = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
"Windows version: {0} (Build {1}.{2}) `n" -f $v.DisplayVersion, $v.CurrentBuildNumber, $v.UBR

$bold = "$([char]0x1b)[1m"
$reset = "$([char]0x1b)[0m"
$check = "$([char]0x1b)[92m$([char]8730)$reset"
$cross =  "$([char]0x1b)[91mX$reset"

function Show-UEFICertIsPresent {
    param (
        [Parameter(Mandatory)]
        [string]$SecureBootUEFIVar,
        [Parameter(Mandatory)]
        [string]$CertName
    )
    if([System.Text.Encoding]::ASCII.GetString((Get-SecureBootUEFI $SecureBootUEFIVar).bytes) -match $CertName) {
        $revoked = [System.Text.Encoding]::ASCII.GetString((Get-SecureBootUEFI dbx).bytes) -match $CertName
        Write-Host "$check $CertName (revoked: $revoked)"
    } else {
        Write-Host "$cross $CertName"
    }
}

Write-Host $bold'Current UEFI KEK'$reset
Show-UEFICertIsPresent -SecureBootUEFIVar KEK -CertName 'Microsoft Corporation KEK CA 2011'
Show-UEFICertIsPresent -SecureBootUEFIVar KEK -CertName 'Microsoft Corporation KEK 2K CA 2023'

Write-Host ""
Write-Host $bold'Default UEFI KEK'$reset
Show-UEFICertIsPresent -SecureBootUEFIVar KEKDefault -CertName 'Microsoft Corporation KEK CA 2011'
Show-UEFICertIsPresent -SecureBootUEFIVar KEKDefault -CertName 'Microsoft Corporation KEK 2K CA 2023'

Write-Host ""
Write-Host $bold'Current UEFI DB'$reset
Show-UEFICertIsPresent -SecureBootUEFIVar db -CertName 'Microsoft Windows Production PCA 2011'
Show-UEFICertIsPresent -SecureBootUEFIVar db -CertName 'Microsoft Corporation UEFI CA 2011'
Show-UEFICertIsPresent -SecureBootUEFIVar db -CertName 'Windows UEFI CA 2023'
Show-UEFICertIsPresent -SecureBootUEFIVar db -CertName 'Microsoft UEFI CA 2023'

Write-Host ""
Write-Host $bold'Default UEFI DB'$reset
Show-UEFICertIsPresent -SecureBootUEFIVar dbDefault -CertName 'Microsoft Windows Production PCA 2011'
Show-UEFICertIsPresent -SecureBootUEFIVar dbDefault -CertName 'Microsoft Corporation UEFI CA 2011'
Show-UEFICertIsPresent -SecureBootUEFIVar dbDefault -CertName 'Windows UEFI CA 2023'
Show-UEFICertIsPresent -SecureBootUEFIVar dbDefault -CertName 'Microsoft UEFI CA 2023'

Write-Host ""
Write-Host $bold'Current UEFI DBX (only the latest one is needed to be secure)'$reset
Write-Host "2023-03-14: " -NoNewline
& $PSScriptRoot'\Check-Dbx-Simplified.ps1' $PSScriptRoot'\x64_DBXUpdate_03142023.bin'
Write-Host "2023-05-09: " -NoNewline
& $PSScriptRoot'\Check-Dbx-Simplified.ps1' $PSScriptRoot'\x64_DBXUpdate_05092023.bin'
Write-Host "2025-01-14: " -NoNewline
& $PSScriptRoot'\Check-Dbx-Simplified.ps1' $PSScriptRoot'\x64_DBXUpdate_01142025.bin'
