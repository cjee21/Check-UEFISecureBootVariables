# Created by github.com/jcoester
# Repository https://github.com/cjee21/Check-UEFISecureBootVariables

function Spacer() {
    Write-Host ("-" * 60)
}

function Get-WindowsVersionFromBuild([int]$Build) {

    # See https://en.wikipedia.org/wiki/List_of_Microsoft_Windows_versions
    switch ($Build) {
        { $_ -ge 22000 } { return "11" }
        { $_ -ge 10240 } { return "10" }
        { $_ -ge 9600 }  { return "8.1" }
        { $_ -ge 9200 }  { return "8" }
        default          { return "" }
    }
}

function Resolve-ArchName {
    param([string]$Arch)

    switch ($Arch.ToUpper()) {
        "AMD64" { "AMD64/X64" }
        "ARM"   { "ARM" }
        "ARM64" { "ARM64/AARCH64" }
        "X86"   { "X86/IA32" }
        default { $Arch }
    }
}

function Format-Set($Values) {

    # Filter out duplicates and junk
    $clean = $Values | Where-Object {
        $_ -and
        $_ -notmatch "to be filled by o\.e\.m\." -and
        $_ -notmatch "default string" -and
        $_ -ne "1.0" # Only applied to hardware, firmware can be '1.0'
    } | Select-Object -Unique

    # Filter out substrings of others
    foreach ($v in @($clean)) {
        if ($clean | Where-Object { $_ -ne $v -and $_ -like "*$v*" }) {
            $clean = $clean -ne $v
        }
    }

    $clean
}

function Format-DeviceModel([string[]]$Values) {

    # Build three tiers, from most specific to most generic
    $t1 = Format-Set $Values[0,1] # OEMModelNumber, OEMModelBaseBoard
    $t2 = Format-Set $Values[2,3] # OEMModelSystemFamily, OEMModelSystemVersion
    $t3 = Format-Set $Values[4,5] # OEMModelSKU, OEMModelBaseBoardVersion

    # T1 and T2 always, T3 as fallback
    $result = if ($t1) { @($t1) + @($t2) } else { @($t3) }
    $result -join ' - '
}

function Show-WindowsVersion {
    $windows = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion"
    "OS : Windows {0} - {1} (Build {2}.{3})" -f `
        (Get-WindowsVersionFromBuild ([int]$windows.CurrentBuildNumber)),
        $windows.DisplayVersion,
        $windows.CurrentBuildNumber,
        $windows.UBR
}

function Show-DeviceOverview {
    (Get-Date).ToString('dd MMM yyyy')
    Spacer
    Show-Device
    Show-WindowsVersion
}

function Show-Device {
    # Show Secure Boot related device hardware and firmware info
    $device  = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\Servicing\DeviceAttributes"

    # Hardware
    "HW : {0} - {1} - {2}" -f `
        ((Format-Set @(
            $device.OEMName
            $device.OEMManufacturerName
            $device.BaseBoardManufacturer
        )) -join " - "),
        (Format-DeviceModel @(
            $device.OEMModelNumber    
            $device.OEMModelBaseBoard
            $device.OEMModelSystemFamily
            $device.OEMModelSystemVersion
            $device.OEMModelSKU
            $device.OEMModelBaseBoardVersion
        )),
        (Resolve-ArchName $device.OSArchitecture)
        
    # Firmware
    "FW : {0} - {1} - {2}" -f `
        $device.FirmwareManufacturer,
        $device.FirmwareVersion,
        ([datetime]$device.FirmwareReleaseDate).ToString('dd MMM yyyy')
}

Export-ModuleMember -Function `
    Spacer,
    Show-WindowsVersion,
    Show-DeviceOverview,
    Resolve-ArchName
