# Created by github.com/jcoester
# Repository https://github.com/cjee21/Check-UEFISecureBootVariables

$reset = "$([char]0x1b)[0m"
$yellow = "$([char]0x1b)[93m"
$red   = "$([char]0x1b)[91m"

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

    $Exclude = @(
        'Default String'
        'System Manufacturer'
        'System Product Name'
        'System Version'
        'To Be Filled By O.E.M.'
    )

    # Filter out empty, exclude list, duplications. Return most specific (first of given set)
    $clean = $Values | Where-Object { $_ -and $_ -notin $Exclude } | Select-Object -Unique

    # Filter out substrings of others
    foreach ($v in @($clean)) {
        if ($clean | Where-Object { $_ -ne $v -and $_ -like "*$v*" }) {
            $clean = $clean -ne $v
        }
    }

    $clean | Select-Object -First 1 
}

function Format-DeviceModel([string[]]$Values) {

    # Build tiers, most specific to most generic device info
    $t1 = Format-Set $Values[0,1] # OEMModelNumber, OEMModelBaseBoard 
    $t2 = Format-Set $Values[2,3] # OEMModelSystemFamily, OEMModelSystemVersion 
    $t3 = Format-Set $Values[4] # OEMModelSKU
    $t4 = Format-Set $Values[5] # OEMModelBaseBoardVersion

    # T1 -> T2 -> T3 + T4 as combined fallback 
    $result = if ($t1) { @($t1) } elseif ($t2) { @($t2) } else { @($t3) + @($t4) }
    $result -join ' - '
}

function Show-WindowsVersion {
    $windows = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion"
    "OS : Windows {0} - {1} (Build {2}.{3}) - {4}" -f `
        (Get-WindowsVersionFromBuild ([int]$windows.CurrentBuildNumber)),
        $windows.DisplayVersion,
        $windows.CurrentBuildNumber,
        $windows.UBR,
        (Show-SystemPartitioning)
}

function Get-PartitionStyle {
    param([string]$DriveLetter = $env:SystemDrive.TrimEnd(':'))
    (Get-Disk -Number (Get-Partition -DriveLetter $DriveLetter).DiskNumber).PartitionStyle
}

function Show-SystemPartitioning {
    $DriveLetter = $env:SystemDrive.TrimEnd(':').Trim()

    switch(Get-PartitionStyle($DriveLetter)) {
        "GPT" { "$($DriveLetter): GPT" }
        "MBR" { $label = "MBR"; return "$($DriveLetter): $red$label$reset" }
        default { $label = "Can't determine partition style"; return "$yellow$label$reset" }
    }
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
    Get-PartitionStyle,
    Show-DeviceOverview,
    Resolve-ArchName
