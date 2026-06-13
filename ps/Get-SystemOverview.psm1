# Created by github.com/jcoester
# Repository https://github.com/cjee21/Check-UEFISecureBootVariables
# References:
    # [1] https://support.microsoft.com/topic/registry-key-updates-for-secure-boot-windows-devices-with-it-managed-updates-a7be69c9-4634-42e1-9ca1-df06f43f360d#bkmk_registry_keys_described
    # [2] https://support.microsoft.com/topic/secure-boot-certificate-updates-guidance-for-it-professionals-and-organizations-e2b43f9f-b424-42df-bc6a-8476db65ab2f#bkmk_preparation
    # [3] https://support.microsoft.com/topic/secure-boot-troubleshooting-guide-5d1bf6b4-7972-455a-a421-0184f1e1ed7d#bkmk_the_availableupdates_registry_bitmask
    # [4] https://support.microsoft.com/topic/how-to-manage-the-windows-boot-manager-revocations-for-secure-boot-changes-associated-with-cve-2023-24932-41a975df-beb2-40c1-99a3-b3ff139f832d#bkmk_mitigation_guidelines

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

function Show-PartitionStyleDisclaimer() {
    $DriveLetter = $env:SystemDrive
    $PartitionStyle = (Get-Disk -Number (Get-Partition -DriveLetter $DriveLetter.TrimEnd(':')).DiskNumber).PartitionStyle
    if ($PartitionStyle -ne "GPT") {
        Write-Warning (
            "System drive $DriveLetter partitioned as '$PartitionStyle', needs to be 'GPT'.`n" + 
            "See https://learn.microsoft.com/windows/deployment/mbr-to-gpt before Secure Boot can be enabled."
        )
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

function Show-UEFISecureBootEnabled($prefix) {
    Write-Host $prefix -NoNewLine

    $path = "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\State"
    $prop = "UEFISecureBootEnabled"
    $value = (Get-ItemProperty $path).$prop

    switch ($value) {
        1 { Write-Host "Enabled" -ForegroundColor Green }
        0 { Write-Host "Disabled" -ForegroundColor Red }
        default { Write-Host "$value unknown for '$prop'" -ForegroundColor Red }
    }
}

# Ref [1]
function Show-WindowsUEFICA2023Capable($prefix) {
    Write-Host $prefix -NoNewLine
     
    $path = "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\Servicing"
    $prop = "WindowsUEFICA2023Capable"
    $value = (Get-ItemProperty $path).$prop
    switch ($value) {
        2 { Write-Host "Windows UEFI CA 2023 cert in DB. Starting from 2023 signed boot manager" -ForegroundColor Green }
        1 { Write-Host "Windows UEFI CA 2023 cert in DB. But NOT starting from 2023 signed boot manager" -ForegroundColor Red }
        0 { Write-Host "Windows UEFI CA 2023 cert NOT in DB" -ForegroundColor Red }
        default { Write-Host "$value unknown for '$prop'" -ForegroundColor Red }
    }
}

# Ref [1]
function Show-UEFICA2023Status($prefix) {
    Write-Host $prefix -NoNewLine
    
    $path = "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\Servicing"
    $prop = "UEFICA2023Status"
    $value = (Get-ItemProperty $path).$prop

    switch ($value) {
        "Updated" { Write-Host "$value" -ForegroundColor Green }
        "InProgress" { Write-Host "$value" -ForegroundColor Yellow }
        "NotStarted" { Write-Host "$value" -ForegroundColor Red }
        default { Write-Host "$value unknown for '$prop'" -ForegroundColor Red }
    }
    
    $prop = "UEFICA2023Error"
    $value = (Get-ItemProperty $path).$prop
    # Show if available
    if ($value -gt 0) {
        Write-Host $prefix -NoNewLine
        Write-Host "Error: $value" -ForegroundColor Red
    }

    $prop = "UEFICA2023ErrorEvent"
    $value = (Get-ItemProperty $path).$prop
    # Show if available
    if ($value -gt 0) {
        Write-Host $prefix -NoNewLine
        Write-Host "ErrorEvent: $value" -ForegroundColor Red
    }
}

# Ref [2]
function Show-ConfidenceLevel($prefix) {
    Write-Host $prefix -NoNewLine
    
    $path = "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\Servicing"
    $prop = "ConfidenceLevel"
    $value = (Get-ItemProperty $path).$prop

    switch -Regex ($value) {
        "High Confidence" { Write-Host "$value" -ForegroundColor Green }
        "Under Observation" { Write-Host "$value" -ForegroundColor DarkCyan }
        "No Data Observed" { Write-Host "$value" -ForegroundColor DarkYellow }
        "Temporarily Paused" { Write-Host "$value" -ForegroundColor DarkYellow }
        "Not Supported" { Write-Host "$value" -ForegroundColor DarkRed }
        default { Write-Host "$value unknown for '$prop'" -ForegroundColor Red }
    }
}

# Refs [1] [2] [3] [4]
function Show-AvailableUpdates($prefix) {
    Write-Host $prefix -NoNewLine
    
    $path = "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot"
    $prop = "AvailableUpdates"
    $value = "0x" + ([Convert]::ToString([int64](Get-ItemProperty $path).$prop, 16)).ToUpper()

    switch ($value) {
        "0x0" { Write-Host "No Secure Boot key updates are performed" }
        "0x2" { Write-Host "Apply updates to DBX" }
        "0x4" { Write-Host "Apply 'Microsoft KEK 2K CA 2023' signed by device PK to KEK" }
        "0x40" { Write-Host "Apply 'Windows UEFI CA 2023' to DB" }
        "0x80" { Write-Host "Revoke 'Windows Production PCA 2011' to DBX" }
        "0x100" { Write-Host "Apply 'Windows UEFI CA 2023' signed boot manager" }
        "0x200" { Write-Host "Apply 'SVN' update to the firmware" }
        "0x400" { Write-Host "Apply 'Secure Boot Advanced Targeting' (SBAT) to the firmware" }
        "0x800" { Write-Host "Apply 'Microsoft Option ROM UEFI CA 2023' to DB" }
        "0x1000" { Write-Host "Apply 'Microsoft UEFI CA 2023' to DB" }
        "0x4000" { Write-Host "Successful completion of all applicable update actions" }
        "0x4100" { Write-Host "Manually reboot the system" -ForegroundColor Yellow }
        "0x4104" { Write-Host "'Microsoft UEFI CA 2023' is added to DB" }
        "0x5104" { Write-Host "'Microsoft Option ROM UEFI CA 2023' is added to DB" }
        "0x5904" { Write-Host "'Windows UEFI CA 2023' is added to DB" }
        "0x5944" { Write-Host "Deploy all needed certificates and update to the PCA2023 signed boot manager" }
        default { Write-Host "$value unknown for '$prop'" -ForegroundColor Red }
    }
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

function Get-DeviceArch {
    (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\Servicing\DeviceAttributes").OSArchitecture
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
    Resolve-ArchName,
    Show-UEFISecureBootEnabled,
    Show-UEFICA2023Status,
    Show-WindowsUEFICA2023Capable,
    Show-ConfidenceLevel,
    Show-AvailableUpdates,
    Show-PartitionStyleDisclaimer
