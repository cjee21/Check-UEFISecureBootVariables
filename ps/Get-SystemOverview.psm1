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

    switch ($Arch) {
        "AMD64" { "AMD64/X64" }
        "ARM"   { "ARM" }
        "ARM64" { "ARM64/AARCH64" }
        "X86"   { "X86/IA32" }
        default { "N/A. Please report." }
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

function Format-Set {
    param([string[]]$Values)

    $clean = @($Values) |
        ForEach-Object { 
            if ($_ ) { $_.ToString().Trim() } else { $null } 
        } |
        Where-Object {
            $_ -and
            $_ -ne 'Default String' -and
            $_ -ne 'To Be Filled By O.E.M.' -and
            $_ -ne 'System Manufacturer' -and
            $_ -ne 'System Product Name' -and
            $_ -ne 'System Version'
        } |
        Select-Object -Unique

    if ($clean) { $clean -join " " } else { $null }
}

function Show-UEFISecureBootEnabled($prefix) {
    Write-Host $prefix -NoNewLine

    $path = "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\State"
    $prop = "UEFISecureBootEnabled"
    $value = (Get-ItemProperty $path -ErrorAction SilentlyContinue).$prop

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
    $value = (Get-ItemProperty $path -ErrorAction SilentlyContinue).$prop
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
    $value = (Get-ItemProperty $path -ErrorAction SilentlyContinue).$prop

    switch ($value) {
        "Updated" { Write-Host "$value" -ForegroundColor Green }
        "InProgress" { Write-Host "$value" -ForegroundColor Yellow }
        "NotStarted" { Write-Host "$value" -ForegroundColor Red }
        default { Write-Host "$value unknown for '$prop'" -ForegroundColor Red }
    }
    
    $prop = "UEFICA2023Error"
    $value = (Get-ItemProperty $path -ErrorAction SilentlyContinue).$prop
    # Show if available
    if ($value -gt 0) {
        Write-Host $prefix -NoNewLine
        Write-Host "Error: $value" -ForegroundColor Red
    }

    $prop = "UEFICA2023ErrorEvent"
    $value = (Get-ItemProperty $path -ErrorAction SilentlyContinue).$prop
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
    $value = (Get-ItemProperty $path -ErrorAction SilentlyContinue).$prop

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
    $value = "0x" + ([Convert]::ToString([int64](Get-ItemProperty $path -ErrorAction SilentlyContinue).$prop, 16)).ToUpper()

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
    $windows = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -ErrorAction SilentlyContinue
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
    $cim_cs = Get-CimInstance -ClassName Win32_ComputerSystemProduct -ErrorAction SilentlyContinue
    $cim_bb = Get-CimInstance -ClassName Win32_BaseBoard -ErrorAction SilentlyContinue
    $cim_fw = Get-CimInstance -ClassName Win32_BIOS -ErrorAction SilentlyContinue

    $cs = if ($cim_cs) { Format-Set @($cim_cs.Vendor, $cim_cs.Name, $cim_cs.Version) } else { $null }
    $bb = if ($cim_bb) { Format-Set @($cim_bb.Manufacturer, $cim_bb.Product, $cim_bb.Version) } else { $null }

    $fwM = if ($cim_fw) { $cim_fw.Manufacturer } else { $null }
    $fwV = if ($cim_fw) { $cim_fw.SMBIOSBIOSVersion } else { $null }
    $fwD = $null
    if ($cim_fw -and $cim_fw.ReleaseDate) {
        try { $fwD = ([datetime]$cim_fw.ReleaseDate).ToString('dd MMM yyyy') }
        catch { $fwD = $cim_fw.ReleaseDate }
    }

    # Print ComputerSystemProduct if available
    if ($cs) { 
        "HW : $cs" 
    # Print BaseBoard if available
    } elseif ($bb) {
        "HW : $bb"
    } else { 
        "HW : N/A" 
    }
    
    $fw = (@($fwM, $fwV, $fwD) | Where-Object { $_ }) -join " - "
    if ($fw) { "FW : $fw" } else { "FW : N/A"}
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
