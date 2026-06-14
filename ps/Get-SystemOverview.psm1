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

    switch ($Arch) {
        "AMD64" { "AMD64/X64" }
        "ARM"   { "ARM" }
        "ARM64" { "ARM64/AARCH64" }
        "X86"   { "X86/IA32" }
        default { "N/A. Please report." }
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
            $_ -ne 'System Product Name'
        } |
        Select-Object -Unique

    if ($clean) { $clean -join " " } else { $null }
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
    $cim_cs = Get-CimInstance Win32_ComputerSystemProduct -ErrorAction SilentlyContinue
    $cim_bb = Get-CimInstance Win32_BaseBoard -ErrorAction SilentlyContinue
    $cim_fw = Get-CimInstance Win32_BIOS -ErrorAction SilentlyContinue

    $cs = if ($cim_cs) { Format-Set @($cim_cs.Vendor, $cim_cs.Name) } else { $null }
    $bb = if ($cim_bb) { Format-Set @($cim_bb.Manufacturer, $cim_bb.Product) } else { $null }
    $arch = Resolve-ArchName $env:PROCESSOR_ARCHITECTURE

    $fwM = if ($cim_fw) { $cim_fw.Manufacturer } else { $null }
    $fwV = if ($cim_fw) { $cim_fw.SMBIOSBIOSVersion } else { $null }
    $fwD = $null
    if ($cim_fw -and $cim_fw.ReleaseDate) {
        try { $fwD = ([datetime]$cim_fw.ReleaseDate).ToString('dd MMM yyyy') }
        catch { $fwD = $cim_fw.ReleaseDate }
    }

    $hw = (@($cs, $bb, $arch) | Where-Object { $_ } | Select-Object -Unique) -join " - "
    $fw = (@($fwM, $fwV, $fwD) | Where-Object { $_ }) -join " - "
    if ($hw) { "HW : $hw" } else { "HW : N/A" }
    if ($fw) { "FW : $fw" } else { "FW : N/A"}
}

Export-ModuleMember -Function `
    Spacer,
    Show-WindowsVersion,
    Show-DeviceOverview,
    Resolve-ArchName
