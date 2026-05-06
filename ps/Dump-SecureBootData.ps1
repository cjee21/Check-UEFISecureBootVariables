# Created by github.com/cjee21
# License: MIT
# Repository: https://github.com/cjee21/Check-UEFISecureBootVariables

Import-Module -Force "$PSScriptRoot\Get-UEFIDatabaseSignatures.psm1"

$ComputerSystem = Get-CimInstance -ClassName Win32_ComputerSystem
$BIOS = Get-CimInstance -ClassName Win32_BIOS
$Processor = Get-CimInstance -ClassName Win32_Processor
$WindowsVersion = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'

$SecureBootState = Confirm-SecureBootUEFI -ErrorAction Stop

$PKraw = Get-SecureBootUEFI -Name pk
$PKDefaultraw = Get-SecureBootUEFI -Name PKDefault
$KEKraw = Get-SecureBootUEFI -Name kek
$KEKDefaultraw = Get-SecureBootUEFI -Name KEKDefault
$DBraw = Get-SecureBootUEFI -Name db
$DBDefaultraw = Get-SecureBootUEFI -Name DBDefault
$DBXraw = Get-SecureBootUEFI -Name dbx
$DBXDefaultraw = Get-SecureBootUEFI -Name DBXDefault

$PK = [PSCustomObject] @{
    UEFIEnvironmentVariable = $PKraw
    UEFISignatureDatabase = $PKraw | Get-UEFIDatabaseSignatures
}
$PKDefault = [PSCustomObject] @{
    UEFIEnvironmentVariable = $PKDefaultraw
    UEFISignatureDatabase = $PKDefaultraw | Get-UEFIDatabaseSignatures
}
$KEK = [PSCustomObject] @{
    UEFIEnvironmentVariable = $KEKraw
    UEFISignatureDatabase = $KEKraw | Get-UEFIDatabaseSignatures
}
$KEKDefault = [PSCustomObject] @{
    UEFIEnvironmentVariable = $KEKDefaultraw
    UEFISignatureDatabase = $KEKDefaultraw | Get-UEFIDatabaseSignatures
}
$DB = [PSCustomObject] @{
    UEFIEnvironmentVariable = $DBraw
    UEFISignatureDatabase = $DBraw | Get-UEFIDatabaseSignatures
}
$DBDefault = [PSCustomObject] @{
    UEFIEnvironmentVariable = $DBDefaultraw
    UEFISignatureDatabase = $DBDefaultraw | Get-UEFIDatabaseSignatures
}

$UEFISignatureDatabaseDBX = $DBXraw | Get-UEFIDatabaseSignatures
$UEFISignatureDatabaseDBXDefault = $DBXDefaultraw | Get-UEFIDatabaseSignatures

Import-Module -Force "$PSScriptRoot\Get-SVNfromDBX.psm1"

$DBX = [PSCustomObject] @{
    UEFIEnvironmentVariable = $DBXraw
    UEFISignatureDatabase = $UEFISignatureDatabaseDBX
    SecurityVersionNumber = Get-SVNfromDBX $UEFISignatureDatabaseDBX
}
$DBXDefault = [PSCustomObject] @{
    UEFIEnvironmentVariable = $DBXDefaultraw
    UEFISignatureDatabase = $UEFISignatureDatabaseDBXDefault
    SecurityVersionNumber = Get-SVNfromDBX $UEFISignatureDatabaseDBXDefault
}

function Get-RegistryObject {
    param([string]$Path)
    $item = Get-Item -Path $Path
    $obj = [ordered]@{}
    $item.GetValueNames() | ForEach-Object {
        $name = if ($_ -eq "") { "(Default)" } else { $_ }
        $obj[$name] = $item.GetValue($_)
    }
    Get-ChildItem -Path $Path | ForEach-Object {
        $obj[$_.PSChildName] = Get-RegistryObject -Path $_.PSPath
    }
    return [PSCustomObject]$obj
}

$RegistryKeys = Get-RegistryObject -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot"

$SecureBootData = [PSCustomObject] @{
    Date = Get-Date
    ComputerSystem = $ComputerSystem | Select-Object -Property Name, PrimaryOwnerName, BootupState, Domain, Manufacturer, Model, OEMStringArray, SystemFamily, SystemSKUNumber, UserName, Workgroup
    BIOS = $BIOS | Select-Object -Property Name, Manufacturer, SerialNumber, Version, BIOSVersion, ReleaseDate, SMBIOSBIOSVersion
    Processor = $Processor | Select-Object -Property Description, Name, Architecture, Manufacturer, NumberOfCores, SerialNumber, SocketDesignation, ThreadCount
    WindowsVersion = $WindowsVersion | Select-Object -Property CurrentBuild, CurrentBuildNumber, CurrentMajorVersionNumber, CurrentMinorVersionNumber, CurrentVersion, DisplayVersion, InstallationType, InstallDate, LCUVer, ProductName, UBR
    SecureBootState = $SecureBootState
    PK = $PK
    PKDefault = $PKDefault
    KEK = $KEK
    KEKDefault = $KEKDefault
    DB = $DB
    DBDefault = $DBDefault
    DBX = $DBX
    DBXDefault = $DBXDefault
    RegistryKeys = $RegistryKeys
}

$SecureBootData | Format-List

Export-Clixml -InputObject $SecureBootData -Path $env:USERPROFILE\Desktop\SecureBootData.xml

"Exported to $env:USERPROFILE\Desktop\SecureBootData.xml"
