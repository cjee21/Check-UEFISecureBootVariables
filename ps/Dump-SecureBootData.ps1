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

function Get-SVNfromDBX {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [PSCustomObject]$UEFISignatureDatabase
    )
    $SVNs = foreach ($SignatureList in $UEFISignatureDatabase) {
        if ($SignatureList.SignatureType -eq 'EFI_CERT_SHA256_GUID') {
            foreach ($Signature in $SignatureList.SignatureList) {
                if ($Signature.SignatureOwner -eq [guid]'9d132b6c-59d5-4388-ab1c-185cfcb2eb92') {
                    if ($Signature.SignatureData -like "01*" -and $Signature.SignatureData.Substring(42, 22) -eq ("0" * 22)) {
                        $byteArray = -split ($Signature.SignatureData -replace '..', '$& ') | ForEach-Object { 
                            [System.Convert]::ToByte($_, 16)
                        }
                        $MinorBytes = $byteArray[17..18]
                        $svn_ver_minor = [System.BitConverter]::ToUInt16($MinorBytes, 0)
                        $MajorBytes = $byteArray[19..20]
                        $svn_ver_major = [System.BitConverter]::ToUInt16($MajorBytes, 0)
                        [PSCustomObject]@{
                            GUID = New-Object -TypeName System.Guid -ArgumentList (,[byte[]]$byteArray[1..16])
                            Version = [version]::new($svn_ver_major, $svn_ver_minor)
                        } 
                    }
                }
            }
        }
    }
    $BootMgrSVN = $SVNs |
        Where-Object { $_.GUID -eq [guid]'9d132b61-59d5-4388-ab1c-185c3cb2eb92' } | 
        Sort-Object Version -Descending | 
        Select-Object -First 1
    $CDBootSVN = $SVNs |
        Where-Object { $_.GUID -eq [guid]'e8f82e9d-e127-4158-a488-4c18abe2f284' } | 
        Sort-Object Version -Descending | 
        Select-Object -First 1
    $WDSMgFwSVN = $SVNs |
        Where-Object { $_.GUID -eq [guid]'c999cac2-7ffe-496f-8127-9e2a8a535976' } | 
        Sort-Object Version -Descending | 
        Select-Object -First 1
    [PSCustomObject] @{
        BootMgr = $BootMgrSVN
        CDBoot = $CDBootSVN
        WDSMgFw = $WDSMgFwSVN
    }
}

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
