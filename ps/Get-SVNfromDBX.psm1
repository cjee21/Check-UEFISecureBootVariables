Set-Variable -Name SVN_OWNER_GUID -Value '9d132b6c-59d5-4388-ab1c-185cfcb2eb92' -Option Constant
Set-Variable -Name EFI_BOOTMGR_DBXSVN_GUID -Value '9d132b61-59d5-4388-ab1c-185c3cb2eb92' -Option Constant
Set-Variable -Name EFI_CDBOOT_DBXSVN_GUID -Value 'e8f82e9d-e127-4158-a488-4c18abe2f284' -Option Constant
Set-Variable -Name EFI_WDSMGR_DBXSVN_GUID -Value 'c999cac2-7ffe-496f-8127-9e2a8a535976' -Option Constant

function Get-SVNfromDBX {
    # Get Security Version Number (SVN) from DBX data
    # SVNs are in SVN_DATA which are stored as EFI_CERT_SHA256_GUID with SignatureOwner {9d132b6c-59d5-4388-ab1c-185cfcb2eb92}
    # There are 3 types of SVNs:
    #  EFI_BOOTMGR_DBXSVN_GUID = {9d132b61-59d5-4388-ab1c-185c3cb2eb92}
    #  EFI_CDBOOT_DBXSVN_GUID = {e8f82e9d-e127-4158-a488-4c18abe2f284}
    #  EFI_WDSMGR_DBXSVN_GUID = {c999cac2-7ffe-496f-8127-9e2a8a535976}
    # SVN_DATA value:
    #  Byte[0] is the UINT8 version of the SVN_DATA structure.
    #  Bytes[1...16] are the GUID of the application being revoked. Little endian.
    #  Bytes[17...18] are the Minor SVN number. Litte endian UINT16.
    #  Bytes[19...20] are the Major SVN number. Litte endian UINT16.
    #  Bytes[21...31] are 11 zero bytes padding.
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [PSCustomObject]$UEFISignatureDatabase
    )
    $SVNs = foreach ($SignatureList in $UEFISignatureDatabase) {
        if ($SignatureList.SignatureType -eq 'EFI_CERT_SHA256_GUID') {
            foreach ($Signature in $SignatureList.SignatureList) {
                if ($Signature.SignatureOwner -eq [guid]$SVN_OWNER_GUID) {
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
        Where-Object { $_.GUID -eq [guid]$EFI_BOOTMGR_DBXSVN_GUID } | 
        Sort-Object Version -Descending | 
        Select-Object -First 1
    $CDBootSVN = $SVNs |
        Where-Object { $_.GUID -eq [guid]$EFI_CDBOOT_DBXSVN_GUID } | 
        Sort-Object Version -Descending | 
        Select-Object -First 1
    $WDSMgFwSVN = $SVNs |
        Where-Object { $_.GUID -eq [guid]$EFI_WDSMGR_DBXSVN_GUID } | 
        Sort-Object Version -Descending | 
        Select-Object -First 1
    [PSCustomObject] @{
        BootMgr = $BootMgrSVN
        CDBoot = $CDBootSVN
        WDSMgFw = $WDSMgFwSVN
    }
}

Export-ModuleMember -Function Get-SVNfromDBX -Variable SVN_OWNER_GUID, EFI_BOOTMGR_DBXSVN_GUID, EFI_CDBOOT_DBXSVN_GUID, EFI_WDSMGR_DBXSVN_GUID
