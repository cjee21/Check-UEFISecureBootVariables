# From https://gist.github.com/out0xb2/f8e0bae94214889a89ac67fceb37f8c0?permalink_comment_id=4572467#gistcomment-4572467

function Get-UefiDatabaseSignatures {
<#
.SYNOPSIS
Parses UEFI Signature Databases into logical Powershell objects
.DESCRIPTION
Original Author: Matthew Graeber (@mattifestation)
Modified By: Jeremiah Cox (@int0x6)
Modified By: Joel Roth (@nafai)
Additional Source: https://gist.github.com/mattifestation/991a0bea355ec1dc19402cef1b0e3b6f
Additional Source: https://www.powershellgallery.com/packages/SplitDbxContent/1.0
License: BSD 3-Clause
.PARAMETER Variable
Specifies a UEFI variable, an instance of which is returned by calling the Get-SecureBootUEFI cmdlet. Only 'db' and 'dbx' are supported.
.PARAMETER BytesIn
Specifies a byte array consisting of the PK, KEK, db, or dbx UEFI vairable contents.
.EXAMPLE
$DbxBytes = [IO.File]::ReadAllBytes('.\dbx.bin')
Get-UEFIDatabaseSignatures -BytesIn $DbxBytes
.EXAMPLE
Get-UEFIDatabaseSignatures -Filename ".\DBXUpdate-20230314.x64.bin"
.EXAMPLE
Get-SecureBootUEFI -Name db | Get-UEFIDatabaseSignatures
.EXAMPLE
Get-SecureBootUEFI -Name dbx | Get-UEFIDatabaseSignatures
.EXAMPLE
Get-SecureBootUEFI -Name pk | Get-UEFIDatabaseSignatures
.EXAMPLE
Get-SecureBootUEFI -Name kek | Get-UEFIDatabaseSignatures
.INPUTS
Microsoft.SecureBoot.Commands.UEFIEnvironmentVariable
Accepts the output of Get-SecureBootUEFI over the pipeline.
.OUTPUTS
UefiSignatureDatabase
Outputs an array of custom powershell objects describing a UEFI Signature Database. "77fa9abd-0359-4d32-bd60-28f4e78f784b" refers to Microsoft as the owner.
#>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory, ValueFromPipeline, ParameterSetName = 'UEFIVariable')]
        [ValidateScript({ ($_.GetType().Fullname -eq 'Microsoft.SecureBoot.Commands.UEFIEnvironmentVariable') -and ($_.Name -in "kek","pk","db","dbx") })]
        $Variable,

        [Parameter(Mandatory, ParameterSetName = 'ByteArray')]
        [Byte[]]
        [ValidateNotNullOrEmpty()]
        $BytesIn,

        [Parameter(Mandatory, ParameterSetName = 'File')]
        [string]
        [ValidateScript({ (Resolve-Path "$_").where({Test-Path $_}).Path })]
        $Filename
    )
    
    $SignatureTypeMapping = @{
        'C1C41626-504C-4092-ACA9-41F936934328' = 'EFI_CERT_SHA256_GUID' # Most often used for dbx
        'A5C059A1-94E4-4AA7-87B5-AB155C2BF072' = 'EFI_CERT_X509_GUID'   # Most often used for db
    }

    $Bytes = $null

    if ($Filename) 
    {
        $Bytes = Get-Content -Encoding Byte $Filename -ErrorAction Stop
    }
    elseif ($Variable)
    {
        $Bytes = $Variable.Bytes
    }
    else
    {
        $Bytes = $BytesIn
    }

    # Modified from Split-Dbx
    if (($Bytes[40] -eq 0x30) -and ($Bytes[41] -eq 0x82 ))
    {
        Write-Debug "Removing signature."

        # Signature is known to be ASN size plus header of 4 bytes
        $sig_length = $Bytes[42] * 256 + $Bytes[43] + 4
        if ($sig_length -gt ($Bytes.Length + 40)) {
            Write-Error "Signature longer than file size!" -ErrorAction Stop
        }
            
        ## Unsigned db store
        [System.Byte[]]$Bytes = @($Bytes[($sig_length+40)..($Bytes.Length - 1)].Clone())
    }
    else
    {
        Write-Debug "Signature not found. Assuming it's already split."
    }

    try
    {
        $MemoryStream = New-Object -TypeName IO.MemoryStream -ArgumentList @(,$Bytes)
        $BinaryReader = New-Object -TypeName IO.BinaryReader -ArgumentList $MemoryStream, ([Text.Encoding]::Unicode)
    }
    catch
    {
        throw $_
        return
    }

    # What follows will be an array of EFI_SIGNATURE_LIST structs

    while ($BinaryReader.PeekChar() -ne -1) {
        $SignatureType = $SignatureTypeMapping[([Guid][Byte[]] $BinaryReader.ReadBytes(16)).Guid]
        $SignatureListSize = $BinaryReader.ReadUInt32()
        $SignatureHeaderSize = $BinaryReader.ReadUInt32()
        $SignatureSize = $BinaryReader.ReadUInt32()

        $SignatureHeader = $BinaryReader.ReadBytes($SignatureHeaderSize)

        # 0x1C is the size of the EFI_SIGNATURE_LIST header
        $SignatureCount = ($SignatureListSize - 0x1C) / $SignatureSize

        $SignatureList = 1..$SignatureCount | ForEach-Object {
            $SignatureDataBytes = $BinaryReader.ReadBytes($SignatureSize)

            $SignatureOwner = [Guid][Byte[]] $SignatureDataBytes[0..15]

            switch ($SignatureType) {
                'EFI_CERT_SHA256_GUID' {
                    $SignatureData = ([Byte[]] $SignatureDataBytes[0x10..0x2F] | ForEach-Object { $_.ToString('X2') }) -join ''
                }

                'EFI_CERT_X509_GUID' {
                    $SignatureData = New-Object Security.Cryptography.X509Certificates.X509Certificate2 -ArgumentList @(,([Byte[]] $SignatureDataBytes[16..($SignatureDataBytes.Count - 1)]))
                }
            }

            [PSCustomObject] @{
                PSTypeName = 'EFI.SignatureData'
                SignatureOwner = $SignatureOwner
                SignatureData = $SignatureData
            }
        }

        [PSCustomObject] @{
            PSTypeName = 'EFI.SignatureList'
            SignatureType = $SignatureType
            SignatureList = $SignatureList
        }
    }
}
