:: Created by github.com/cjee21
@echo off
title EFI File Info

if "%~1" == "" (
    set /p filepath="Path to EFI file: "
) else (
    set filepath=%~1
)

powershell -ExecutionPolicy Bypass -Command "Import-Module -Force '%~dp0\ps\Get-PEInfo.psm1'; try { $ErrorActionPreference = 'Stop'; Get-PEInfo -FilePath '%filepath%' | Format-List } catch {}"

echo File Information:
powershell -Command "(Get-Item -Path '%filepath%').VersionInfo | Format-List"

powershell -ExecutionPolicy Bypass -Command "Import-Module -Force '%~dp0\ps\Get-EfiSignatures.psm1'; $hashnsigs = Get-EfiSignatures -FilePath '%filepath%'; Write-Host \""Authenticode SHA256: $($hashnsigs.Authentihash)\""; $json = Get-Content -Path '%~dp0\dbx_info\dbx_info_msft_10_14_25.json' -Raw | ConvertFrom-Json; $allImages = @($json.images.x64 + $json.images.x86 + $json.images.arm + $json.images.arm64); foreach ($image in $allImages) { if ($hashnsigs.Authentihash -eq $image.authenticodeHash) { Write-Warning \""This hash was added to the UEFI revocation list on $($image.dateOfAddition)\""; if ($image.description) { Write-Warning \""$($image.description)\""; } } } Write-Host \""`n`n\""; Write-Host 'Signature Certificate(s):'; if ($hashnsigs.Signatures) { foreach ($sig in $hashnsigs.Signatures) { $sig.Signer | Format-List } } else { \""No signatures found`n\"" }"

powershell -ExecutionPolicy Bypass -Command "Import-Module -Force '%~dp0\ps\Get-BootMgrSecurityVersion.psm1'; try { $ErrorActionPreference = 'Stop'; $SVN = Get-BootMgrSecurityVersion -Path '%filepath%' } catch {}; if ($SVN) { \""BOOTMGRSECURITYVERSIONNUMBER: $SVN\"" } "

powershell -ExecutionPolicy Bypass -Command "Import-Module -Force '%~dp0\ps\Get-SBAT.psm1'; try { $ErrorActionPreference = 'Stop'; $SBAT = Get-SBAT -FilePath '%filepath%' } catch {}; if ($SBAT) { Write-Host \""SBAT:\""; Write-Host \""$SBAT\"" } "

echo.
echo.
echo.

pause
