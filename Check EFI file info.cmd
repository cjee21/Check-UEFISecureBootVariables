:: Created by github.com/cjee21
@echo off
title EFI File Info

if "%~1" == "" (
    set /p filepath="Path to EFI file: "
) else (
    set filepath=%~1
)

powershell -ExecutionPolicy Bypass -Command "Import-Module '%~dp0\ps\Get-PEInfo.ps1'; try { $ErrorActionPreference = 'Stop'; Get-PEInfo -FilePath '%filepath%' | Format-List } catch {}"

echo File Information:
powershell -Command "(Get-Item -Path '%filepath%').VersionInfo | Format-List"

echo Signature Certificate(s):
powershell -ExecutionPolicy Bypass -Command "Import-Module '%~dp0\ps\Get-EfiSignatures.ps1'; try { $sigs = Get-EfiSignatures -FilePath '%filepath%'; if ($sigs) { foreach ($sig in $sigs) { $sig.Signer | Format-List } } else { ""No signatures found`n\"" } } catch { \""No signatures found`n\"" }"

powershell -ExecutionPolicy Bypass -Command "Import-Module '%~dp0\ps\Get-BootMgrSecurityVersion.ps1'; try { $ErrorActionPreference = 'Stop'; $SVN_bytes = Get-BootMgrSecurityVersionBytes -Path '%filepath%' } catch {}; if ($SVN_bytes) { $svn_ver_minor = [System.BitConverter]::ToInt16($SVN_bytes[0..1], 0); $svn_ver_major = [System.BitConverter]::ToInt16($SVN_bytes[2..3], 0); \""BOOTMGRSECURITYVERSIONNUMBER: $([version]::new($svn_ver_major, $svn_ver_minor))\"" } "

powershell -ExecutionPolicy Bypass -Command "Import-Module '%~dp0\ps\Get-SBAT.ps1'; try { $ErrorActionPreference = 'Stop'; $SBAT = Get-SBAT -FilePath '%filepath%' } catch {}; if ($SBAT) { Write-Host \""SBAT:\""; Write-Host \""$SBAT\"" } "

echo.
echo.
echo.

pause
