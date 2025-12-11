:: Created by github.com/cjee21
@echo off
title EFI File Info

if "%~1" == "" (
    set /p filepath="Path to EFI file: "
) else (
    set filepath=%~1
)

powershell -ExecutionPolicy Bypass -Command "Import-Module '%~dp0\ps\Get-PEInfo.ps1'; try { $ErrorActionPreference = 'Stop'; Get-PEInfo -FilePath %filepath% | Format-List } catch {}"

echo File Information:
powershell -Command "(Get-Item -Path %filepath%).VersionInfo | Format-List"

echo Signature Certificate:
powershell -Command "try { [System.Security.Cryptography.X509Certificates.X509Certificate2]::new([System.Security.Cryptography.X509Certificates.X509Certificate]::CreateFromSignedFile('%filepath%')) | Format-List } catch { \""No certificate found\"" }"

powershell -ExecutionPolicy Bypass -Command "Import-Module '%~dp0\ps\Get-BootMgrSecurityVersion.ps1'; try { $ErrorActionPreference = 'Stop'; $SVN_bytes = Get-BootMgrSecurityVersionBytes -Path %filepath% } catch {}; if ($SVN_bytes) { $svn_ver_minor = [System.BitConverter]::ToInt16($SVN_bytes[0..1], 0); $svn_ver_major = [System.BitConverter]::ToInt16($SVN_bytes[2..3], 0); \""BOOTMGRSECURITYVERSIONNUMBER: $([version]::new($svn_ver_major, $svn_ver_minor))\"" } "

echo.
echo.
echo.

pause
