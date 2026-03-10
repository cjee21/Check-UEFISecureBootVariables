:: Created for cjee21/Check-UEFISecureBootVariables
@echo off
title Scan EFI files against Microsoft DBX JSON

:: NOTE: Replace URL with a raw URL or use -MsftJsonPath to a local file.
set MSFT_JSON_URL=https://raw.githubusercontent.com/microsoft/secureboot_objects/main/PreSignedObjects/DBX/dbx_info_msft_latest.json

powershell -ExecutionPolicy Bypass -Command "& '%~dp0ps\Find-EfiFilesRevokedByDbx.ps1' -ScanESP -ScanDefaultPaths -MatchMode MsftJson -MsftJsonUrl '%MSFT_JSON_URL%'"

echo.
pause