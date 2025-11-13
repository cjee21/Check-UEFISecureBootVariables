:: Created by github.com/cjee21
@title Show UEFI PK, KEK, DB and DBX
@powershell -ExecutionPolicy Bypass -Command "& Import-Module '%~dp0ps\Get-UEFIDatabaseSignatures.ps1'; $FormatEnumerationLimit = -1; Write-Output "PK:"; Get-SecureBootUEFI -Name pk | Get-UEFIDatabaseSignatures | Format-List; Write-Output "KEK:"; Get-SecureBootUEFI -Name kek | Get-UEFIDatabaseSignatures | Format-List; Write-Output "DB:"; Get-SecureBootUEFI -Name db | Get-UEFIDatabaseSignatures | Format-List;  Write-Output "DBX:"; Get-SecureBootUEFI -Name dbx | Get-UEFIDatabaseSignatures | Format-List"
@echo.
@pause
