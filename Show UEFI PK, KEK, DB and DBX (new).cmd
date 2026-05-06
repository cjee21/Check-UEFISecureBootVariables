:: Created by github.com/cjee21
@title Show UEFI PK, KEK, DB and DBX
@echo PK
@powershell -Command "Get-SecureBootUEFI -Name PK -Decoded"
@echo KEK
@powershell -Command "Get-SecureBootUEFI -Name KEK -Decoded"
@echo DB
@powershell -Command "Get-SecureBootUEFI -Name DB -Decoded"
@echo DBX
@powershell -Command "Get-SecureBootUEFI -Name DBX -Decoded"
@echo.
@pause
