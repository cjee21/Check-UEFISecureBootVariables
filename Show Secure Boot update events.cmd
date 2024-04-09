:: Created by github.com/cjee21
@title Show Secure Boot update events
@powershell -Command "Get-WinEvent -FilterHashtable @{ProviderName='microsoft-windows-tpm-wmi'; Id=1032,1033,1034,1035,1036,1037,1795,1796,1797,1798,1799}"
@echo.
@pause
