@echo off

set DesiredAvailableUpdates=0x682
echo Desired AvailableUpdates: %DesiredAvailableUpdates%

FOR /F "tokens=3*" %%A IN ('REG QUERY HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Secureboot /v AvailableUpdates 2^>nul') DO (
    SET CurrentAvailableUpdates=%%A
)
echo Current AvailableUpdates: %CurrentAvailableUpdates%

set /a "TargetAvailableUpdates = %CurrentAvailableUpdates% | %DesiredAvailableUpdates%"
FOR /F "tokens=*" %%A IN ('powershell -Command "\""0x{0:X}\"" -f %TargetAvailableUpdates%"') DO (
    SET TargetAvailableUpdates=%%A
)

echo Setting AvailableUpdates to %TargetAvailableUpdates%
reg add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Secureboot /v AvailableUpdates /t REG_DWORD /d %TargetAvailableUpdates% /f

echo Starting \Microsoft\Windows\PI\Secure-Boot-Update
Start-ScheduledTask -TaskName "\Microsoft\Windows\PI\Secure-Boot-Update"

pause
