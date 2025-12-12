reg add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Secureboot /v AvailableUpdates /t REG_DWORD /d 0x5944 /f
powershell -Command "Start-ScheduledTask -TaskName \""\Microsoft\Windows\PI\Secure-Boot-Update\"""
