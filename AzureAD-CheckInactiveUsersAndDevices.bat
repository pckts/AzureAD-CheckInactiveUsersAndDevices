CD /d %~dp0
PowerShell -NoProfile -ExecutionPolicy Bypass -Command "& {Start-Process PowerShell -ArgumentList '-NoProfile -ExecutionPolicy Bypass -File ""%~dp0AzureAD-CheckInactiveUsersAndDevices.ps1""' -Verb RunAs}"
