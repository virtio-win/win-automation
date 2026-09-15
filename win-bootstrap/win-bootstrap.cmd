@echo off
rem Prefer PowerShell 7 (pwsh) when it's already installed - Windows
rem PowerShell 5.1 has been observed to intermittently/deterministically
rem fail to auto-load Microsoft.PowerShell.Security (breaking
rem Get-ExecutionPolicy, the Cert:\ drive, and Get-Acl) for this specific
rem script on at least one arm64 machine, while pwsh handles it fine.
rem Falls back to powershell.exe for a fresh machine that doesn't have
rem PowerShell 7 yet - if that first run hits the issue on one of those
rem steps, re-running (this script is idempotent) after PowerShell 7 gets
rem installed picks pwsh automatically and clears it up.
where pwsh.exe >nul 2>nul
if %ERRORLEVEL% EQU 0 (
    pwsh.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0win-bootstrap.ps1" %*
) else (
    powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0win-bootstrap.ps1" %*
)
