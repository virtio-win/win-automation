# =====================================================================
# Script to increase UTM Spice WebDAV limit & remap network drive
# =====================================================================
param(
    # WebClient's FileSizeLimitInBytes is a 32-bit DWORD - 4294967295
    # (2^32 - 1) is the highest value it can hold, confirmed against
    # Microsoft's documented behavior for this setting: there is no way
    # to raise the WebDAV transfer limit any higher via this registry
    # key, regardless of what's requested here. Lower values are
    # accepted if you deliberately want a smaller cap than the maximum.
    [ValidateRange(1, 4294967295)]
    [long]$FileSizeLimitBytes = 4294967295
)

# 1. Check if the script is running with Administrator privileges
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin) {
    Write-Host "ERROR: This script must be run as an Administrator!" -ForegroundColor Red
    Write-Host "Please right-click PowerShell and select 'Run as administrator'." -ForegroundColor Yellow
    Exit
}

# 2. Detect existing WebDAV/Spice mapped drives
#    First check persistent mappings in the registry (works across elevated/non-elevated sessions).
#    If none found, detect the SPICE WebDAV listening port and construct the path.
$mappedDrives = @()
Get-ChildItem "HKCU:\Network" -ErrorAction SilentlyContinue | ForEach-Object {
    $props = Get-ItemProperty $_.PSPath
    if ($props.RemotePath -match '\\\\(?:localhost|127\.0\.0\.1)@\d+\\') {
        $mappedDrives += @{ Letter = "$($_.PSChildName):"; Remote = $props.RemotePath }
    }
}

if ($mappedDrives.Count -eq 0) {
    $spicePort = Get-NetTCPConnection -State Listen -LocalAddress 127.0.0.1 -ErrorAction SilentlyContinue |
        Where-Object { $_.LocalPort -in @(9843, 9844, 8000) } |
        Select-Object -First 1 -ExpandProperty LocalPort
    if ($spicePort) {
        Write-Host "Detected SPICE WebDAV service on port $spicePort" -ForegroundColor Cyan
        $mappedDrives += @{ Letter = "Z:"; Remote = "\\localhost@$spicePort\DavWWWRoot" }
    }
}

# 3. Registry path and target value
$registryPath = "HKLM:\SYSTEM\CurrentControlSet\Services\WebClient\Parameters"
$valueName    = "FileSizeLimitInBytes"
$newValue     = $FileSizeLimitBytes
$newValueGB   = [math]::Round($newValue / 1GB, 2)

# 4. Check if the registry value is already set — skip restart if so
$currentValue = (Get-ItemProperty -Path $registryPath -Name $valueName -ErrorAction SilentlyContinue).$valueName
if ($currentValue -eq $newValue) {
    Write-Host "Registry value is already set to $newValue bytes (~$newValueGB GB). No restart needed." -ForegroundColor Green
    exit 0
}

try {
    Write-Host "Updating Registry value for WebClient..." -ForegroundColor Cyan
    Set-ItemProperty -Path $registryPath -Name $valueName -Value $newValue -Type DWord -ErrorAction Stop
    Write-Host "Registry successfully updated to: $newValue bytes (~$newValueGB GB)" -ForegroundColor Green

    # 5. Restart the WebClient service
    Write-Host "Restarting WebClient service..." -ForegroundColor Cyan
    Restart-Service -Name "WebClient" -Force -ErrorAction Stop
    Start-Sleep -Seconds 2
    Write-Host "WebClient service restarted successfully!" -ForegroundColor Green

    # 6. Remap previously detected drive(s) in both elevated and non-elevated sessions
    if ($mappedDrives.Count -gt 0) {
        $allOk = $true
        foreach ($drive in $mappedDrives) {
            $letter = $drive.Letter
            $remote = $drive.Remote
            $driveName = $letter.Replace(":", "")
            Write-Host "Remapping drive $letter -> $remote..." -ForegroundColor Cyan

            net use $letter /delete /yes 2>&1 | Out-Null
            $result = net use $letter $remote 2>&1
            if ($LASTEXITCODE -ne 0) {
                Write-Host "WARNING: Failed to remap in elevated session: $result" -ForegroundColor Yellow
            }

            # Remap in the non-elevated user session via a temporary scheduled task
            # (elevated and non-elevated sessions have separate drive namespaces under UAC)
            $taskName = "WinAutomation_Remap_$driveName"
            try {
                $action = New-ScheduledTaskAction -Execute "cmd.exe" -Argument "/c net use $letter $remote"
                $principal = New-ScheduledTaskPrincipal -UserId ([System.Security.Principal.WindowsIdentity]::GetCurrent().Name) -LogonType Interactive -RunLevel Limited
                $task = New-ScheduledTask -Action $action -Principal $principal
                Register-ScheduledTask -TaskName $taskName -InputObject $task -Force | Out-Null
                Start-ScheduledTask -TaskName $taskName
                Start-Sleep -Seconds 3
                Unregister-ScheduledTask -TaskName $taskName -Confirm:$false
                Write-Host "Drive $letter remapped successfully." -ForegroundColor Green
            } catch {
                Write-Host "WARNING: Could not remap in user session: $_" -ForegroundColor Yellow
                $allOk = $false
            }
        }
        if ($allOk) {
            Write-Host "Done! The network drive is reconnected and ready for files up to ~$newValueGB GB." -ForegroundColor Green
        }
    } else {
        Write-Host ""
        Write-Host "Registry updated and WebClient restarted. No existing WebDAV drive was detected to remap." -ForegroundColor Yellow
        Write-Host "Map the UTM shared folder manually (adjust port as needed):" -ForegroundColor Yellow
        Write-Host "  net use Z: \\localhost@9843\DavWWWRoot" -ForegroundColor White
        Write-Host "Then re-run this script next time to have it remapped automatically." -ForegroundColor Yellow
    }
}
catch {
    Write-Error "An error occurred: $_"
}