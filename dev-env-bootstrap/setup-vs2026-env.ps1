<#
.SYNOPSIS
    Setup script for VS 2026 Community + WDK + WinFSP + CPDK development environment.

.DESCRIPTION
    Checks for and installs:
      - Visual Studio 2026 Community Edition (with driver dev components)
      - Windows Driver Kit (WDK)
      - WinFSP 2023 (v2.0) with Developer and Kernel Developer features
      - Cryptographic Provider Development Kit (CPDK) 8.0

    Must be run as Administrator. Without parameters the script asks before
    each install step. Use -Automatic or -Quiet for unattended operation.

.PARAMETER Automatic
    No prompts. Installers show their own progress windows.
    Alias: -a

.PARAMETER Quiet
    No prompts, no UI windows. Progress is reported to the console only.
    Alias: -q

.PARAMETER Help
    Show this help message.
    Alias: -h

.EXAMPLE
    .\setup-vs2026-env.ps1
    Interactive mode - asks before each install.

.EXAMPLE
    .\setup-vs2026-env.ps1 -Automatic
    Installs everything without prompts, shows installer progress windows.

.EXAMPLE
    .\setup-vs2026-env.ps1 -Quiet
    Fully headless - no UI, console progress only.
#>

param(
    [Alias("a")][switch]$Automatic,
    [Alias("q")][switch]$Quiet,
    [Alias("h")][switch]$Help
)

if ($Help) {
    Get-Help $MyInvocation.MyCommand.Definition -Detailed
    exit 0
}

if ($Automatic -and $Quiet) {
    Write-Host "Cannot use -Automatic and -Quiet together. Pick one." -ForegroundColor Red
    exit 1
}

$script:NoPrompt = $Automatic -or $Quiet

$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"
$script:errors = @()
$script:warnings = @()

# ---------------------------------------------
# 0. Administrator check with elevation offer
# ---------------------------------------------
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator
)

if (-not $isAdmin) {
    Write-Host "This script requires Administrator privileges." -ForegroundColor Red
    if ($script:NoPrompt) {
        Write-Host "Cannot elevate in unattended mode. Run from an elevated prompt." -ForegroundColor Red
        exit 1
    }
    Write-Host ""
    $choice = Read-Host "Attempt to re-launch as Administrator? (Y/N)"
    if ($choice -match '^[Yy]') {
        $scriptPath = $MyInvocation.MyCommand.Definition
        $argList = @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", "`"$scriptPath`"")
        if ($Automatic) { $argList += "-Automatic" }
        if ($Quiet) { $argList += "-Quiet" }
        try {
            Start-Process powershell.exe -ArgumentList $argList -Verb RunAs
            Write-Host "Elevated process started. This window can be closed." -ForegroundColor Cyan
            exit 0
        } catch {
            Write-Host "Elevation failed: $_" -ForegroundColor Red
            exit 1
        }
    } else {
        Write-Host "Cannot continue without Administrator privileges. Exiting." -ForegroundColor Red
        exit 1
    }
}

function Write-Status  { param($msg) Write-Host "[OK]    $msg" -ForegroundColor Green }
function Write-Err     { param($msg) Write-Host "[ERROR] $msg" -ForegroundColor Red; $script:errors += $msg }
function Write-Warn    { param($msg) Write-Host "[WARN]  $msg" -ForegroundColor Yellow; $script:warnings += $msg }
function Write-Info    { param($msg) Write-Host "[INFO]  $msg" -ForegroundColor Cyan }
function Write-Section { param($msg) Write-Host "`n=== $msg ===" -ForegroundColor White }

# Shared temp directory and TLS setup
$tempDir = Join-Path $env:TEMP "vs2026-setup"
if (-not (Test-Path $tempDir)) { New-Item -ItemType Directory -Path $tempDir | Out-Null }
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

function Get-Installer {
    param(
        [string]$Url,
        [string]$OutFile,
        [string]$DisplayName
    )
    Write-Info "Downloading $DisplayName..."
    Invoke-WebRequest -Uri $Url -OutFile $OutFile -UseBasicParsing -TimeoutSec 300
    $fileSize = (Get-Item $OutFile).Length
    if ($fileSize -lt 10000) {
        throw "Downloaded file is suspiciously small ($fileSize bytes) - possibly a redirect or error page."
    }
    $sizeMB = [math]::Round($fileSize / 1MB, 1)
    Write-Status "Downloaded $DisplayName ($sizeMB MB)"
}

if ($Quiet) { $vsUiMode = "--quiet" } else { $vsUiMode = "--passive" }

function Start-InstallerWithProgress {
    param(
        [string]$FilePath,
        [string]$Arguments,
        [string]$StepName,
        [int]$IntervalSec = 30,
        [switch]$ForceConsoleProgress
    )
    Write-Info "$StepName -- starting..."
    if (-not $Quiet -and -not $ForceConsoleProgress) {
        # Interactive or Automatic: let the installer show its own UI
        $proc = Start-Process -FilePath $FilePath -ArgumentList $Arguments -Wait -PassThru
        return $proc.ExitCode
    }
    # No UI available or Quiet mode: poll and print console progress
    $proc = Start-Process -FilePath $FilePath -ArgumentList $Arguments -PassThru
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    while (-not $proc.HasExited) {
        Start-Sleep -Seconds $IntervalSec
        $elapsed = $sw.Elapsed.ToString("hh\:mm\:ss")
        Write-Info "$StepName -- still running ($elapsed elapsed)..."
    }
    $sw.Stop()
    $elapsed = $sw.Elapsed.ToString("hh\:mm\:ss")
    Write-Info "$StepName -- finished ($elapsed)."
    return $proc.ExitCode
}

# ---------------------------------------------
# 1. Visual Studio 2026 Community Edition
# ---------------------------------------------
Write-Section "Visual Studio 2026 Community Edition"

# Embedded VS 2026 component configuration
$vsConfigJson = @'
{
  "version": "1.0",
  "components": [
    "Component.Microsoft.Windows.DriverKit",
    "Microsoft.Component.MSBuild",
    "Microsoft.VisualStudio.Component.CoreEditor",
    "Microsoft.VisualStudio.Component.CppBuildInsights",
    "Microsoft.VisualStudio.Component.Debugger.JustInTime",
    "Microsoft.VisualStudio.Component.DiagnosticTools",
    "Microsoft.VisualStudio.Component.Graphics",
    "Microsoft.VisualStudio.Component.IntelliCode",
    "Microsoft.VisualStudio.Component.NuGet",
    "Microsoft.VisualStudio.Component.Roslyn.Compiler",
    "Microsoft.VisualStudio.Component.TextTemplating",
    "Microsoft.VisualStudio.Component.VC.14.44.17.14.ARM64",
    "Microsoft.VisualStudio.Component.VC.14.44.17.14.ATL",
    "Microsoft.VisualStudio.Component.VC.14.44.17.14.ATL.ARM64",
    "Microsoft.VisualStudio.Component.VC.14.44.17.14.MFC",
    "Microsoft.VisualStudio.Component.VC.14.44.17.14.MFC.ARM64",
    "Microsoft.VisualStudio.Component.VC.14.44.17.14.x86.x64",
    "Microsoft.VisualStudio.Component.VC.ASAN",
    "Microsoft.VisualStudio.Component.VC.ATL",
    "Microsoft.VisualStudio.Component.VC.ATL.ARM64",
    "Microsoft.VisualStudio.Component.VC.ATL.ARM64.Spectre",
    "Microsoft.VisualStudio.Component.VC.ATL.Spectre",
    "Microsoft.VisualStudio.Component.VC.ATLMFC.Spectre",
    "Microsoft.VisualStudio.Component.VC.CMake.Project",
    "Microsoft.VisualStudio.Component.VC.CoreIde",
    "Microsoft.VisualStudio.Component.VC.DiagnosticTools",
    "Microsoft.VisualStudio.Component.VC.MFC.ARM64.Spectre",
    "Microsoft.VisualStudio.Component.VC.Redist.14.Latest",
    "Microsoft.VisualStudio.Component.VC.Runtimes.ARM64.Spectre",
    "Microsoft.VisualStudio.Component.VC.Runtimes.ARM64EC.Spectre",
    "Microsoft.VisualStudio.Component.VC.Runtimes.x86.x64.Spectre",
    "Microsoft.VisualStudio.Component.VC.TestAdapterForBoostTest",
    "Microsoft.VisualStudio.Component.VC.TestAdapterForGoogleTest",
    "Microsoft.VisualStudio.Component.VC.Tools.ARM64",
    "Microsoft.VisualStudio.Component.VC.Tools.ARM64EC",
    "Microsoft.VisualStudio.Component.VC.Tools.x86.x64",
    "Microsoft.VisualStudio.Component.Vcpkg",
    "Microsoft.VisualStudio.Component.Windows11SDK.28000",
    "Microsoft.VisualStudio.Component.Windows11Sdk.WindowsPerformanceToolkit",
    "Microsoft.VisualStudio.ComponentGroup.NativeDesktop.Core",
    "Microsoft.VisualStudio.ComponentGroup.WebToolsExtensions.CMake",
    "Microsoft.VisualStudio.Workload.CoreEditor",
    "Microsoft.VisualStudio.Workload.NativeDesktop"
  ],
  "extensions": []
}
'@

$vsConfigPath = Join-Path $tempDir "vs2026.vsconfig"
Set-Content -Path $vsConfigPath -Value $vsConfigJson -Encoding UTF8

# Detect existing VS 2026 via vswhere
$vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
$vsInstalled = $false
$vsInstallPath = $null

if (Test-Path $vswhere) {
    $vsInstallPath = & $vswhere -version "[18.0,19.0)" -products Microsoft.VisualStudio.Product.Community -property installationPath 2>$null | Select-Object -First 1
    if ($vsInstallPath) {
        $vsInstalled = $true
        $vsVersion = & $vswhere -version "[18.0,19.0)" -products Microsoft.VisualStudio.Product.Community -property installationVersion 2>$null | Select-Object -First 1
        Write-Status "VS 2026 Community is installed (v$vsVersion): $vsInstallPath"
    }
}

if (-not $vsInstalled) {
    Write-Host "[MISS]  VS 2026 Community is not installed." -ForegroundColor Yellow
}

$vsSetupUrl = "https://c2rsetup.officeapps.live.com/c2r/downloadVS.aspx?sku=community&channel=Stable&version=VS18"
$vsSetupExe = Join-Path $tempDir "VisualStudioSetup.exe"

if ($vsInstalled) {
    $doUpdate = $false
    if ($script:NoPrompt) {
        $doUpdate = $true
    } else {
        $answer = Read-Host "  Update VS 2026 and ensure all required components are installed? (Y/N)"
        if ($answer -match '^[Yy]') { $doUpdate = $true }
    }

    if ($doUpdate) {
        try {
            Get-Installer -Url $vsSetupUrl -OutFile $vsSetupExe -DisplayName "VS 2026 bootstrapper"

            $exitCode = Start-InstallerWithProgress -FilePath $vsSetupExe `
                -Arguments "update --installPath `"$vsInstallPath`" $vsUiMode --norestart --wait" `
                -StepName "VS 2026 update"
            if ($exitCode -ne 0 -and $exitCode -ne 3010) {
                Write-Warn "VS update exited with code $exitCode"
            } else {
                Write-Status "VS 2026 update completed."
            }

            $exitCode = Start-InstallerWithProgress -FilePath $vsSetupExe `
                -Arguments "modify --installPath `"$vsInstallPath`" --config `"$vsConfigPath`" $vsUiMode --norestart --wait" `
                -StepName "VS 2026 modify"
            if ($exitCode -ne 0 -and $exitCode -ne 3010) {
                Write-Warn "VS modify exited with code $exitCode"
            } else {
                Write-Status "VS 2026 components verified/installed."
            }

            if ($exitCode -eq 3010) {
                Write-Warn "A system restart is required to complete VS 2026 changes."
            }
        } catch {
            Write-Err "VS 2026 update/modify failed: $_"
        }
    }
} else {
    $doInstall = $false
    if ($script:NoPrompt) {
        $doInstall = $true
    } else {
        $answer = Read-Host "  Install VS 2026 Community Edition? (Y/N)"
        if ($answer -match '^[Yy]') { $doInstall = $true }
    }

    if ($doInstall) {
        try {
            Get-Installer -Url $vsSetupUrl -OutFile $vsSetupExe -DisplayName "VS 2026 bootstrapper"

            $exitCode = Start-InstallerWithProgress -FilePath $vsSetupExe `
                -Arguments "--config `"$vsConfigPath`" $vsUiMode --norestart --wait" `
                -StepName "VS 2026 install"
            if ($exitCode -ne 0 -and $exitCode -ne 3010) {
                throw "VS installer exited with code $exitCode"
            }
            Write-Status "VS 2026 Community installed successfully."
            if ($exitCode -eq 3010) {
                Write-Warn "A system restart is required to complete VS 2026 installation."
            }
        } catch {
            Write-Err "VS 2026 installation failed: $_"
        }
    } else {
        Write-Warn "VS 2026 Community not installed."
    }
}

# ---------------------------------------------
# 2. Windows Driver Kit (WDK)
# ---------------------------------------------
Write-Section "Windows Driver Kit (WDK)"

$wdkInstalled = $false
$wdkKitsRoot = "${env:ProgramFiles(x86)}\Windows Kits\10"
if (Test-Path $wdkKitsRoot) {
    $kmPaths = Get-ChildItem (Join-Path $wdkKitsRoot "Include\*\km") -Directory -ErrorAction SilentlyContinue
    if ($kmPaths) {
        $wdkInstalled = $true
        $wdkVersions = ($kmPaths | ForEach-Object { $_.Parent.Name }) -join ", "
        Write-Status "WDK is installed (versions: $wdkVersions)"
    }
}

if (-not $wdkInstalled) {
    Write-Host "[MISS]  WDK is not installed." -ForegroundColor Yellow

    $doInstall = $false
    if ($script:NoPrompt) {
        $doInstall = $true
    } else {
        $answer = Read-Host "  Install Windows Driver Kit? (Y/N)"
        if ($answer -match '^[Yy]') { $doInstall = $true }
    }

    if ($doInstall) {
        $wdkUrl = "https://go.microsoft.com/fwlink/?LinkId=2362091"
        $wdkSetupExe = Join-Path $tempDir "wdksetup.exe"
        try {
            Get-Installer -Url $wdkUrl -OutFile $wdkSetupExe -DisplayName "WDK Setup"

            $exitCode = Start-InstallerWithProgress -FilePath $wdkSetupExe `
                -Arguments "/features + /q /norestart /ceip off" `
                -StepName "WDK install (web installer, may take 20+ min)" `
                -ForceConsoleProgress
            if ($exitCode -ne 0 -and $exitCode -ne 3010) {
                throw "WDK installer exited with code $exitCode"
            }
            Write-Status "WDK installed successfully."
            if ($exitCode -eq 3010) {
                Write-Warn "A system restart is required to complete WDK installation."
            }
        } catch {
            Write-Err "WDK installation failed: $_"
        }
    } else {
        Write-Warn "WDK not installed."
    }
}

# ---------------------------------------------
# 3. Additional Tools (WinFSP, CPDK)
# ---------------------------------------------
Write-Section "Additional Tools"

$tools = @(
    @{
        Name        = "WinFSP 2023 (v2.0)"
        TestPath    = "${env:ProgramFiles(x86)}\WinFsp"
        TestAlt     = "$env:ProgramFiles\WinFsp"
        DownloadUrl = "https://github.com/winfsp/winfsp/releases/download/v2.0/winfsp-2.0.23075.msi"
        FileName    = "winfsp-2.0.23075.msi"
        InstallCmd  = {
            param($path, $isSilent)
            if ($isSilent) { $ui = "/qn" } else { $ui = "/qb" }
            Start-Process msiexec.exe -ArgumentList "/i `"$path`" $ui /norestart ADDLOCAL=F.Main,F.User,F.Developer,F.KernelDeveloper" -Wait -PassThru
        }
    },
    @{
        Name        = "CPDK 8.0"
        TestPath    = "${env:ProgramFiles(x86)}\Windows Kits\10\Cryptographic Provider Development Kit"
        DownloadUrl = "https://download.microsoft.com/download/1/7/6/176909b0-50f2-4df3-b29b-830a17ea7e38/CPDK_RELEASE_UPDATE/cpdksetup.exe"
        FileName    = "cpdksetup.exe"
        InstallCmd  = {
            param($path, $isSilent)
            Start-Process -FilePath $path -ArgumentList "/features + /q /norestart /ceip off" -Wait -PassThru
        }
    }
)

foreach ($tool in $tools) {
    $installed = $false
    if ($tool.TestPath -and (Test-Path $tool.TestPath)) { $installed = $true }
    if (-not $installed -and $tool.TestAlt -and (Test-Path $tool.TestAlt)) { $installed = $true }

    if ($installed) {
        Write-Status "$($tool.Name) is already installed."
    } else {
        Write-Host "[MISS]  $($tool.Name) is not installed." -ForegroundColor Yellow

        $doInstall = $false
        if ($script:NoPrompt) {
            $doInstall = $true
        } else {
            $answer = Read-Host "  Install $($tool.Name) now? (Y/N)"
            if ($answer -match '^[Yy]') { $doInstall = $true }
        }

        if ($doInstall) {
            $installerPath = Join-Path $tempDir $tool.FileName
            try {
                Get-Installer -Url $tool.DownloadUrl -OutFile $installerPath -DisplayName $tool.Name

                Write-Info "Installing $($tool.Name)..."
                $proc = & $tool.InstallCmd $installerPath $Quiet
                if ($proc.ExitCode -ne 0) {
                    throw "Installer exited with code $($proc.ExitCode)"
                }
                Write-Status "$($tool.Name) installed successfully."
            } catch {
                Write-Err "Failed to download/install $($tool.Name): $_"
            }
        } else {
            Write-Warn "$($tool.Name) not installed. Install manually from: $($tool.DownloadUrl)"
        }
    }
}

# ---------------------------------------------
# Summary
# ---------------------------------------------
Write-Section "Summary"

if ($script:errors.Count -eq 0 -and $script:warnings.Count -eq 0) {
    Write-Host "`nDevelopment environment is fully configured." -ForegroundColor Green
} else {
    if ($script:warnings.Count -gt 0) {
        Write-Host "`nWarnings ($($script:warnings.Count)):" -ForegroundColor Yellow
        $script:warnings | ForEach-Object { Write-Host "  - $_" -ForegroundColor Yellow }
    }
    if ($script:errors.Count -gt 0) {
        Write-Host "`nErrors ($($script:errors.Count)):" -ForegroundColor Red
        $script:errors | ForEach-Object { Write-Host "  - $_" -ForegroundColor Red }
        Write-Host "`nSetup is INCOMPLETE. Fix the errors above." -ForegroundColor Red
        exit 1
    }
}
