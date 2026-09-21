# Visual Studio Build Environment

`setup-vs2022-env.ps1` / `setup-vs2026-env.ps1` set up a full Visual Studio development environment for building and debugging Windows drivers from the [kvm-guest-drivers-windows](https://github.com/virtio-win/kvm-guest-drivers-windows/) repository. After either script completes, you can open `virtio-win.sln` and the drivers are ready to build. The scripts do not clone the driver repository or build it; obtain that repository separately. On a later run they check the installed components and update/repair the Visual Studio installation when the selected mode requests it.

## setup-vs2022-env

- Installs/updates **VS 2022 Community** with the components required
  for driver development
- Installs **Windows 11 SDK/WDK 26100**
- Installs **WinFSP**, **CPDK**

```powershell
.\setup-vs2022-env.cmd                  # interactive
.\setup-vs2022-env.cmd -a               # automatic
.\setup-vs2022-env.cmd -q               # quiet
```

## setup-vs2026-env

Same as above but targeting **Visual Studio 2026 Community** (version range 18.x) with SDK/WDK 28000.

```powershell
.\setup-vs2026-env.cmd                  # interactive
.\setup-vs2026-env.cmd -a               # automatic
.\setup-vs2026-env.cmd -q               # quiet
```

## Parameters

| Parameter | Alias | Description |
|---|---|---|
| `-Automatic` | `-a` | No prompts. Installers may show progress UI. |
| `-Quiet` | `-q` | No prompts, no UI. Console output only. |
| `-Help` | `-h` | Show built-in help (`Get-Help`). |

`-Automatic` and `-Quiet` are mutually exclusive. Without either, the script asks before each step.

## Requirements

- A supported 64-bit host OS. For this setup, use **Windows 11** or
  **Windows Server 2019, 2022, or 2025 with Desktop Experience**. Visual Studio's supported OS list and lifecycle can change; see Microsoft's [Visual Studio 2022 system requirements](https://learn.microsoft.com/visualstudio/releases/2022/system-requirements) and [Visual Studio 2026 system requirements](https://learn.microsoft.com/visualstudio/releases/2026/vs-system-requirements).
- **PowerShell 5.1** (built-in on Windows 10+)
- **Administrator privileges** — both scripts install software and
  write to `C:\`, which requires elevation.

The host architecture and the driver target architecture are separate: these scripts configure the host and install x64/ARM64 toolchains, while the target platform (for example, x64 or ARM64) is selected when building the driver solution. A host's architecture does not by itself select the driver target.

## Running the scripts

Change to `dev-env-bootstrap` first, or invoke the wrapper by its full path. Each `.ps1` script has a matching `.cmd` wrapper that handles execution policy, so you can run it from `cmd.exe` or double-click:

```cmd
cd /d path\to\win-automation\dev-env-bootstrap
setup-vs2022-env.cmd -a
```

To run the PowerShell script directly (e.g. from an elevated PowerShell prompt):

```powershell
Set-Location path\to\win-automation\dev-env-bootstrap
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\setup-vs2022-env.ps1 -a
```

After setup, clone or otherwise obtain `kvm-guest-drivers-windows` and open its solution from that checkout; the setup scripts do not clone or build it.
