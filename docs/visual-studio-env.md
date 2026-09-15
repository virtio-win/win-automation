# Visual Studio Build Environment

`setup-vs2022-env.ps1` / `setup-vs2026-env.ps1` set up a full Visual
Studio development environment for building and debugging Windows
drivers from the
[kvm-guest-drivers-windows](https://github.com/virtio-win/kvm-guest-drivers-windows/)
repository. After either script completes, you can open
`virtio-win.sln` and the drivers are ready to build. Both scripts are
idempotent — safe to re-run on an already-configured machine.

## setup-vs2022-env

- Installs/updates **VS 2022 Community** with all components required
  for driver development
- Installs **WDK 26000**
- Installs **WinFSP**, **CPDK**

```powershell
.\setup-vs2022-env.cmd                  # interactive
.\setup-vs2022-env.cmd -a               # automatic
.\setup-vs2022-env.cmd -q               # quiet
```

## setup-vs2026-env

Same as above but targeting **Visual Studio 2026 Community** (version
range 18.x) with SDK/WDK 28000.

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

`-Automatic` and `-Quiet` are mutually exclusive. Without either, the
script asks before each step.

## Requirements

- **Windows 10/11** or **Windows Server 2019+**
- **PowerShell 5.1** (built-in on Windows 10+)
- **Administrator privileges** — both scripts install software and
  write to `C:\`, which requires elevation.

## Running the scripts

Each `.ps1` script has a matching `.cmd` wrapper that handles execution
policy, so you can run it from `cmd.exe` or double-click:

```cmd
setup-vs2022-env.cmd -a
```

To run the PowerShell script directly (e.g. from an elevated PowerShell
prompt):

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\setup-vs2022-env.ps1 -a
```
