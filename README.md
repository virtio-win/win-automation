# Windows Automation Tools

A collection of automation tooling for Windows environments, split into two areas:

- [`win-bootstrap/`](win-bootstrap/) — the generic, config-driven bootstrap
  engine for a freshly installed Windows machine.
- [`dev-env-bootstrap/`](dev-env-bootstrap/) — PowerShell scripts that run
  *inside* an already-bootstrapped Windows guest/machine to set up
  build environments for
  [kvm-guest-drivers-windows](https://github.com/virtio-win/kvm-guest-drivers-windows/)
  and supporting VM tooling.

All documentation for both areas lives under [`docs/`](docs/); the
code folders themselves contain only scripts/config.

## Documentation

### Windows bootstrap

- [Configuration reference](docs/windows-bootstrap.md)

### Development environment bootstrap

- [Visual Studio build environment](docs/visual-studio-env.md)
- [UTM WebDAV file size limit](docs/utm-webdav-limit.md)

## win-bootstrap

A generic, config-driven bootstrap engine for a freshly installed Windows
machine (Windows 10/11, x64 or arm64) — unlike the scripts under
`dev-env-bootstrap/` below, it has no personal data baked in at all; every
action is driven by an external YAML config, so the same script works for
anyone. It can, among other things:

- Import trusted root CA certificates.
- Set up OpenSSH Server with pinned host keys and key-based login.
- Create and configure local user accounts.
- Configure firewall rules and SMB shares.
- Configure kernel debugging.
- Install apps and common Windows tooling.
- Manage selected Windows security, network, recovery, and power settings.
- And more — every capability is opt-in per config section and idempotent.

Real secrets (certificates, private keys, passwords) can be sourced from
**Bitwarden Secrets Manager** instead of ever being written into the config
file.

See [`docs/windows-bootstrap.md`](docs/windows-bootstrap.md) for the full
reference — start with its TL;DR section for the fastest path to a
working config.

## dev-env-bootstrap scripts

### Requirements

- **Windows 10/11** or **Windows Server 2019+**
- **PowerShell 5.1** (built-in on Windows 10+)
- **Administrator privileges** — most scripts install software, write
  to `C:\`, and set machine-level environment variables, all of which
  require elevation. See each script's own doc for exceptions.

### Running the scripts

All scripts below live under [`dev-env-bootstrap/`](dev-env-bootstrap/) —
run them from inside that folder (or prefix the path as shown).

Each `.ps1` script has a matching `.cmd` wrapper that handles execution
policy, so you can run it from `cmd.exe` or double-click:

```cmd
dev-env-bootstrap\setup-vs2022-env.cmd -a
```

To run the PowerShell script directly (e.g. from an elevated PowerShell
prompt):

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\dev-env-bootstrap\setup-vs2022-env.ps1 -a
```

Most scripts share the same core CLI interface (`-Automatic`/`-a`,
`-Quiet`/`-q`, `-Help`/`-h`) — see each script's own doc for the full
parameter reference.
