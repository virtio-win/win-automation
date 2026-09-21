# Windows Bootstrap Compatibility

`win-bootstrap.ps1` primarily targets Windows 10 and Windows 11. Its core machine-configuration features are also expected to work on Windows Server 2019, 2022, and 2025, but Windows Server support is currently limited and has not been validated as a complete end-to-end configuration.

The table below describes the current implementation. It is not a guarantee that every possible configuration has been tested on every listed operating system.

## Compatibility matrix

| Capability | Windows 10/11 | Server 2019 | Server 2022 | Server 2025 |
| --- | --- | --- | --- | --- |
| Core machine configuration | Supported | Limited; not end-to-end validated | Limited; not end-to-end validated | Limited; not end-to-end validated |
| WinGet app installation | Supported when available | Not available by default | Not available by default | Available, subject to image/features |
| PowerShell 7 installation | WinGet required | Limited; WinGet required | Limited; WinGet required | Limited; WinGet required |
| Windows Terminal | Client/desktop only | Not supported | Limited; WinGet required | Desktop Experience only |
| OpenSSH Server | Supported | Limited; current flow uses WinGet | Limited; current flow uses WinGet | Limited; current flow uses WinGet |
| Windows `sudo` | Windows 11 24H2+ only | Not supported | Not supported | Not supported |
| Desktop removal and first-login setup | Supported where applicable | Desktop Experience only | Desktop Experience only | Desktop Experience only |
| VBS/Credential Guard changes | Supported with limitations | Limited | Limited | Limited; policy/UEFI may override |

## Important Windows Server limitations

- **WinGet dependencies:** the current `apps`, `install_powershell7`,
  `windows_terminal`, and `ssh_server` implementations depend on WinGet. WinGet is available by default on Windows Server 2025, but not on Windows Server 2019 or 2022. Manually adding WinGet to those releases is outside the supported bootstrap workflow.
- **OpenSSH:** Windows Server 2019 and 2022 provide OpenSSH Server as a Windows
  capability. Windows Server 2025 includes it by default. The bootstrap script does not currently use these server-native installation paths.
- **Server Core:** GUI-oriented operations, Windows Terminal, desktop
  shortcuts, and interactive first-login application setup are not suitable for Server Core installations.
- **Windows sudo:** Windows `sudo` is a Windows 11 feature. It is not supported
  on Windows Server, including Server 2025.
- **Domain network profiles:** Windows controls the `DomainAuthenticated`
  network category. A configuration that attempts to change such a profile to `Private` or `Public` may fail on a domain-joined server.
- **VBS and Credential Guard:** registry changes alone may not fully disable
  security features enforced by Group Policy or protected by a UEFI lock. This is particularly relevant to Windows Server 2025.
- **Localized installations:** local-user configuration currently refers to
  the built-in `Administrators` group by its English name, which can fail on a non-English Windows installation.

Use `-Only` and `-Skip` to restrict a server configuration to compatible steps. Review the output of `-Verify` carefully; verification confirms the state checks implemented by the script, not general operating-system support.

## Relevant Microsoft documentation

- [WinGet overview](https://learn.microsoft.com/windows/package-manager/winget/)
- [OpenSSH for Windows overview](https://learn.microsoft.com/windows-server/administration/openssh/openssh-overview)
- [Get started with OpenSSH Server for Windows](https://learn.microsoft.com/windows-server/administration/openssh/openssh_install_firstuse)
- [Sudo for Windows](https://learn.microsoft.com/windows/advanced-settings/sudo/)
- [Server Core and Desktop Experience installation options](https://learn.microsoft.com/windows-server/get-started/install-options-server-core-desktop-experience)
