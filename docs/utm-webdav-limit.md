# UTM WebDAV File Size Limit

`utm-webdav-limit-change.ps1` is only relevant if this Windows machine
is a **VM guest running under [UTM](https://mac.getutm.app/)** (Apple's
QEMU/Apple Virtualization based hypervisor for macOS) with a **SPICE
WebDAV shared folder** configured between the Mac host and the Windows
guest. It has no purpose on bare metal or under any other hypervisor.

## The problem

Windows' built-in WebDAV client (the `WebClient` service, aka "Web
Client") caps file transfers over WebDAV shares at a default limit far
below what's practical for a shared-folder workflow (build artifacts,
VM snapshots, etc. moved between host and guest). UTM's SPICE WebDAV
shared folder is exposed to the guest as exactly this kind of WebDAV
share (mounted as a network drive via `net use Z:
\\localhost@<port>\DavWWWRoot`), so it inherits the same low default
limit — large file copies silently fail partway through.

## What the script does

1. Detects the currently mapped WebDAV/SPICE drive(s) — first via
   persistent drive mappings in the registry, falling back to
   auto-detecting the SPICE WebDAV port (`9843`/`9844`/`8000`) if none
   are found.
2. Raises
   `HKLM:\SYSTEM\CurrentControlSet\Services\WebClient\Parameters\FileSizeLimitInBytes`
   to `4294967295` bytes (~4 GB) by default — a no-op if it's already
   set to the requested value.
3. Restarts the `WebClient` service so the new limit takes effect.
4. Remaps the previously detected drive(s) — both in the current
   (elevated) session and in the interactive (non-elevated) user
   session via a short-lived scheduled task, since elevated and
   non-elevated sessions have separate drive-letter namespaces under
   UAC.

If no existing WebDAV drive is detected, the script still applies the
registry change and service restart, then prints the `net use` command
to map the share manually (adjust the port to match your VM).

## Why 4 GB, and why that's a hard ceiling

`FileSizeLimitInBytes` is a 32-bit `REG_DWORD` — `4294967295` (2³²−1)
is the highest value that field can hold, full stop. This isn't an
arbitrary choice modeled after FAT32's file size limit (which happens
to be the same number only because both are constrained by a 32-bit
size field); it's the literal maximum the Windows `WebClient` service
supports, confirmed against Microsoft's documented behavior for this
setting. There is no registry value, and no other configuration, that
raises a WebDAV transfer above ~4 GB.

For **Windows** guests specifically, this is also effectively the best
sharing option UTM offers at all: UTM's other, faster shared-folder
mechanism (VirtioFS/VirtFS) is only available for **Linux** guests —
SPICE WebDAV is the only cross-platform option, so this registry tweak
is the practical optimum for this sharing method on Windows, not a
partial workaround for a better alternative.

**If you need to move files larger than ~4 GB** (VHDX images, ISOs,
large build artifacts) between host and guest, this share fundamentally
can't do it — reach for something else instead, e.g. an SMB share from
the Mac host (Windows has far more mature SMB support than WebDAV), or
`scp`/`rsync` over SSH if the guest has an SSH server configured.

## Parameters

| Parameter | Description |
|---|---|
| `-FileSizeLimitBytes` | Target value for `FileSizeLimitInBytes`, in bytes. Default: `4294967295` (~4 GB, the maximum possible — see above). Rejects anything above that maximum; only useful to lower if you deliberately want a smaller cap. |

## Running the script

```cmd
utm-webdav-limit-change.cmd
```

or, to set a smaller-than-default limit (e.g. 1 GB):

```cmd
utm-webdav-limit-change.cmd -FileSizeLimitBytes 1073741824
```

or directly, from an elevated PowerShell prompt:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\utm-webdav-limit-change.ps1
```

Requires Administrator privileges (checked up front, exits immediately
if not elevated). Idempotent — if the registry value is already at the
target, the script exits right away without restarting the service or
touching drive mappings.

## Requirements

- **Windows 10/11 guest**, running under **UTM** on a Mac host
- A **SPICE WebDAV shared folder** already configured in UTM for this VM
- **Administrator privileges**
