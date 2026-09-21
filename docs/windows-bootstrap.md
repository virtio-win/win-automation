# win-bootstrap.ps1 — Windows Bootstrap Script

`win-bootstrap.ps1` is a generic, config-driven bootstrap engine for a freshly installed Windows machine (Windows 10/11, x64 or arm64). It has no personal data baked into it at all — every action it can take is driven entirely by an external YAML configuration file, so the same script works for anyone; only the config differs.

Core functionality is also expected to work on Windows Server 2019, 2022, and 2025, but server support is currently limited. Some features require WinGet or Desktop Experience and are unavailable on older Server releases or Server Core. Review the [operating system compatibility matrix](windows-bootstrap-compatibility.md) before using the script on Windows Server.

## TL;DR

From the repository's `win-bootstrap` directory, create a deliberately small config. Validate it first, then apply it. The validation command needs no elevation and does not apply any machine changes:

```powershell
@'
power:
  display_off_after:
    on_power: 15
'@ | Set-Content .\win-bootstrap.config.yaml

powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\win-bootstrap.ps1 -ConfigPath .\win-bootstrap.config.yaml -ValidateConfig
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\win-bootstrap.ps1 -ConfigPath .\win-bootstrap.config.yaml
```

Run the final command from an elevated PowerShell session, or let the script offer a UAC relaunch. `-Quiet` is non-interactive: it auto-confirms confirmation-gated risky operations, fails if elevation is unavailable, and may reboot when the configured changes require it. See [Quick Use](#quick-use) for execution notes and [Deployment](#deployment) for URL, private-config, corporate-CA, and Bitwarden scenarios.

## Table of Contents

- [TL;DR](#tldr)
- [Overview](#overview)
- [Operating System Compatibility](windows-bootstrap-compatibility.md)
- [Quick Use](#quick-use)
- [What Bootstrap Can Do](#what-bootstrap-can-do)
- [CLI Parameters and Environment Variables](#cli-parameters-and-environment-variables)
  - [Run transcript and exit status](#run-transcript-and-exit-status)
- [Secrets](#secrets)
  - [Sources](#sources)
  - [Which fields support which sources](#which-fields-support-which-sources)
  - [SSH public key lists](#ssh-public-key-lists)
  - [On-machine generation](#on-machine-generation)
  - [Bitwarden Secrets Manager](#bitwarden-secrets-manager)
- [Configuration File](#configuration-file)
  - [General](#general) — format, source resolution, secrets, `disabled: true`
  - [`disable_pwsh_execution_policy`](#disable_pwsh_execution_policy) — allow running local PowerShell scripts
  - [`root_ca`](#root_ca) — install trusted root CA certificates
  - [`recovery_partition`](#recovery_partition) — delete recovery partition, extend system drive
  - [`disable_vbs`](#disable_vbs) — disable Virtualization-Based Security
  - [`remove_onedrive`](#remove_onedrive) — uninstall OneDrive
  - [`remove_teams`](#remove_teams) — uninstall Microsoft Teams
  - [`remove_outlook`](#remove_outlook) — uninstall Outlook (new)
  - [`defender_exclusions`](#defender_exclusions) — Windows Defender path exclusions
  - [`uac_level`](#uac_level) — set the User Account Control level
  - [`apps`](#apps) — install apps via winget
  - [`install_powershell7`](#install_powershell7) — install PowerShell 7, native MSI build
  - [`windows_terminal`](#windows_terminal) — install Windows Terminal, set default profile
  - [`ssh_server`](#ssh_server) — OpenSSH Server, host keys, authorized keys, default shell
  - [`disable_winssh_agent`](#disable_winssh_agent) — disable Windows ssh-agent service
  - [`computer_name`](#computer_name) — rename the computer
  - [`firewall`](#firewall) — network profile, ICMP ping rule
  - [`smb_shares`](#smb_shares) — create SMB file shares
  - [`local_users`](#local_users) — create local user accounts, per-user SSH keys
  - [`sudo`](#sudo) — configure Windows' built-in sudo
  - [`crash_dump`](#crash_dump) — configure crash dump type/path
  - [`kernel_debugging`](#kernel_debugging) — configure kernel debugging via BCD
  - [`windows_product_key`](#windows_product_key) — install and activate a Windows product key
  - [`power`](#power) — sleep/display timeout settings
  - [`network`](#network) — static IP/gateway/DNS/MAC address
  - [`delete_bootstrap_user`](#delete_bootstrap_user) — delete the account that ran bootstrap
- [Reboot handling](#reboot-handling)
- [Usage Scenarios](#usage-scenarios)
  - [Bootstrapping under an account you're keeping](#bootstrapping-under-an-account-youre-keeping)
  - [Bootstrapping from a disposable template account](#bootstrapping-from-a-disposable-template-account)
- [Deployment](#deployment)

## Overview

- **No personal data in the script.** `win-bootstrap.ps1` itself is
  generic and safe to share/publish; anything machine- or person-specific (certificates, SSH keys, computer name, app list) lives in a separate YAML config file.
- **Opt-in per step.** A config with no entry for a given step simply
  skips that step — this is expected, not an error. A config containing only one section (e.g. just `root_ca`) is perfectly valid.
- **State-aware steps.** Many steps compare the current machine state before
  acting, but a real run can still write configuration, schedule deferred work, restart services, or request a reboot. Review the configured steps before re-running it.
- **Requires Administrator.** The script self-elevates (prompts to
  relaunch as Administrator) unless run with `-Quiet`, in which case it fails fast if not already elevated instead of prompting.
- **Read-only verification mode.** `-Verify` checks the machine against
  the config and reports `OK` / `NOT APPLIED` / `ERROR` / `UNKNOWN` per step without ever changing anything — see [CLI Parameters and Environment Variables](#cli-parameters-and-environment-variables).

## Quick Use

Use the minimal local example in [TL;DR](#tldr) as a starting point, then add only the configuration sections you need. Notes on running it:

- **Execution policy**: the example passes `-ExecutionPolicy Bypass` to
  each PowerShell process. This does not change the persistent machine execution policy or require a separate `Set-ExecutionPolicy` command.
- **Elevation**: the script detects if it isn't already running as
  Administrator and prompts you to relaunch itself elevated. For a fully unattended run (no prompts at all), add `-Quiet` — in that mode the script fails immediately with an error instead of prompting if it isn't already elevated, so launch it from an already-elevated prompt.
- For a config URL that requires authentication, set
  `$env:BOOTSTRAP_CONFIG_TOKEN` before running. It is sent only to that URL's origin; see [Config source](#config-source) for the redirect and process-argument safeguards.
- If the config URL sits behind a corporate TLS-inspecting proxy with an
  untrusted internal CA, see [Deployment](#deployment) below for `-ConfigCaPath` / `-ConfigCaUrl` / `-ConfigUrlInsecureSkipCertCheck`.

See [Deployment](#deployment) for URL and private-config scenarios, and the recommended `win-bootstrap.cmd` wrapper for repeat use.

## What Bootstrap Can Do

Every capability below is opt-in via its config key, and can also be selectively included/excluded on the command line via `-Only`/`-Skip` and its tag (see [CLI Parameters and Environment Variables](#cli-parameters-and-environment-variables)).

- **Set PowerShell execution policy** — allows running local PowerShell
  scripts (`Set-ExecutionPolicy Unrestricted`, `LocalMachine` scope).
  - Tag: `execution_policy`
  - Config: [`disable_pwsh_execution_policy`](#disable_pwsh_execution_policy)
- **Install trusted root CA certificates** — imports one or more CA
  certificates into `Cert:\LocalMachine\Root`.
  - Tag: `root_ca`
  - Config: [`root_ca`](#root_ca)
- **Remove the recovery partition and extend the system drive** —
  deletes the Windows Recovery partition (destructive, confirmation-gated unless `-Quiet`) and optionally grows the system drive into the freed space.
  - Tag: `recovery_partition`
  - Config: [`recovery_partition`](#recovery_partition)
- **Disable Virtualization-Based Security** — turns off Core
  Isolation/Memory Integrity, mainly useful when the target machine is itself a VM.
  - Tag: `vbs`
  - Config: [`disable_vbs`](#disable_vbs)
- **Remove OneDrive** — stops and uninstalls OneDrive for the current
  account, and sets the machine-wide `DisableFileSyncNGSC` policy so it isn't silently reprovisioned for any account created afterward (e.g. via `local_users`).
  - Tag: `onedrive`
  - Config: [`remove_onedrive`](#remove_onedrive)
- **Remove Microsoft Teams** — removes the AppX-provisioned package,
  any per-user installed package, and the classic "Teams Machine-Wide Installer", whichever are present.
  - Tag: `teams`
  - Config: [`remove_teams`](#remove_teams)
- **Remove Outlook (new)** — removes the `Microsoft.OutlookForWindows`
  AppX-provisioned package and any per-user installed package. Does not touch classic desktop Outlook (Office).
  - Tag: `outlook`
  - Config: [`remove_outlook`](#remove_outlook)
- **Configure Windows Defender exclusions** — excludes one or more paths
  from Defender scanning.
  - Tag: `defender`
  - Config: [`defender_exclusions`](#defender_exclusions)
- **Set UAC level** — sets User Account Control to one of Windows' own
  defined levels (off, never notify, default, always notify).
  - Tag: `uac`
  - Config: [`uac_level`](#uac_level)
- **Install apps via winget** — installs any number of packages by
  winget ID.
  - Tag: `apps`
  - Config: [`apps`](#apps)
- **Install PowerShell 7** — installs the native MSI build (not the
  MSIX/Store package), needed for `ssh_server.default_shell`/ `windows_terminal.default_profile: pwsh7`.
  - Tag: `powershell7`
  - Config: [`install_powershell7`](#install_powershell7)
- **Install and configure Windows Terminal** — installs Windows Terminal
  via winget if missing, and optionally sets its default profile.
  - Tag: `windows_terminal`
  - Config: [`windows_terminal`](#windows_terminal)
- **Enable OpenSSH Server** — installs and starts `sshd`, configures
  key-based login, pinned host keys, and the default shell for incoming sessions.
  - Tag: `ssh`
  - Config: [`ssh_server`](#ssh_server)
- **Disable the Windows ssh-agent service** — stops/disables it so a
  third-party agent (e.g. Bitwarden's) can take over.
  - Tag: `winssh_agent`
  - Config: [`disable_winssh_agent`](#disable_winssh_agent)
- **Set the computer name** — renames the machine (takes effect after
  reboot).
  - Tag: `computer_name`
  - Config: [`computer_name`](#computer_name)
- **Configure the network profile and ICMP ping rule** — sets the
  network category (Public/Private) and a dedicated inbound ping-allow firewall rule.
  - Tag: `firewall`
  - Config: [`firewall`](#firewall)
- **Configure SMB file shares** — creates one or more SMB shares with a
  chosen access level (also needs `firewall.smb` to be reachable).
  - Tag: `smb`
  - Config: [`smb_shares`](#smb_shares)
- **Create local user accounts** — creates local Windows accounts
  (several password-source options), reconciles Administrators group membership, initializes their real Windows profile, and (much later in the run, once OpenSSH is installed) configures per-user SSH keys. Account creation and profile initialization run near the very start of the run, ahead of most other steps.
  - Tag: `local_users`
  - Config: [`local_users`](#local_users)
- **Schedule first-login setup for local user accounts** — registers a
  self-deleting Scheduled Task per account that installs its `scope: user` [`apps`](#apps) the next time that account actually logs in interactively.
  - Tag: `first_login`
  - Config: [`local_users`](#local_users) (`complete_setup_on_first_login`)
- **Configure `sudo` for Windows** — sets the mode of Windows 11
  24H2+'s built-in `sudo` command.
  - Tag: `sudo`
  - Config: [`sudo`](#sudo)
- **Configure crash dump behavior** — sets the type (and optionally path)
  of memory dump Windows writes on a crash.
  - Tag: `crash_dump`
  - Config: [`crash_dump`](#crash_dump)
- **Configure kernel debugging** — enables `bcdedit`-based kernel
  debugging (serial or network transport), optionally on a dedicated boot entry rather than the default one.
  - Tag: `kernel_debugging`
  - Config: [`kernel_debugging`](#kernel_debugging)
- **Install and activate Windows product key** — installs a product key
  and requests online activation. Compares against whatever's already installed first, so an already-activated machine with a matching key is left alone.
  - Tag: `product_key`
  - Config: [`windows_product_key`](#windows_product_key)
- **Configure power sleep/display timeouts** — sets how long until the
  machine sleeps and/or the display turns off, separately for plugged-in (AC) and battery (DC) power.
  - Tag: `power`
  - Config: [`power`](#power)
- **Configure a static IP/gateway/DNS/MAC address** — IP/gateway/DNS
  either right away or deferred to the next reboot via a scheduled task (applying it immediately can drop the very session bootstrap is running over); MAC is always deferred to a reboot via a registry write, never applied live.
  - Tag: `network`
  - Config: [`network`](#network)
- **Delete the bootstrap user account** — permanently deletes the local
  account that ran this script, once it's no longer needed (e.g. after a real admin account has been provisioned). Confirmation-gated, and refuses outright if it would leave the machine with no other enabled Administrator.
  - Tag: `cleanup`
  - Config: [`delete_bootstrap_user`](#delete_bootstrap_user)

## CLI Parameters and Environment Variables

### Config source

Resolved in this priority order — the first one that resolves wins:

| Priority | Parameter | Environment variable |
|---|---|---|
| 1 | `-ConfigPath <path>` | — |
| 2 | `-ConfigUrl <url>` | — |
| 3 | — | `BOOTSTRAP_CONFIG_PATH` |
| 4 | — | `BOOTSTRAP_CONFIG_URL` |
| 5 | *(default)* `win-bootstrap.config.yaml` next to the script | — |

`-ConfigPath`/`-ConfigUrl` (and their environment variable equivalents) are mutually exclusive with each other. If nothing resolves, the script errors out.

For a config fetched via URL from a private repo/server, set `$env:BOOTSTRAP_CONFIG_TOKEN`. The token is sent as an `Authorization: Bearer <token>` header only to the selected config URL's origin (scheme, host, and port). Authenticated redirects to a different origin are rejected. The token is read only from the environment, never accepted as a parameter or placed in child-process arguments. Setting an environment variable with a literal secret in an interactive command can still record it in shell history; use your secret manager or CI secret injection for that handoff.

### Certificate trust for the config fetch itself

If `-ConfigUrl`/`BOOTSTRAP_CONFIG_URL` sits behind a corporate TLS-inspecting proxy, the config fetch fails certificate validation before the config — the only place a corporate root CA would normally be declared, via [`root_ca`](#root_ca) — has even been parsed. Three independent, opt-in ways to resolve that:

| Parameter | Environment variable | Use when |
|---|---|---|
| `-ConfigCaPath <path>` | `BOOTSTRAP_CONFIG_CA_PATH` | The CA certificate is already a local file on this machine. |
| `-ConfigCaUrl <url>` | `BOOTSTRAP_CONFIG_CA_URL` | The CA certificate is published on its own URL that is itself served with an ordinary, already publicly-trusted certificate (e.g. a corporate IT download page) — the common case. |
| `-ConfigUrlInsecureSkipCertCheck` (switch) | — | Last resort: skips certificate validation, but only for the one request that fetches the config. Only use this against a URL you already trust by other means. |

When an authenticated fetch uses the insecure curl path, the token is stored in an ACL-protected temporary header file. Curl receives the file's path via `-H @<path>`, not the token value, in its process arguments. The header file and temporary response files are removed after the fetch. The fetch is also performed outside the persistent run transcript.

`-ConfigCaPath` and `-ConfigCaUrl` are mutually exclusive with each other. Both install the certificate into `Cert:\LocalMachine\Root` *before* the config is resolved/fetched; it's safe to also declare the same certificate under [`root_ca`](#root_ca) in the config (it won't be installed twice).

### Other parameters

| Parameter | Environment variable | Description |
|---|---|---|
| `-Download` (switch) | — | Only meaningful with `-ConfigUrl`/`BOOTSTRAP_CONFIG_URL`: writes the fetched config text to the explicit file `win-bootstrap.config.yaml` next to the script. Prompts before overwriting an existing file (errors instead, under `-Quiet`). No effect when the config came from a local path. |
| `-Verify` (switch) | — | Read-only mode: checks only the state checks implemented for the config and reports `OK` / `NOT APPLIED` / `ERROR` (or `UNKNOWN` if a step has no verification check) per step. It is not a guarantee that every desired or deferred effect is complete. Still requires elevation. Mutually exclusive with `-ValidateConfig`. |
| `-ValidateConfig` (switch) | — | Standalone, no-elevation check: resolves, fetches, parses, and statically validates the *entire* config (required fields, enum values, mutual exclusivity). It does not inspect machine state or guarantee that a later real run will succeed. Mutually exclusive with `-Verify`/`-Only`/`-Skip`; `-Download` still works alongside it. Prints `Config is valid.` (exit 0) or every problem found (exit 1). |
| `-Only <tags>` | — | Run only the step(s) matching these tag(s) (comma-separated for more than one), skipping everything else regardless of config. Mutually exclusive with `-Skip`. |
| `-Skip <tags>` | — | Run every step except the one(s) matching these tag(s). Mutually exclusive with `-Only`. |
| `-Quiet` / `-q` (switch) | — | Non-interactive mode: auto-confirms confirmation-gated risky operations, may reboot when configured changes require it, and fails immediately (instead of prompting) if not already elevated. |

### Run transcript and exit status

Real runs write a protected transcript under `C:\ProgramData\win-bootstrap\transcripts\bootstrap-run-*.log`; access is restricted to SYSTEM and local Administrators. `-ValidateConfig` and `-Verify` do not create a persistent transcript. Generated-password and KDNET key handoff output is kept out of the transcript; inspect the one-time console output or the generated handoff file described in the relevant section. This protects bootstrap's own transcript only; external console, host, or process logging may still capture output. Transcript logs from older versions or other locations are not migrated.

The process exits `1` when a real run catches a failed/errored/not-applied step, or when `-Verify` finds a mismatch or verification error; it exits `0` when no such result is reported. Exit status reflects the implemented checks, not a guarantee that every deferred effect is complete.

### Step tags (for `-Only`/`-Skip`)

Matching is case-insensitive.

| Tag | Config key |
|---|---|
| `execution_policy` | [`disable_pwsh_execution_policy`](#disable_pwsh_execution_policy) |
| `root_ca` | [`root_ca`](#root_ca) |
| `recovery_partition` | [`recovery_partition`](#recovery_partition) |
| `vbs` | [`disable_vbs`](#disable_vbs) |
| `onedrive` | [`remove_onedrive`](#remove_onedrive) |
| `teams` | [`remove_teams`](#remove_teams) |
| `outlook` | [`remove_outlook`](#remove_outlook) |
| `defender` | [`defender_exclusions`](#defender_exclusions) |
| `uac` | [`uac_level`](#uac_level) |
| `apps` | [`apps`](#apps) |
| `powershell7` | [`install_powershell7`](#install_powershell7) |
| `windows_terminal` | [`windows_terminal`](#windows_terminal) |
| `ssh` | [`ssh_server`](#ssh_server) |
| `winssh_agent` | [`disable_winssh_agent`](#disable_winssh_agent) |
| `computer_name` | [`computer_name`](#computer_name) |
| `firewall` | [`firewall`](#firewall) |
| `smb` | [`smb_shares`](#smb_shares) |
| `local_users` | [`local_users`](#local_users) |
| `first_login` | [`local_users`](#local_users) |
| `sudo` | [`sudo`](#sudo) |
| `crash_dump` | [`crash_dump`](#crash_dump) |
| `kernel_debugging` | [`kernel_debugging`](#kernel_debugging) |
| `product_key` | [`windows_product_key`](#windows_product_key) |
| `power` | [`power`](#power) |
| `network` | [`network`](#network) |
| `cleanup` | [`delete_bootstrap_user`](#delete_bootstrap_user) |

Two things worth knowing about `-Only`/`-Skip`:

- If `ssh_server.default_shell`/`windows_terminal.default_profile` is set
  to `pwsh7`, `-Only` automatically pulls the `powershell7` tag back in even if you didn't name it — so e.g. `-Only ssh` still results in a working `pwsh7` default shell instead of failing on a machine that doesn't have it yet. Explicitly `-Skip`-ping `powershell7` while one of those is still active is instead treated as a conflict and errors out up front.
- Independently of `-Only`/`-Skip`, the config's documented `disabled: true`
  forms can skip supported sections or entries — see [General](#general) below. It is not a generic option accepted by every section.

## Secrets

Fields that need secret material (certificates, private keys, passwords) consistently support the same set of mutually-exclusive sources, so there's exactly one pattern to learn regardless of which field you're looking at.

### Sources

| Suffix | Source | Notes |
|---|---|---|
| *(bare field)* | Inline value | `key: \|` block scalar for multi-line values (certificates, private keys). |
| `_path` | Local file on the target machine | Read at run time — never embedded in the config. |
| `_url` | Fetched over HTTP(S) | The bearer token is sent only when the URL has the same scheme, host, and port as the selected config URL; authenticated cross-origin redirects are rejected. |
| `_secret_id` | A secret ID in a secrets manager | Today always means **Bitwarden Secrets Manager** — see [Bitwarden Secrets Manager](#bitwarden-secrets-manager) below. |

Exactly one source must be set per field — the script errors out up front if zero or more than one is set for the same field.

### Which fields support which sources

| Config field family | Inline | `_path` | `_url` | `_secret_id` | Also supports |
|---|---|---|---|---|---|
| [`root_ca[].cert`](#root_ca) | `cert` | `cert_path` | `cert_url` | `cert_secret_id` | — |
| [`ssh_server.host_keys[].private_key`](#ssh_server) | `private_key` | `private_key_path` | `private_key_url` | `private_key_secret_id` | — |
| [`local_users[].password`](#local_users) | `password` | `password_path` | `password_url` | `password_secret_id` | `generate: true`, `ask: true` |
| [`kernel_debugging.network.key`](#kernel_debugging) | `key` | `key_path` | `key_url` | `key_secret_id` | `generate: true` |

Worth calling out: `kernel_debugging.network.key` grants remote kernel debugging access, which means full control of the machine — treat it with at least as much care as a root CA private key or an admin password, not as a lesser "just a debug setting".

### SSH public key lists

[`ssh_server.authorized_keys`](#ssh_server) and [`local_users[].ssh_keys`](#local_users) don't fit the single-field 4-source pattern above — each is a *list*, and each item in that list is either:

- a literal string (the public key line itself), or
- a map with a single `key_secret_id` key, resolved from Bitwarden
  Secrets Manager the same way as any other `_secret_id` field.

The two forms can be freely mixed in the same list:

```yaml
authorized_keys:
  - "ssh-ed25519 AAAA... a-literal-key"
  - key_secret_id: 00000000-0000-0000-0000-000000000000
```

Public keys aren't sensitive on their own, so this exists purely for convenience — e.g. keeping one shared/personal access key in Bitwarden and referencing it from every machine's config instead of pasting the same key text everywhere.

### On-machine generation

Where a real secret shouldn't need to be written into the config at all:

- `local_users[].generate: true` / `ask: true` (the latter falls back to
  `generate`'s behavior under `-Quiet`, since there's no console to prompt on) — auto-generates a strong random password, forces a password change at next logon, and reveals the generated value exactly once (console, or a locked-down file next to the script under `-Quiet`). An existing account's password is never touched by a later run — only group membership is kept in sync.
- `kernel_debugging.network.generate: true` — auto-generates the shared
  debug key the same way. An already-configured key is never regenerated/touched by a later run.

### Bitwarden Secrets Manager

Any `_secret_id` field resolves its value from Bitwarden Secrets Manager at run time instead of carrying the real secret inline — this is what makes a config safe to commit to git even with real certificates, keys, or passwords involved, since none of them need to appear in the file at all.

Requirements:

- A top-level `secret_manager: bws` key (the only supported value
  today). Using any `_secret_id` field without it is a config error, caught by [`-ValidateConfig`](#cli-parameters-and-environment-variables) as a structural configuration error. `-ValidateConfig` does not check whether the token is present or usable; the token is required when a run resolves the referenced secret, including `-Verify`.
- `$env:BWS_ACCESS_TOKEN` — a scoped, independently revocable Bitwarden
  Secrets Manager *machine* access token — set before running. Only ever read from the environment, never accepted as a parameter or passed in child-process arguments. Avoid typing its literal value into a command that your shell records in history.

The `bws` CLI itself is installed automatically on first use — the latest `bws-v*` release is resolved from its official GitHub releases (checksum-verified against Bitwarden's own published checksums before ever being run), installed permanently to `%ProgramData%\bws\bws.exe`, and added to the machine `PATH` so it's also usable as a normal command afterward. This install step never happens under `-Verify` (it would be a real machine mutation) — if `bws.exe` isn't already present, `-Verify` reports an `ERROR` for that step instead, asking you to run for real first. Secrets are fetched fresh on every run (never cached to disk), with an in-memory-only cache so the same secret ID referenced twice in one run doesn't trigger two `bws` calls.

## Configuration File

### General

- **Format**: a restricted subset of YAML — 2-space indentation (no
  tabs), `#` comments, `key: value` scalars (`true`/`false`/`yes`/`no` become booleans, quotes are stripped), nested maps, `- item` lists (of scalars or of maps), `key: [a, b]` inline flow lists, and `key: |` block scalars for multi-line text (used for inline certificates/keys). Flow mappings are not supported: write a map as indented `key: value` lines. Anchors/aliases and multi-document files are also **not** supported.
- **Source resolution**: see [CLI Parameters and Environment Variables](#cli-parameters-and-environment-variables)
  above.
- **A fully-commented, complete example covering every section below**
  lives at [`win-bootstrap.config.example.yaml`](../win-bootstrap/win-bootstrap.config.example.yaml) — copy it, customize it, and either name your copy `win-bootstrap.config.yaml` next to the script, pass its path via `-ConfigPath`, or host it and pass its raw URL via `-ConfigUrl`.
- **Secrets**: fields that need secret material (certificates, private
  keys, passwords) consistently support the same inline/`_path`/`_url`/ `_secret_id` sources, plus on-machine generation for some fields — see the dedicated [Secrets](#secrets) section for the full list of which fields support what, and how Bitwarden Secrets Manager fits in.
- **The `disabled: true` convention**: supported sections can be switched
  off without deleting their content — useful while iterating on a config.

  - Map sections ([`firewall`](#firewall), [`recovery_partition`](#recovery_partition),
  [`power`](#power), [`network`](#network)) take it directly inside the map. These are the only generic map-section `disabled` forms.
  - List sections ([`root_ca`](#root_ca), [`defender_exclusions`](#defender_exclusions),
  [`smb_shares`](#smb_shares), [`local_users`](#local_users), [`apps`](#apps)) can be disabled as a whole by using this block-map form instead of a bare list:

    ```yaml
    <key>:
      disabled: true
      items:
        - ...
    ```

Both shapes are accepted. For `apps`, the whole-list flag disables the main installation step, not first-login scheduling; see the limitations under [`local_users`](#local_users). Per-entry `disabled: true` is supported for `defender_exclusions`, `smb_shares`, `local_users`, and `apps`; it is not supported for `root_ca` entries.
  - [`windows_terminal`](#windows_terminal), [`ssh_server`](#ssh_server), and
  [`kernel_debugging`](#kernel_debugging) use their own `enable: false`; [`root_ca`](#root_ca) entries are individually skipped via `install: false`.

### `disable_pwsh_execution_policy`

```yaml
disable_pwsh_execution_policy: true
```

A plain boolean. `true` sets `LocalMachine` execution policy to `Unrestricted` (a no-op, logged, if enforced by Group Policy instead). Omit/`false` leaves the current policy alone.

### `root_ca`

```yaml
root_ca:
  - name: my-corporate-root-ca
    install: true
    cert: |
      -----BEGIN CERTIFICATE-----
      ...
      -----END CERTIFICATE-----
```

A list — install any number of root CA certificates into `Cert:\LocalMachine\Root`.

| Field | Required/Optional | Description |
|---|---|---|
| `name` | Required | Friendly name, used in step and status messages. |
| `install` | Required | `true` to install this entry; `false` skips it (kept in the file for later). |
| `cert` | Exactly one of `cert`/`cert_path`/`cert_url`/`cert_secret_id` required | Inline PEM certificate text (`key: \|` block scalar). |
| `cert_path` | — | Local file path to the certificate. |
| `cert_url` | — | URL to fetch the certificate from. |
| `cert_secret_id` | — | Bitwarden Secrets Manager secret ID (needs `secret_manager: bws`, see [General](#general)). |

### `recovery_partition`

```yaml
recovery_partition:
  delete: true
  extend_system_drive: true
```

A map. Deletes the Windows Recovery partition (destructive — asks for confirmation unless `-Quiet`) and optionally extends the system drive into the freed space.

| Field | Required/Optional | Description |
|---|---|---|
| `delete` | Required (`true` to act) | Deletes the recovery partition if present. |
| `extend_system_drive` | Optional, default `false` | Grows the system drive into the freed space (only works if the recovery partition was directly adjacent to it). |
| `disabled` | Optional, default `false` | Skip this whole section (see [General](#general)). |

### `disable_vbs`

```yaml
disable_vbs: true
```

A plain boolean. Disables Virtualization-Based Security / Core Isolation / Memory Integrity — mainly useful when the target machine is itself a VM. Requires a reboot to fully take effect.

### `remove_onedrive`

```yaml
remove_onedrive: true
```

A plain boolean. Stops OneDrive and runs its own uninstaller for the current account, then sets the machine-wide `HKLM:\SOFTWARE\Policies\ Microsoft\Windows\OneDrive\DisableFileSyncNGSC` registry policy (the equivalent of "Prevent the usage of OneDrive for file storage") so it doesn't get silently reprovisioned for a `local_users` account created afterward - uninstalling only affects the account that ran this step, not future ones, unless this policy is also set. A no-op (for the uninstall half) if OneDrive's uninstaller isn't found (assumed not installed) - the policy is still set either way.

### `remove_teams`

```yaml
remove_teams: true
```

A plain boolean. Removes Microsoft Teams, whichever form is present:

- "New" Teams' AppX **provisioned** package (prevents new user profiles
  from getting it) and any **per-user installed** AppX package.
- Classic Teams' "Teams Machine-Wide Installer" (the deprecated,
  pre-2023 Win32 build).

A no-op if none of the above are found (assumed not installed).

### `remove_outlook`

```yaml
remove_outlook: true
```

A plain boolean. Removes "new" Outlook for Windows (`Microsoft.OutlookForWindows`): the AppX **provisioned** package (prevents new user profiles from getting it) and any **per-user installed** AppX package. Does not touch classic desktop Outlook (Office) - that's a separate product. A no-op if neither is found (assumed not installed).

### `defender_exclusions`

```yaml
defender_exclusions:
  - path: C:\Devel
    create: true
```

A list — any number of paths to exclude from Windows Defender.

| Field | Required/Optional | Description |
|---|---|---|
| `path` | Required | Path to exclude. |
| `create` | Optional, default `false` | If `path` doesn't exist: `true` creates it first; otherwise this entry is skipped with a warning (nothing created, nothing excluded). |
| `disabled` | Optional, default `false` | Skip just this entry (see [General](#general)). |

### `uac_level`

```yaml
uac_level: default
```

Sets User Account Control to one of Windows' own defined levels. Not configured = step is skipped, UAC is left untouched.

| Value | `EnableLUA` | `ConsentPromptBehaviorAdmin` | `PromptOnSecureDesktop` | Matches |
|---|---|---|---|---|
| `off` | `0` | *(unmanaged)* | *(unmanaged)* | Fully disables UAC (the old "Turn User Account Control on or off" checkbox) - no split token, no elevation prompts at all. **Requires a reboot** to fully take effect. |
| `never_notify` | `1` | `0` | `0` | Control Panel slider: "Never notify". |
| `default` | `1` | `5` | `1` | Control Panel slider: "Notify only when apps try to make changes" - Windows' own out-of-box default. |
| `always_notify` | `1` | `2` | `1` | Control Panel slider: "Always notify". |

The rarely-used "notify without dimming the desktop" slider position isn't exposed as a separate value - it's cosmetically different from `default` only.

Switching to or away from `off` only takes effect after a reboot; `-Verify` reflects the configured registry state, not live in-session UAC behavior.

### `apps`

```yaml
apps:
  - id: Google.Chrome
    scope: machine
  - id: Microsoft.VisualStudioCode
    scope: user
```

A list — apps to install via `winget`.

| Field | Required/Optional | Description |
|---|---|---|
| `id` | Required | The winget package ID. |
| `scope` | Optional, default `machine` | `machine` or `user`. |
| `platforms` | Optional | Restrict this entry to specific architectures (`[arm64]`, `[x64]`); omit to let winget pick automatically. |
| `architecture` | Optional | Pin a specific build; falls back to automatic selection if unsupported. |
| `installer_type` | Optional | Force a specific winget installer type (e.g. `wix` for a native MSI build). winget won't switch installer types on an already-installed package — uninstall first if changing this on a machine that already has the app. |
| `disabled` | Optional, default `false` | Skip just this entry (see [General](#general)). |
| `desktop_shortcut` | Optional, default `false` | Also copy the app's Start Menu shortcut to a desktop — see below. |

PowerShell 7 and Windows Terminal are **not** listed here — see [`install_powershell7`](#install_powershell7) and [`windows_terminal`](#windows_terminal), they're special-cased.

**`scope: machine`**: some installers (confirmed for `Ghisler.TotalCommander`'s classic EXE installer) drop their Start Menu shortcut(s) under the *current* user's own per-user Start Menu folder even for a machine-wide install, regardless of what winget's `--scope machine` asked for — `scope` only controls how the installer is invoked, not where that installer decides to put its shortcuts. To compensate, after every `scope: machine` install this diffs the bootstrap account's Start Menu `Programs` folder before/after, and copies any new item into the shared all-users Start Menu (`C:\ProgramData\Microsoft\Windows\Start Menu\Programs`) so other accounts can see it too — never overwriting an existing shared shortcut of the same name.

**`scope: user`** installs into whichever account is currently running this script:

- If [`delete_bootstrap_user`](#delete_bootstrap_user) is `true`, that
  account is about to be deleted, so any `scope: user` entry is skipped outright (not installed then lost) with a `SKIPPED` reason explaining why.
- Independently of that, each [`local_users`](#local_users) account
  gets its own copy of eligible `scope: user` apps installed automatically the next time *that account* actually logs in — see [`local_users`](#local_users)'s `complete_setup_on_first_login`. This is the only reliable way to get `scope: user` software onto an account other than whoever ran bootstrap, and needs no second manual bootstrap run.

Deferred first-login installs do not honor all app options. See the `complete_setup_on_first_login` limitations under [`local_users`](#local_users) before relying on architecture filters or a particular installer type.

**`desktop_shortcut: true`** picks a single shortcut for the app and copies it to a desktop too — which desktop depends on `scope`:

- `scope: machine` → the shared all-users desktop
  (`C:\Users\Public\Desktop`), copied right after the main install, same timing as the shared Start Menu copy.
- `scope: user` → that specific account's own desktop, copied at that
  account's own first-login setup (same timing as the `scope: user` install itself).

Picking *which* shortcut, in priority order (confirmed live for `Ghisler.TotalCommander`, whose classic installer creates a Start Menu *subfolder* with 3 shortcuts — the real one plus Help and Uninstall/Repair, not a single flat `.lnk`):
1. If the installer created its own shortcut directly on a desktop
  (many classic installers have a "create desktop icon" option, on by default) — that one is used as-is. It's always a single, correctly-iconed shortcut, more reliable than guessing from the Start Menu.
2. Otherwise, if the new Start Menu item is a single flat `.lnk` — that
  one is used (this is what most winget packages do, e.g. Chrome, Git, 7-Zip).
3. Otherwise, if the new Start Menu item is a *folder* — its contents
  are filtered to drop obvious non-launcher entries (`uninstall`, `help`, `readme`, `license`, `changelog`, `manual`, `documentation`, `website`, `update`, `repair`, case-insensitive substring match on the filename). If exactly one shortcut survives, it's used; if 0 or 2+ remain (ambiguous), nothing is copied and a warning is printed — add the shortcut by hand in that case, no guessing.

Taskbar pinning is intentionally not offered: Windows 11 blocks the script-based ways to do that, but pinning a desktop shortcut by hand (right-click → *Pin to taskbar*) still works fine once it exists.

### `install_powershell7`

```yaml
install_powershell7: true
```

A boolean, but with implicit dependency pull-in:

- **Omitted**: installed only if [`windows_terminal.default_profile`](#windows_terminal)
  or [`ssh_server.default_shell`](#ssh_server) is set to `pwsh7`.
- **`true`**: always installed.
- **`false`**: never installed — if a dependent still needs it, the
  script errors out immediately (before any step runs), rather than silently overriding your explicit `false`.

Always installs the native MSI build (winget installer type `wix`), not the default MSIX/Store package, since MSIX doesn't work as an OpenSSH default shell.

### `windows_terminal`

```yaml
windows_terminal:
  enable: true
  default_profile: pwsh7
  desktop_shortcut: true
```

A map.

| Field | Required/Optional | Description |
|---|---|---|
| `enable` | Required (`true` to act) | Installs Windows Terminal via winget if missing. `false`/omitted only means "leave it alone" — never uninstalls an existing copy. |
| `default_profile` | Optional | `cmd` \| `pwsh5` \| `pwsh7`. Only takes effect once Windows Terminal has run at least once (needs its `settings.json` to exist); `pwsh7` relies on [`install_powershell7`](#install_powershell7). |
| `desktop_shortcut` | Optional, default `false` | Adds a shortcut to the shared all-users desktop that launches Windows Terminal. |

Windows Terminal is an MSIX/Store package, so it never drops a physical `.lnk` file anywhere the way classic installers do — the `apps` [`desktop_shortcut`](#apps) Start Menu diff/copy doesn't apply to it. `desktop_shortcut` here instead points a shortcut at `shell:AppsFolder\Microsoft.WindowsTerminal_8wekyb3d8bbwe!App`, the officially supported way to shortcut a UWP app by its stable AppUserModelID. Setting this to `true` on a machine where Terminal is already installed still creates the shortcut on the next run — verified independently of whether the package itself needed installing.

### `ssh_server`

```yaml
ssh_server:
  enable: true
  default_shell: pwsh7
  host_keys:
    - type: ed25519
      private_key: |
        -----BEGIN OPENSSH PRIVATE KEY-----
        ...
        -----END OPENSSH PRIVATE KEY-----
  authorized_keys:
    - "ssh-ed25519 AAAA... your-comment"
```

A map. Enables OpenSSH Server.

| Field | Required/Optional | Description |
|---|---|---|
| `enable` | Required (`true` to act) | Installs and starts `sshd`, opens the firewall rule, and fixes the SFTP subsystem path. |
| `default_shell` | Optional | `cmd` \| `pwsh5` \| `pwsh7` — shell used for new SSH sessions. Omit to leave Windows' own `cmd.exe` default. An unavailable/misspelled shell fails this step with a clear error. `pwsh7` relies on [`install_powershell7`](#install_powershell7). |
| `host_keys` | Optional | List of pinned host keys — see below. Without it, `sshd` auto-generates its own key(s), silently changing the machine's SSH identity/fingerprint on every reinstall. |
| `authorized_keys` | Optional | List of public key lines for key-based login — each item is a literal `"ssh-... comment"` string or a block map with `key_secret_id` (see [SSH public key lists](#ssh-public-key-lists)). Without any, the server still runs but only accepts password authentication. |

`host_keys` entries:

| Field | Required/Optional | Description |
|---|---|---|
| `type` | Required | `rsa` \| `ecdsa` \| `ed25519` (`ed25519` alone is enough for identity purposes). |
| `private_key` | Exactly one of `private_key`/`private_key_path`/`private_key_url`/`private_key_secret_id` required | Inline OpenSSH private key. |
| `private_key_path` | — | Local file path. |
| `private_key_url` | — | Fetched URL. |
| `private_key_secret_id` | — | Bitwarden Secrets Manager secret ID (needs `secret_manager: bws`, see [General](#general)). |

The matching public key is always derived automatically — there's no field to supply it separately.

### `disable_winssh_agent`

```yaml
disable_winssh_agent: true
```

A plain boolean. Stops and disables the Windows `ssh-agent` service so a third-party agent (e.g. Bitwarden's built-in one) can take over its named pipe. Only has an effect if such a provider is actually detected as installed.

### `computer_name`

```yaml
computer_name: my-computer
```

A plain string. Renames the computer (takes effect after reboot). Omit to leave the current name unchanged.

### `firewall`

```yaml
firewall:
  profile: private
  ping: allow_lan
  smb: allow_lan
```

A map. Three independent, optional keys:

| Field | Required/Optional | Description |
|---|---|---|
| `profile` | Optional | `public` \| `private` only (Windows assigns `Domain` automatically on domain-joined machines; a script can't force it). |
| `ping` | Optional | `block` \| `allow_lan` \| `allow_all` — a dedicated inbound ICMPv4 Echo Request rule. |
| `smb` | Optional | Same `block` \| `allow_lan` \| `allow_all` shape, for [`smb_shares`](#smb_shares) below. |
| `disabled` | Optional, default `false` | Skip all three above at once (see [General](#general)). |

`profile` and `ping`/`smb` don't depend on each other — e.g. `profile: public` + `ping: allow_lan` is valid, the rule just has no effect while the live category stays `Public`.

### `smb_shares`

```yaml
smb_shares:
  - name: Shared
    path: C:\Shared
    create: true
    access: read
```

A list — SMB file shares.

| Field | Required/Optional | Description |
|---|---|---|
| `name` | Required | Share name. |
| `path` | Required | Local path to share. |
| `create` | Optional, default `false` | If `path` doesn't exist: `true` creates it first; otherwise this entry is skipped with a warning. |
| `access` | Optional, default `read` | `read` \| `change` \| `full`, granted to `Everyone` at both the SMB share level and a matching NTFS ACE. Other existing share/NTFS permissions are preserved and can still affect effective access; this is not a complete ACL reset. |
| `disabled` | Optional, default `false` | Skip just this entry (see [General](#general)). |

Network access also requires suitable firewall rules; use [`firewall.smb`](#firewall) to manage this script's SMB rules.

### `local_users`

```yaml
local_users:
  - name: contractor
    generate: true
    admin: false
    ssh_keys: default
```

A list — create local Windows accounts.

| Field | Required/Optional | Description |
|---|---|---|
| `name` | Required | Account name. |
| `password` / `password_path` / `password_url` / `password_secret_id` / `generate` / `ask` | Exactly one required | Password source — see below. |
| `admin` | Optional, default `false` | Local Administrators group membership — reconciled (added/removed) on every run. |
| `password_never_expires` | Optional, default `false` | Only applied when the account is first created. |
| `initialize_profile` | Optional, default `true` | Force-creates the account's real Windows profile (`C:\Users\<name>`, registry hive) right after creation, without needing an actual interactive logon — see below. Set `false` to opt a given account out. |
| `complete_setup_on_first_login` | Optional, default `true` | Schedules this account's `scope: user` [`apps`](#apps) to install automatically at its next real interactive logon — see below. Set `false` to opt a given account out. |
| `ssh_keys` | Optional | `default` (reuses [`ssh_server.authorized_keys`](#ssh_server)) or an explicit list of `"ssh-... comment"` strings / block maps with `key_secret_id` (see [SSH public key lists](#ssh-public-key-lists)). Admin accounts share the machine-wide `administrators_authorized_keys` file; non-admin accounts get their own per-user file, which needs the account's real profile directory to exist first — normally handled automatically by `initialize_profile` above. |
| `disabled` | Optional, default `false` | Skip just this entry (see [General](#general)). |

Password sources (exactly one):

| Source | Behavior |
|---|---|
| `password` | Inline plaintext password. |
| `password_path` | Local file containing the password. |
| `password_url` | Fetched URL; the config token is used only for the selected config URL's exact origin. |
| `password_secret_id` | Bitwarden Secrets Manager secret ID (needs `secret_manager: bws`, see [General](#general)). |
| `generate: true` | Auto-generates a strong random password. |
| `ask: true` | Prompts for the password twice, interactively. Falls back to `generate`'s behavior under `-Quiet` (no console to prompt on). |

You can avoid storing an inline password: `password_path`, `password_url`, and `password_secret_id` resolve it outside the config, while `generate` and `ask` obtain it at run time (`ask` falls back to generation under `-Quiet`). Only generated passwords force a change at next logon. The generated value is revealed exactly once (console, or a locked-down file next to the script under `-Quiet`). If an account with this name already exists, its password is **never** touched by a later run — only group membership is kept in sync.

**`initialize_profile`**: Windows only creates a local account's real profile (folder, `NTUSER.DAT` registry hive, `ProfileList` registry entry) at that account's first interactive logon. This forces that to happen right away, via a one-shot Scheduled Task registered with the account's own credentials — Task Scheduler performs the same profile-loading a real logon does before running the task's (trivial, no-op) action, so no actual desktop session is needed. The account is first granted the "Log on as a batch job" right (via `secedit.exe`, confirmed necessary live — Task Scheduler does *not* auto-grant it), otherwise the task registers successfully but silently never actually runs. This only works right after the account is *freshly created in the same run*: if the account already existed before this run, its current password isn't known to the script (passwords are never touched for pre-existing accounts — see above), so this step can't do anything for it and just warns instead. In that case, log on manually once and re-run bootstrap.

Account creation and profile initialization both run very early in a bootstrap run (right after config parsing), deliberately - so the account already exists, with a real profile, well before later steps (e.g. `apps`) run. Configuring `ssh_keys` for the same accounts still happens much later (after OpenSSH Server is installed), since that's the earliest point a non-admin account's per-user `authorized_keys` file can be written.

**`complete_setup_on_first_login`**: a batch logon (used by `initialize_profile` above) never starts a real shell session, so it can create the account's profile files but can't do what an actual interactive logon does — this is also why the "Hi, we are preparing things for you" first-logon experience still appears the first time someone really signs into a bootstrap-created account, no matter what bootstrap does beforehand; that part is inherent to Windows and isn't something bootstrap can (or needs to) prevent. `winget --scope user` installs are the same story: they only ever succeed in the target account's own real interactive session. Rather than trying to fake one, this registers a Scheduled Task that fires at that specific account's *next actual interactive logon* (`-AtLogOn`, `LogonType Interactive`), installs that account's eligible `scope: user` [`apps`](#apps) for real, logs the result to `C:\ProgramData\win-bootstrap\first-login-<name>.log`, then deletes itself only after a successful installation. If an install fails, the task and helper script remain, no completion marker is written, and the helper retries during that run and at a later interactive logon. For this first-login helper only, each app is passed as just its `id` and `desktop_shortcut`; `platforms`, `architecture`, and `installer_type` are not forwarded, so those filters/options are not applied by the deferred install. The whole-list `apps.disabled` flag also only disables the main `apps` step; use per-entry `disabled: true`, `complete_setup_on_first_login: false`, or `-Skip first_login` when the first-login scheduling itself must be excluded. These settings do not remove a task that was already scheduled. Re-running bootstrap while this task is still pending leaves it alone rather than registering a duplicate. Skipped entirely if the account has no `scope: user` apps configured.

### `sudo`

```yaml
sudo:
  mode: force_new_window
```

A map. Configures Windows 11 24H2+'s built-in `sudo` command.

| Field | Required/Optional | Description |
|---|---|---|
| `mode` | Required (to act) | `disabled` \| `force_new_window` \| `disable_input` \| `normal`. |

| Mode | Behavior |
|---|---|
| `disabled` | `sudo` refuses to run (Windows' own default). |
| `force_new_window` | Runs elevated in a new window (like `runas`) — Microsoft's own recommended default if enabling this at all. |
| `disable_input` | Runs attached to the current console, but the elevated process can't receive input from it. |
| `normal` | Full input/output in the current console — most convenient, but carries the most risk (an unelevated process could in principle drive the elevated session). |

Omitting this section leaves whatever's currently configured alone; `mode: disabled` actively turns it off.

### `crash_dump`

```yaml
crash_dump:
  type: automatic
```

A map. Configures what kind of memory dump Windows writes on a crash (BSOD). Omit the whole section to leave Windows' own default untouched.

| Field | Required/Optional | Description |
|---|---|---|
| `type` | Required (to act) | `none` \| `complete` \| `kernel` \| `small` \| `automatic` \| `active`. |
| `dump_file` | Optional | Dump file path. Omit for Windows' own default. |
| `overwrite` | Optional | Whether an existing dump file is overwritten. Omit for Windows' own default (`true`). |

### `kernel_debugging`

```yaml
kernel_debugging:
  enable: true
  target: dedicated
  transport: serial
  serial:
    port: COM1
    baud_rate: 115200
```

A map. Enables Windows kernel debugging (the `bcdedit /debug` + `/dbgsettings` combo normally used to attach WinDbg). A reboot is required for changes here to take effect.

| Field | Required/Optional | Description |
|---|---|---|
| `enable` | Required (`true` to act) | Omit/`false` leaves BCD completely untouched. |
| `target` | Optional, default `current` | `current` enables debug on today's default boot entry, in place. `dedicated` finds or creates one script-managed copy of it (never duplicated across reruns) and enables debug there instead, leaving the original entry untouched. |
| `default_profile` | Optional, default `current` | Only consulted when `target: dedicated` (harmless no-op otherwise). `current` keeps booting into the original entry (the dedicated debug entry is only reachable via the boot menu); `dedicated` switches the boot default to it. |
| `legacy_boot_menu` | Optional, default `false` | `true` switches every boot loader entry's `bootmenupolicy` to `Legacy` (classic text-based boot menu, also re-enables the F8 Advanced Options menu) — applied to *all* entries at once, not just the one used for kernel debugging, since Windows only supports this per-entry, not as a single global switch. Mainly useful when `target: dedicated` needs a reliable way to pick between boot entries over a serial console/remote KVM where the modern graphical boot menu doesn't render well. Omit/`false` leaves the current policy alone. |
| `transport` | Required (to act) | `serial` \| `network` — which sub-block below is read. |
| `serial.port` | Optional, default `COM1` | Serial port. |
| `serial.baud_rate` | Optional, default `115200` | Baud rate. |
| `network.host_ip` | Required for `transport: network` | Debug host IP. |
| `network.port` | Required for `transport: network` | Debug host port. |
| `network.key` / `network.key_path` / `network.key_url` / `network.key_secret_id` / `network.generate` | Exactly one required for `transport: network` | Explicit shared secret (inline, local file, URL, or Bitwarden Secrets Manager secret ID — see [Secrets](#secrets)), or `generate: true` to auto-generate one (revealed exactly once, same convention as `local_users` generated passwords). An already-configured key is never regenerated/touched by a later run. |
| `network.bus_params` | Optional | PCI location of the debug NIC as `bus.device.function` (e.g. `2.0.0`) — `bcdedit /set "{dbgsettings}" busparams <value>`. Only needed when Windows can't auto-select the right NIC for KDNET (e.g. multiple NICs). Carries no secret, so unlike the key it's re-applied (and corrected) on every run if it drifts from the configured value. |

Note: `/dbgsettings` (the transport) is a single **global** BCD object shared by any boot entry with debug on, not per-entry.

### `windows_product_key`

```yaml
windows_product_key: XXXXX-XXXXX-XXXXX-XXXXX-XXXXX
# windows_product_key_path: C:\path\to\key.txt
# windows_product_key_url: https://example.com/key.txt
# windows_product_key_secret_id: 00000000-0000-0000-0000-000000000000
```

Exactly one of the 4 fields above (inline value, local file, URL, or Bitwarden Secrets Manager secret ID - see [Secrets](#secrets)). Installs the key and requests online activation via the same `SoftwareLicensingService`/`SoftwareLicensingProduct` WMI methods `slmgr.vbs` itself uses internally.

**Important limitation:** Windows never exposes a fully-installed product key back out, for security reasons - only the last 5 characters (`PartialProductKey`). So verification is necessarily a **suffix comparison**, not a full-key comparison: if the currently installed key's last 5 characters match the configured key's last 5 characters *and* the machine is already licensed, the step reports OK and touches nothing. This means an already-activated OEM/pre-installed license is left alone rather than blindly overwritten, as long as its last 5 characters happen to match what's configured (in practice, different keys essentially never share a last-5-character suffix).

If the key installs successfully but activation fails (most commonly: no network/KMS reachability at bootstrap time), the failure is logged as a warning, not a hard error - the key stays installed, and re-running bootstrap later (once online) retries just the activation half.

### `power`

```yaml
power:
  sleep_after:
    on_power: never
    on_battery: never
  display_off_after:
    on_power: 15
```

A map. Sets how long until the machine sleeps and/or the display turns off, via the same `powercfg /change` mechanism as Windows' own Settings app, applied to whichever power plan is currently active.

| Field | Required/Optional | Description |
|---|---|---|
| `sleep_after.on_power` | Optional | `never`, or a whole number of minutes while plugged in (AC power). |
| `sleep_after.on_battery` | Optional | Same, while running on battery (DC power). |
| `display_off_after.on_power` | Optional | `never`, or a whole number of minutes while plugged in. |
| `display_off_after.on_battery` | Optional | Same, while running on battery. |
| `disabled` | Optional, default `false` | Skip this whole section (see [General](#general)). |

All four fields are independent - set only the ones you care about, the rest are left exactly as they already are. There's no `on_battery`-only machine requirement: setting just `sleep_after.on_power` on a desktop/VM with no battery is perfectly normal, the `on_battery` value simply never applies.

**Machines/VMs without sleep support**: many virtualized machines (confirmed for QEMU/KVM guests) have virtual firmware that doesn't expose any ACPI sleep state at all (`powercfg /a` reports every S-state as unavailable) - Windows then hides the "Put my device to sleep" control from Settings entirely, showing only the display timeout, which is exactly the symptom that motivated this section. Setting `sleep_after.on_power`/`sleep_after.on_battery` here still works without error on such a machine - `powercfg /change` only ever writes the value into the power scheme, so it's a harmless no-op if the underlying sleep state was never reachable in the first place. No detection or special-casing needed either way.

### `network`

```yaml
network:
  interface: Ethernet          # optional - see "Adapter selection" below
  ip: 192.168.1.50/24          # optional, CIDR (address/prefix) notation
  gateway: 192.168.1.1         # optional, requires 'ip'
  dns:
    - 192.168.1.1
    - 8.8.8.8
  mac_address: 00:11:22:33:44:55   # optional
  apply_after_reboot: true     # default true (safe) - see below
  # disabled: true
```

A map. Configures a static IP address (with subnet and default gateway), DNS servers, and/or a fixed MAC address. `ip`/`dns`/`mac_address` are independent of each other - set only the ones you need (e.g. `mac_address` alone, to pin a DHCP reservation, with no static IP at all). At least one of `ip`/`dns`/`mac_address` must be set, otherwise this step is skipped. `gateway` only makes sense together with `ip` (it's applied as part of the same static IP assignment) and is rejected by config validation on its own.

| Field | Required/Optional | Description |
|---|---|---|
| `interface` | Optional | Adapter name (`InterfaceAlias`). Auto-detected via the current default route if omitted - see below. |
| `ip` | Optional | Static IPv4 address in `address/prefix` (CIDR) form, e.g. `192.168.1.50/24`. |
| `gateway` | Optional | Default gateway IPv4 address. Requires `ip`. |
| `dns` | Optional | List of DNS server IPv4 addresses. |
| `mac_address` | Optional | `XX:XX:XX:XX:XX:XX` address to assign to the adapter, if its driver supports it (see below). |
| `apply_after_reboot` | Optional, default `true` | Governs `ip`/`gateway`/`dns` only - `true` schedules the change for the next reboot; `false` applies it immediately. See below. `mac_address` always requires a reboot regardless of this setting (see below). |
| `disabled` | Optional, default `false` | Skip this whole section (see [General](#general)). |

**Adapter selection**: without `interface`, the adapter carrying the current default IPv4 route is used (`Get-NetRoute -DestinationPrefix 0.0.0.0/0`) - reliable on the single-NIC VMs/servers this is meant for. Re-resolved every time this step runs (including at boot, for the deferred path below), not cached, since the adapter's state can differ after a reboot.

**`mac_address` never applies live** - it's written straight to the adapter driver's own registry key (the same key `Set-NetAdapterAdvancedProperty` itself writes to), *without* calling that cmdlet - it also forces the driver to reset and reload immediately, which is unnecessary risk when a plain registry write has no live effect at all: the driver only reads it back the next time it loads, i.e. the next real reboot. This just flags that a reboot is needed, same as [`recovery_partition`](#recovery_partition)'s delete, [`kernel_debugging`](#kernel_debugging), and `computer_name` changes - see [Reboot handling](#reboot-handling) for when that reboot actually happens. Skipped (with a warning, everything else still applies) if the adapter doesn't expose the `NetworkAddress` override in the first place (`Get-NetAdapterAdvancedProperty -RegistryKeyword NetworkAddress`).

**Why `ip`/`gateway`/`dns` can be risky**: changing the IP address of the adapter this script itself is connected over (typically true when running bootstrap over SSH/RDP) can drop that connection immediately, possibly for good if the new settings are wrong. Two modes handle this:

- **`apply_after_reboot: true` (default, safe)**: registers a
  `-AtStartup` scheduled task (SYSTEM context) that applies the configured settings about 30 seconds after the next boot, logging to `C:\ProgramData\win-bootstrap\network-config.log`. Unlike the one-shot, self-deleting tasks used elsewhere in this script (e.g. [`delete_bootstrap_user`](#delete_bootstrap_user)'s profile cleanup), this task is **re-registered on every bootstrap run** (not left alone) and **stays registered**, reapplying the same settings on every subsequent boot too - so a config change before the next reboot is picked up instead of a stale task applying outdated values, and any later manual drift on the machine gets corrected back on the next reboot too. Re-applying already-correct settings is a safe no-op (old addresses/routes are removed before the new ones are added). Skipped entirely if the live configuration already matches.
- **`apply_after_reboot: false` (applies immediately)**: confirmation-gated
  the same way as [`recovery_partition`](#recovery_partition)'s delete - prompts for a literal `YES` unless `-Quiet` - warning explicitly that the current session may drop. Like [`delete_bootstrap_user`](#delete_bootstrap_user), the actual change is **deferred to the very end of the run** (after the final summary, and after even the bootstrap user deletion), so every other step's result is visible first.

### `delete_bootstrap_user`

```yaml
delete_bootstrap_user: true
```

A plain boolean. `true` permanently deletes the local user account that ran this script (`$env:USERNAME`) — useful when bootstrap was run under a temporary/provisioning account that shouldn't stick around once a real admin account exists. Omit/`false` leaves it alone.

This is deliberately a **late cleanup** step in a real run, so every other step's result is visible before it acts. Network application and reboot handling can still follow it:

- **Hard safety gate, no override**: refuses outright if the account
  being deleted is the only enabled local Administrator left on the machine — checked against live machine state, not just whether the config *intends* to create a replacement admin. Configure at least one other admin account (e.g. via [`local_users`](#local_users)) first.
- **Hard safety gate, no override**: also refuses outright if the
  account being deleted is itself one of this same config's [`local_users`](#local_users) entries. This setting means "delete whoever is running bootstrap right now," which is only correct for the original, disposable provisioning account — if `delete_bootstrap_user: true` is left in the config and someone later re-runs bootstrap while already logged in as one of the real target accounts, this gate stops it from deleting that account instead. Remove `delete_bootstrap_user: true` from the config once the original provisioning account is gone.
- **Confirmation-gated** the same way as [`recovery_partition`](#recovery_partition)'s
  delete — prompts for a literal `YES` unless `-Quiet`.
- **Deferred to the late cleanup point**, after the final summary has
  printed and before the final completion message — deleting the account currently running the script (often over an active SSH session as that account) can end the session before the rest of the run finishes, so every other step's result is visible first. Network application and reboot handling may still run afterward. If the deletion itself fails (e.g. the account still has an active logon session), the script warns and recommends a reboot, then re-running after confirming the account is no longer logged in.
- **Warns about `apps` entries with `scope: user`**: those install into
  whichever account is running the script — i.e. the account this setting is about to delete — so the `apps` step already skips them outright (see [`apps`](#apps)) rather than installing then losing them. This is mentioned again here, at the point of deletion, since it's easy to miss earlier in a long run's output.
- **Full profile cleanup is deferred to the next reboot**: `Remove-LocalUser`
  only removes the account itself, not its `C:\Users\<name>` folder — left alone, a later run that creates a new account with the same name can end up reusing that same leftover folder, which can confuse the before/after checks [`apps`](#apps)'s `desktop_shortcut`/Start Menu copying rely on. This schedules a one-time `-AtStartup` task (SYSTEM context) that fully removes the old profile via `Win32_UserProfile` once its registry hive is no longer loaded — which it still is for the rest of this run, hence waiting for the next reboot (bootstrap already routinely ends with "reboot required" for unrelated steps). If the profile is still locked at that point, the task keeps retrying on every subsequent boot until it succeeds.
- Has no `-Verify` side effect beyond reporting whether the account
  still exists.

## Reboot handling

Several steps ([`recovery_partition`](#recovery_partition)'s delete, [`kernel_debugging`](#kernel_debugging), `computer_name` changes, and [`network`](#network)'s `mac_address`) only fully take effect after a reboot. Rather than each having its own separate reboot logic, they all just flag it, and once every other step has finished and the final summary has printed, this runs **once**, right at the very end (after even [`delete_bootstrap_user`](#delete_bootstrap_user)'s deletion). Note that [`network`](#network)'s `ip`/`gateway`/`dns` handle their own reboot timing separately via `apply_after_reboot`, rather than through this mechanism:

- **Interactively**: prompts the same way as
  [`recovery_partition`](#recovery_partition)'s delete - type `YES` to reboot now, anything else to leave it for later (the machine stays in a valid, working state either way; it just won't have every configured change applied until it's rebooted).
- **`-Quiet`**: reboots automatically, no prompt - an unattended run
  shouldn't finish half-applied, waiting indefinitely on a manual reboot nobody's there to trigger.

Rebooting can end the current session immediately (e.g. SSH/RDP), same as the other confirmation-gated destructive actions in this script.

## Usage Scenarios

Two common ways to run this script — the same config keys end up meaning something different depending on which one applies, which is easy to miss when reading the field-by-field reference above in isolation.

### Bootstrapping under an account you're keeping

You're already logged in (locally, over SSH, over RDP - doesn't matter) as the account that will keep using this machine, typically already an Administrator or about to become one via this same run. Nothing gets created or deleted, so [`local_users`](#local_users) and [`delete_bootstrap_user`](#delete_bootstrap_user) usually don't come up at all.

**SSH keys**: just [`ssh_server.authorized_keys`](#ssh_server) - that step always configures key-based login for whichever account is currently running bootstrap (the shared `administrators_authorized_keys` file if it's an Administrator, that account's own per-user file otherwise), so no `local_users` entry is needed just to grant yourself access.

```yaml
ssh_server:
  enable: true
  authorized_keys:
    - "ssh-ed25519 AAAA... your-comment"
```

Other things that stay simple in this scenario:

- [`apps`](#apps) entries with `scope: user` install straight into your
  own account, immediately, in this same run - no first-login deferral needed, since the account isn't going anywhere.
- [`delete_bootstrap_user`](#delete_bootstrap_user): omit/`false` (the
  default) - there's nothing to delete.
- [`local_users`](#local_users) is only needed if you *also* want to
  provision additional accounts beyond the one you're already using.

### Bootstrapping from a disposable template account

You're logged in as some generic/default account (e.g. baked into a VM template or an OOBE image) purely to run bootstrap once, provision the *real* account(s) that will actually be used going forward, and then get rid of the template account entirely.

**SSH keys**: define them per real account under [`local_users[].ssh_keys`](#local_users) instead - `ssh_keys: default` reuses [`ssh_server.authorized_keys`](#ssh_server) without repeating the key text, and for an `admin: true` account still lands in the same shared `administrators_authorized_keys` file `ssh_server.authorized_keys` itself populates - so it doesn't matter which account happens to be running bootstrap, the key ends up somewhere every current and future Administrator can use. Non-admin accounts get their own per-user file instead.

```yaml
ssh_server:
  enable: true
  authorized_keys:
    - "ssh-ed25519 AAAA... your-comment"

local_users:
  - name: realadmin
    generate: true
    admin: true
    ssh_keys: default

delete_bootstrap_user: true
```

Other things worth calling out for this scenario:

- At least one [`local_users`](#local_users) entry needs `admin: true`
  - [`delete_bootstrap_user`](#delete_bootstrap_user)'s hard safety gate
  refuses to run at all if it would leave the machine with zero enabled Administrators.
- [`apps`](#apps) entries with `scope: user` are skipped outright for
  the template account (they'd just be lost when it's deleted) and instead installed automatically for each `local_users` account the next time *that* account actually logs in (`complete_setup_on_first_login`, default `true`).
- `initialize_profile` (default `true`) is what makes the `ssh_keys`
  above actually apply in this SAME run, without needing to log into the new account manually first - it force-creates the account's real Windows profile right after creation.
- Don't leave `delete_bootstrap_user: true` in the config once the
  template account is gone for good. It won't accidentally delete the real account on a later re-run (the hard safety gate specifically refuses if the account currently running bootstrap matches one of this same config's `local_users` entries) - removing the setting is just cleaner once it's done its job.

## Deployment

### From local disk

Copy `win-bootstrap.ps1`, `win-bootstrap.cmd`, and your `win-bootstrap.config.yaml` onto the target machine, then run:

```
win-bootstrap.cmd
```

or directly:

```powershell
powershell.exe -ExecutionPolicy Bypass -File .\win-bootstrap.ps1 -ConfigPath .\win-bootstrap.config.yaml
```

### Split public-script / private-config repos

Host `win-bootstrap.ps1` in a public repo and your actual config (with real secrets) in a separate, private one. Fetch the config at run time via `-ConfigUrl`, authenticating with `BOOTSTRAP_CONFIG_TOKEN` if the private repo requires it — see [CLI Parameters and Environment Variables](#cli-parameters-and-environment-variables). For a GitHub-hosted public script, use your actual owner, repository, and ref; the repository path below reflects this project's `win-bootstrap/` directory:

```powershell
$scriptUrl = 'https://raw.githubusercontent.com/<owner>/<repo>/<ref>/win-bootstrap/win-bootstrap.ps1'
$configUrl = 'https://<private-config-host>/<path>/win-bootstrap.config.yaml'
Invoke-WebRequest -Uri $scriptUrl -OutFile "$env:TEMP\win-bootstrap.ps1"
powershell.exe -ExecutionPolicy Bypass -File "$env:TEMP\win-bootstrap.ps1" -ConfigUrl $configUrl
```

This is an advanced deployment pattern; keep the script and config URLs placeholders until a repository and ref have actually been selected.

### Corporate TLS-inspecting proxy / untrusted internal CA

If `-ConfigUrl` points at a host behind a corporate proxy whose CA isn't trusted by default, pick one of:

1. **`-ConfigCaUrl`** — the CA certificate is published on its own URL
  served with an ordinary, already publicly-trusted certificate (e.g. a corporate IT download page). This is the most common case and requires no manual file transfer.
2. **`-ConfigCaPath`** — the CA certificate is already a local file on
  the target machine.
3. **`-ConfigUrlInsecureSkipCertCheck`** — last resort: skips
  certificate validation, but only for the one request that fetches the config. Only use this against a URL you already trust by other means (e.g. an internal server on a network you control) — a warning is printed whenever it's used.

All three are documented in detail in [CLI Parameters and Environment Variables](#cli-parameters-and-environment-variables).

### Why `win-bootstrap.cmd` exists

`win-bootstrap.cmd` is a thin wrapper that prefers `pwsh.exe` (PowerShell
7) when it's already installed, falling back to `powershell.exe`
  (Windows PowerShell 5.1) otherwise. This works around a confirmed Windows PowerShell 5.1 bug (observed on at least one arm64 machine) where `Microsoft.PowerShell.Security` intermittently fails to auto-load for this specific script, breaking `Get-ExecutionPolicy`, the `Cert:\` drive, and `Get-Acl`. On a genuinely fresh machine (before [`install_powershell7`](#install_powershell7) has ever run), `win-bootstrap.cmd` falls back to `powershell.exe` — if that first pass happens to hit the bug, re-run after PowerShell 7 is installed so the wrapper can pick `pwsh` automatically. **Prefer `win-bootstrap.cmd` over invoking `win-bootstrap.ps1` directly for any repeat/permanent use.**

### Storing secrets in Bitwarden Secrets Manager instead of the config file

See the dedicated [Secrets](#secrets) section — in short, any `_secret_id` field resolves its value from Bitwarden Secrets Manager at run time instead of carrying the real secret inline, which is what makes a config safe to commit to git even with real certificates, keys, or passwords involved.

### Verify-before-apply and re-verification

- [`-ValidateConfig`](#cli-parameters-and-environment-variables) checks
  the config itself for authoring mistakes — no elevation, no machine involved at all, so it can run anywhere, before a config is ever deployed.
- `-Verify` reports the current state of every configured step against
  the config — `OK` / `NOT APPLIED` / `ERROR` / `UNKNOWN` — without ever changing anything on the machine. Useful both before a real run (to preview) and after one (to confirm).
- `-Download` writes a config fetched via `-ConfigUrl` to the explicit
  `win-bootstrap.config.yaml` file next to the script, so a later run (or offline inspection/editing) doesn't need to fetch it again.
- A later real run may re-check and re-apply configured state, but it can
  also repeat writes, deferred work, service operations, or reboot handling; review the config and the run summary before re-running it.
