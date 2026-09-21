<#
.SYNOPSIS
    Config-driven bootstrap script for a freshly installed Windows VM (x64 or arm64).

.DESCRIPTION
    Generic bootstrap engine: every action it can take (execution policy,
    root CA install, recovery partition removal, Virtualization-Based
    Security, OneDrive/Teams/Outlook removal, Defender exclusions, UAC reset,
    winget app install, PowerShell 7 as the default Windows Terminal
    profile, OpenSSH Server + key-based login, disabling the Windows
    ssh-agent service, computer rename, firewall/SMB shares, local user
    account creation, sudo/crash-dump/kernel-debugging configuration, and
    Windows product key installation/activation, among other things) is
    driven entirely by an external YAML config file - this script has no
    built-in personal data. A step with no corresponding config entry is
    simply skipped (that is expected, not an error). See
    docs/windows-bootstrap.md's "What Bootstrap Can Do" section for the
    complete, currently-accurate list of every supported config key.

    Config source resolution, in priority order:
      1. -ConfigPath parameter (local file)
      2. -ConfigUrl parameter (http/https URL)
      3. BOOTSTRAP_CONFIG_PATH environment variable
      4. BOOTSTRAP_CONFIG_URL environment variable
      5. win-bootstrap.config.yaml next to this script
    -ConfigPath and -ConfigUrl (and their environment variable equivalents)
    are mutually exclusive. If none of the above resolves to a usable
    config, the script errors out.

    For a config fetched via URL from a private repo, set
    BOOTSTRAP_CONFIG_TOKEN to send it as an "Authorization: Bearer <token>"
    header. This is only ever read from the environment, never accepted as
    a parameter.

    If -ConfigUrl/BOOTSTRAP_CONFIG_URL points at a host behind a corporate
    TLS-inspecting proxy, the initial config fetch fails certificate
    validation before the config (which is the only place a corporate root
    CA would normally be declared, via root_ca) has even been parsed. See
    -ConfigCaPath, -ConfigCaUrl, and -ConfigUrlInsecureSkipCertCheck below
    for ways to resolve that.

    The YAML parser only supports the subset of YAML this config format
    needs: 2-space indentation (no tabs), '#' comments, "key: value"
    scalars (true/false/yes/no become booleans, quotes are stripped),
    nested maps, "- item" lists (of scalars or of maps), "key: [a, b]"
    inline flow lists, and "key: |" block scalars for multi-line text
    (used for inline certificates). Flow mappings, anchors/aliases, and
    multi-document files are not supported.

    Fields that hold secret material (root_ca[].cert, ssh_server.
    host_keys[].private_key, local_users[].password) also accept a
    "_secret_id" source (cert_secret_id, private_key_secret_id,
    password_secret_id) instead of an inline value/_path/_url - a secret
    ID in Bitwarden Secrets Manager, fetched at run time via the bws CLI
    (installed automatically on first use). Requires the top-level config
    key "secret_manager: bws" (the only supported value today) and
    $env:BWS_ACCESS_TOKEN to be set before running - using any
    "_secret_id" field without "secret_manager" set is a config error,
    caught by -ValidateConfig or the same pre-flight check on a real run.

.PARAMETER ConfigPath
    Path to a local YAML config file. Mutually exclusive with -ConfigUrl.

.PARAMETER ConfigUrl
    URL to fetch the YAML config from. Mutually exclusive with -ConfigPath.

.PARAMETER ConfigCaPath
    Path to a CA certificate file already present locally on this machine.
    If set, it's imported into Cert:\LocalMachine\Root immediately, before
    the config is resolved/fetched - use this when -ConfigUrl/
    BOOTSTRAP_CONFIG_URL points at a host behind a corporate TLS-inspecting
    proxy whose CA isn't trusted yet. Must be a local file: fetching the CA
    itself via URL through that same untrusted chain would just move the
    trust problem one level. Mutually exclusive with -ConfigCaUrl. Safe to
    also declare the same certificate under root_ca in the config (it
    won't be installed twice).

.PARAMETER ConfigCaUrl
    URL to fetch a CA certificate from and import into
    Cert:\LocalMachine\Root before the config is resolved/fetched - same
    purpose as -ConfigCaPath, but for the common case where the CA
    certificate itself is published on a normal web page/download served
    with an ordinary, already publicly-trusted certificate (e.g. a
    corporate IT page hosting its own internal root CA for download,
    itself served over plain HTTPS the OS already trusts) - so fetching it
    has no chicken-and-egg problem and is validated normally, unlike
    -ConfigUrl/BOOTSTRAP_CONFIG_URL. Mutually exclusive with -ConfigCaPath.
    If this fetch itself fails certificate validation, that means the CA
    download URL isn't actually publicly trusted either - use
    -ConfigCaPath with a locally-obtained copy instead.

.PARAMETER ConfigUrlInsecureSkipCertCheck
    Skips TLS certificate validation, but only for the single HTTPS
    request that fetches the config via -ConfigUrl/BOOTSTRAP_CONFIG_URL -
    every other HTTPS request this script makes (winget, root_ca's
    cert_url, ssh_server.host_keys' private_key_url) still validates
    normally. Only use this against a URL whose destination you already
    trust by other means (e.g. an internal server on a network you
    control) - anyone able to intercept that one request could otherwise
    serve an arbitrary malicious config (fake root CA, arbitrary SSH keys,
    arbitrary app installs). Prints a warning whenever it's used. Prefer
    -ConfigCaPath when you have the CA certificate available locally.
    Shells out to curl.exe (bundled with Windows 10 1803+/Server 2019+) to
    do the actual insecure fetch - see Get-ConfigText.

    Note this only helps once this script is already running - fetching
    win-bootstrap.ps1 itself over a URL whose cert chains to the same
    untrusted CA has no such flag (the script doesn't exist locally yet to
    apply it), so that initial download needs the same curl.exe -k
    workaround manually - see the TL;DR's scenario 2/3.

.PARAMETER Download
    Only meaningful together with -ConfigUrl/BOOTSTRAP_CONFIG_URL: saves the
    fetched config text to win-bootstrap.config.yaml next to this script,
    for offline inspection/editing or so a later run can skip fetching it
    again. If that file already exists, prompts to overwrite it (or, under
    -Quiet, errors instead of silently overwriting). No effect when the
    config already came from a local path.

.PARAMETER Verify
    Read-only mode: for every step that would normally run, checks whether
    the current machine state already matches the config and reports
    OK / NOT APPLIED / ERROR (or UNKNOWN if that step has no verification
    check implemented) - never makes any changes. Steps skipped by config/
    -Only/-Skip are still reported as SKIPPED, same as a normal run. Still
    requires elevation, same as a normal run. Exits 1 when verification
    reports NOT APPLIED or ERROR for any step; otherwise exits 0.

.PARAMETER ValidateConfig
    Standalone, no-elevation config check: resolves, fetches, parses, and
    statically validates the config (required fields, enum values, mutual
    exclusivity across all sections) - no machine state is inspected or
    changed, so this can run on any machine, not just the eventual deploy
    target, to catch config-authoring mistakes before deployment. This is
    different from -Verify, which compares the config against this
    machine's live state and therefore still needs elevation - the two are
    mutually exclusive. Also mutually exclusive with -Only/-Skip (always
    validates the whole config). -Download still works alongside it.
    Prints "Config is valid." and exits 0, or lists every problem found
    and exits 1.

.PARAMETER Only
    Run only the step(s) matching these tag(s), skipping everything else
    regardless of config (e.g. -Only ssh). Comma-separate for more than
    one (e.g. -Only smb,firewall). Mutually exclusive with -Skip. See the
    tag table further down for the full list of valid tags.

.PARAMETER Skip
    Run every step except the one(s) matching these tag(s) (e.g.
    -Skip apps). Comma-separate for more than one. Mutually exclusive
    with -Only.

    Tags (used by both -Only and -Skip): execution_policy, root_ca,
    recovery_partition, vbs, onedrive, teams, outlook, defender, uac, apps,
    powershell7, windows_terminal, ssh, winssh_agent, computer_name,
    firewall, smb, local_users, first_login, sudo, crash_dump,
    kernel_debugging, cleanup, product_key, power. Matching is
    case-insensitive.

    If ssh_server.default_shell/windows_terminal.default_profile: pwsh7 is
    configured, -Only automatically pulls the "powershell7" tag back in
    even if you didn't name it (so e.g. -Only ssh actually results in a
    working pwsh7 default shell instead of failing that step on a machine
    that doesn't already have it) - explicitly -Skip-ping "powershell7"
    while one of those is still configured and active is instead treated
    as a conflict and errors out up front, same as install_powershell7:
    false vs. a config dependent.

    Independently of -Only/-Skip, most config sections that aren't
    already a single boolean/enum value also accept their own
    "disabled: true" - useful for temporarily switching a section off
    without deleting its content. Map sections (firewall,
    recovery_partition) take it directly inside the map. List sections
    (root_ca, defender_exclusions, smb_shares, local_users, apps) take it
    per-entry to disable just one item, or on the whole list at once by
    replacing the bare list with a block map containing "disabled: true"
    and an "items:" list - both shapes are accepted. windows_terminal and ssh_server
    already have the whole-section effect via their own "enable: false",
    and root_ca entries individually via "install: false".

.PARAMETER Quiet
    Non-interactive mode. Automatically confirms risky actions, including
    recovery-partition removal, bootstrap-user deletion, immediate network
    changes, and a required reboot. If the script is not already running
    elevated, it exits with an error instead of prompting to relaunch.

.EXAMPLE
    .\win-bootstrap.ps1
    Resolves the config from environment variables or
    win-bootstrap.config.yaml next to the script.

.EXAMPLE
    .\win-bootstrap.ps1 -ConfigPath C:\Users\me\my-bootstrap.yaml -Quiet

.EXAMPLE
    .\win-bootstrap.ps1 -ConfigUrl https://example.com/my-bootstrap.yaml
    (set $env:BOOTSTRAP_CONFIG_TOKEN first if the URL requires auth)

.EXAMPLE
    .\win-bootstrap.ps1 -ConfigUrl https://internal.example.com/my-bootstrap.yaml -ConfigUrlInsecureSkipCertCheck
    For an internal URL behind a corporate TLS-inspecting proxy whose CA
    isn't trusted yet - see -ConfigCaPath/-ConfigCaUrl for stricter
    alternatives.

.EXAMPLE
    .\win-bootstrap.ps1 -ConfigUrl https://internal.example.com/my-bootstrap.yaml -ConfigCaUrl https://it.example.com/corporate-root-ca.pem
    Trusts the corporate CA first, fetched from its own publicly-trusted
    download page, then fetches the config with full certificate
    validation - no -ConfigUrlInsecureSkipCertCheck needed.

.EXAMPLE
    .\win-bootstrap.ps1 -Only ssh
    Runs only the ssh_server-related steps, skipping everything else.

.EXAMPLE
    .\win-bootstrap.ps1 -Skip apps
    Runs everything except installing apps.

.EXAMPLE
    .\win-bootstrap.ps1 -ConfigUrl https://example.com/my-bootstrap.yaml -Download
    Fetches the config and also saves a local copy next to the script.

.EXAMPLE
    .\win-bootstrap.ps1 -Verify
    Reports whether the machine already matches the config, without
    changing anything.

.EXAMPLE
    .\win-bootstrap.ps1 -ConfigPath .\my-bootstrap.yaml -ValidateConfig
    Checks the config for authoring mistakes (no elevation, no machine
    state touched) - safe to run on any machine before deploying it.
#>

[CmdletBinding()]
param(
    [string]$ConfigPath,
    [string]$ConfigUrl,
    [string]$ConfigCaPath,
    [string]$ConfigCaUrl,
    [switch]$ConfigUrlInsecureSkipCertCheck,
    [switch]$Download,
    [switch]$Verify,
    [switch]$ValidateConfig,
    [string[]]$Only = @(),
    [string[]]$Skip = @(),
    [Alias('q')]
    [switch]$Quiet
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Fresh Windows images can default to TLS 1.0, which breaks Invoke-WebRequest
# against GitHub and most other HTTPS hosts.
[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12

# Windows PowerShell 5.1's Invoke-WebRequest renders its default progress
# bar (the blue pseudo-dialog with a spinner) via Write-Progress on every
# chunk received, which drastically slows down downloads (a long-standing
# PS 5.1 issue; PowerShell 7 doesn't have it, but this script runs under
# PS 5.1 until install_powershell7 gets around to installing it). No step
# in this script displays its own progress UI, so silencing it globally
# has no downside here.
$ProgressPreference = 'SilentlyContinue'

# Full console transcript, independent of whatever window/session started
# this run - useful because 'delete_bootstrap_user' can end that very
# session partway through (see below), and a scheduled-task-driven run
# has no visible window to read at all. Written below the protected Windows
# log directory, not under any user profile or the first-login artifact
# directory, so standard users cannot pre-create or replace its parent.
# Validation and verification deliberately do not create a persistent log:
# they may fetch private config and resolve secrets, and neither mode needs
# a durable transcript.
$script:TranscriptActive = $false
$script:TranscriptBaseDir = Join-Path ([Environment]::GetFolderPath([Environment+SpecialFolder]::Windows)) 'Logs\win-bootstrap'
$script:TranscriptPath = $null
$script:ConfigAuthOrigin = $null

function Assert-NotReparsePoint {
    param([Parameter(Mandatory)] [string]$Path)

    $item = Get-Item -LiteralPath $Path -Force -ErrorAction SilentlyContinue
    if ($item -and (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)) {
        throw "Refusing reparse point at protected transcript path '$Path'."
    }
}

function Set-BootstrapTranscriptAcl {
    param(
        [Parameter(Mandatory)] [string]$Path,
        [switch]$Directory,
        [switch]$AllowCurrentUser
    )

    Assert-NotReparsePoint -Path $Path

    # Use stable SIDs rather than localized account names. Replace the whole
    # DACL, rather than merely adding/replacing two grants: an old explicit
    # ACE (for example Everyone:Read) would otherwise survive /grant:r.
    $acl = Get-Acl -LiteralPath $Path
    $acl.SetAccessRuleProtection($true, $false)
    foreach ($existingRule in @($acl.Access)) {
        [void]$acl.RemoveAccessRuleSpecific($existingRule)
    }

    $systemSid = New-Object System.Security.Principal.SecurityIdentifier -ArgumentList 'S-1-5-18'
    $administratorsSid = New-Object System.Security.Principal.SecurityIdentifier -ArgumentList 'S-1-5-32-544'
    $currentUserSid = if ($AllowCurrentUser) { [System.Security.Principal.WindowsIdentity]::GetCurrent().User } else { $null }
    $inheritanceFlags = if ($Directory) {
        [System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor
            [System.Security.AccessControl.InheritanceFlags]::ObjectInherit
    }
    else {
        [System.Security.AccessControl.InheritanceFlags]::None
    }
    $rights = [System.Security.AccessControl.FileSystemRights]::FullControl
    $allow = [System.Security.AccessControl.AccessControlType]::Allow
    $propagation = [System.Security.AccessControl.PropagationFlags]::None
    $systemRule = New-Object System.Security.AccessControl.FileSystemAccessRule -ArgumentList @($systemSid, $rights, $inheritanceFlags, $propagation, $allow)
    $administratorsRule = New-Object System.Security.AccessControl.FileSystemAccessRule -ArgumentList @($administratorsSid, $rights, $inheritanceFlags, $propagation, $allow)
    [void]$acl.AddAccessRule($systemRule)
    [void]$acl.AddAccessRule($administratorsRule)
    if ($currentUserSid) {
        $currentUserRule = New-Object System.Security.AccessControl.FileSystemAccessRule -ArgumentList @($currentUserSid, $rights, $inheritanceFlags, $propagation, $allow)
        [void]$acl.AddAccessRule($currentUserRule)
        $acl.SetOwner($currentUserSid)
    }
    else {
        $acl.SetOwner($administratorsSid)
    }
    Set-Acl -LiteralPath $Path -AclObject $acl
}

function Start-BootstrapTranscript {
    if ($script:TranscriptActive) { return }
    try {
        Assert-NotReparsePoint -Path $script:TranscriptBaseDir
        if (-not (Test-Path $script:TranscriptBaseDir)) {
            New-Item -ItemType Directory -Path $script:TranscriptBaseDir -Force | Out-Null
        }
        Assert-NotReparsePoint -Path $script:TranscriptBaseDir
        Set-BootstrapTranscriptAcl -Path $script:TranscriptBaseDir -Directory
        Get-ChildItem -Path $script:TranscriptBaseDir -Filter 'bootstrap-run-*.log' -File -ErrorAction SilentlyContinue |
            ForEach-Object {
                Assert-NotReparsePoint -Path $_.FullName
                Set-BootstrapTranscriptAcl -Path $_.FullName
            }
        if (-not $script:TranscriptPath) {
            $script:TranscriptPath = Join-Path $script:TranscriptBaseDir "bootstrap-run-$(Get-Date -Format 'yyyyMMdd-HHmmss').log"
        }
        Assert-NotReparsePoint -Path $script:TranscriptPath
        Start-Transcript -Path $script:TranscriptPath -Append | Out-Null
        $script:TranscriptActive = $true
        try {
            Set-BootstrapTranscriptAcl -Path $script:TranscriptPath
        }
        catch {
            Stop-Transcript | Out-Null
            $script:TranscriptActive = $false
            throw
        }
    }
    catch {
        $script:TranscriptActive = $false
        Write-Warning "Could not start a protected transcript log: $($_.Exception.Message)"
    }
}

function Stop-BootstrapTranscript {
    if (-not $script:TranscriptActive) { return }
    try {
        Stop-Transcript | Out-Null
    }
    finally {
        $script:TranscriptActive = $false
    }
}

function Invoke-WithoutBootstrapTranscript {
    param([Parameter(Mandatory)] [scriptblock]$ScriptBlock)
    $resume = $script:TranscriptActive
    if ($resume) {
        try {
            Stop-BootstrapTranscript
        }
        catch {
            throw 'Cannot safely display or handle secret material because the bootstrap transcript could not be stopped.'
        }
    }
    try {
        & $ScriptBlock
    }
    finally {
        if ($resume) {
            Start-BootstrapTranscript
            if (-not $script:TranscriptActive) {
                throw 'Bootstrap transcript could not be restarted after secret handling; refusing to continue.'
            }
        }
    }
}

# ----------------------------------------------------------------------------
# -Only / -Skip step-tag filtering - validated up front (pure input
# validation, doesn't need elevation or a loaded config) so a typo'd tag
# fails fast instead of silently matching nothing.
# ----------------------------------------------------------------------------

$script:KnownStepTags = @(
    'execution_policy', 'root_ca', 'recovery_partition', 'vbs', 'onedrive',
    'teams', 'outlook', 'defender', 'uac', 'apps', 'powershell7',
    'windows_terminal', 'ssh', 'winssh_agent', 'computer_name', 'firewall',
    'smb', 'local_users', 'first_login', 'sudo', 'crash_dump',
    'kernel_debugging', 'cleanup', 'product_key', 'power', 'network'
)

# A comma-separated -Only/-Skip value (e.g. "ssh,computer_name") only gets
# split into an array automatically when the PowerShell *parser* sees it
# directly (typed interactively, or in a .ps1 that calls this one) - it
# does NOT get re-split when passed as a single argv string, which is
# exactly what happens through win-bootstrap.cmd's "powershell.exe -File
# ... %*" wrapper. Without this, -Only ssh,computer_name arrives as one
# literal tag "ssh,computer_name" instead of two, and fails validation
# below. Splitting every element on ',' here handles both invocation
# styles identically (a no-op for elements that came in already split).
function ConvertTo-NormalizedTagList {
    param([string[]]$Tags)
    # The leading comma prevents PowerShell from unrolling a 0/1-element
    # array back into $null/a bare scalar when the caller captures this
    # return value - the same pitfall (and fix) as Read-YamlSequence and
    # Get-ConfigValue elsewhere in this file. Without it, -Skip defaulting
    # to an empty array collapses to $null here, and $null.Count then
    # throws under Set-StrictMode when validated just below.
    return , @($Tags | ForEach-Object { $_ -split ',' } | ForEach-Object { $_.Trim() } | Where-Object { $_ })
}
$Only = ConvertTo-NormalizedTagList -Tags $Only
$Skip = ConvertTo-NormalizedTagList -Tags $Skip

if ($Only.Count -gt 0 -and $Skip.Count -gt 0) {
    throw '-Only and -Skip are mutually exclusive; specify only one.'
}
if ($ValidateConfig -and $Verify) {
    throw '-ValidateConfig and -Verify are mutually exclusive; -ValidateConfig checks config syntax/values only (no machine involved), -Verify checks the config against this machine''s live state.'
}
if ($ValidateConfig -and ($Only.Count -gt 0 -or $Skip.Count -gt 0)) {
    throw '-ValidateConfig always validates the whole config; it cannot be combined with -Only/-Skip.'
}
foreach ($t in ($Only + $Skip)) {
    if ($t -notin $script:KnownStepTags) {
        throw "Unknown tag '$t' in -Only/-Skip. Valid tags: $($script:KnownStepTags -join ', ')"
    }
}
$script:OnlyTags = $Only
$script:SkipTags = $Skip

# -Verify never calls a step's -Action, only its -Verify check (see
# Invoke-Step below) - this is the load-bearing guarantee that -Verify can
# never mutate the machine, so it's read once here into a script-scope flag
# rather than threaded through every call site individually.
$script:VerifyMode = $Verify.IsPresent

# ----------------------------------------------------------------------------
# GUIDs for Windows Terminal profiles that windows_terminal.default_profile
# can select. cmd/pwsh5 are Windows Terminal's own built-in dynamic
# profiles - these GUIDs are fixed/well-known (the same on every
# installation, confirmed against multiple independent settings.json
# examples), unlike e.g. WSL/VS Dev Shell profiles whose GUIDs are
# machine-generated. pwsh7 is different: winget-installed PowerShell 7 does
# not reliably register its own Windows Terminal fragment/profile, so this
# script writes one directly instead, using the real GUID Windows
# Terminal's own PowerShell 7 integration generates (confirmed from a
# working machine, not made up). None of these are meant to be
# user-retargetable via config.
# ----------------------------------------------------------------------------
$CmdTerminalProfileGuid = '{0caa0dad-35be-5f56-a8ff-afceeeaa6101}'
$Pwsh5TerminalProfileGuid = '{61c54bbd-c2c6-5271-96e7-009a87ff44bf}'
$PowerShell7TerminalProfileGuid = '{574e775e-4f2a-5b96-ac1e-a2962a402336}'

# Fixed BCD boot entry description this script uses to recognize a debug
# entry it previously created (kernel_debugging.target: dedicated) - lets
# that step be idempotent (find-and-reuse) instead of creating a new
# duplicate boot entry on every run.
$KernelDebugEntryDescription = 'Windows (Kernel Debug)'

# ----------------------------------------------------------------------------
# Shared valid-value sets for config fields with a fixed set of allowed
# strings. Defined once here and referenced both by each step's own
# inline validation AND by Test-BootstrapConfig (used by -ValidateConfig)
# - a single source of truth, so the two never drift apart the way a
# second, separately-maintained validator would (the exact failure mode
# that made this project abandon a standalone verify-bootstrap.ps1
# earlier on).
# ----------------------------------------------------------------------------
$script:ValidCrashDumpTypes = @('none', 'complete', 'kernel', 'small', 'automatic', 'active')
$script:ValidSshHostKeyTypes = @('rsa', 'ecdsa', 'ed25519')
$script:ValidFirewallProfiles = @('public', 'private')
$script:ValidFirewallRuleModes = @('block', 'allow_lan', 'allow_all')
$script:ValidShellNames = @('cmd', 'pwsh5', 'pwsh7')
$script:ValidSmbAccessLevels = @('read', 'change', 'full')
$script:ValidSudoModes = @('disabled', 'force_new_window', 'disable_input', 'normal')
$script:ValidUacLevels = @('off', 'never_notify', 'default', 'always_notify')
$script:ValidKernelDebugTargets = @('current', 'dedicated')
$script:ValidKernelDebugTransports = @('serial', 'network')
$script:ValidAppScopes = @('machine', 'user')
$script:ValidArchitectures = @('arm64', 'x64')
$script:ValidSecretManagers = @('bws')

# ----------------------------------------------------------------------------
# Minimal YAML parser - only supports the subset described in the header
# comment above. Not a general-purpose YAML implementation.
# ----------------------------------------------------------------------------

function Get-YamlIndent {
    param([Parameter(Mandatory)] [string]$Line)
    $i = 0
    while ($i -lt $Line.Length -and $Line[$i] -eq ' ') { $i++ }
    return $i
}

function Skip-YamlBlankAndComments {
    param(
        [Parameter(Mandatory)] [AllowEmptyString()] [string[]]$Lines,
        [Parameter(Mandatory)] [ref]$Index
    )
    while ($Index.Value -lt $Lines.Count) {
        $trimmed = $Lines[$Index.Value].Trim()
        if ($trimmed -eq '' -or $trimmed.StartsWith('#')) {
            $Index.Value++
        }
        else {
            break
        }
    }
}

function Remove-YamlTrailingComment {
    param([Parameter(Mandatory)] [AllowEmptyString()] [string]$Text)
    if ($Text.StartsWith("'") -or $Text.StartsWith('"')) {
        return $Text
    }
    $hashIndex = $Text.IndexOf('#')
    if ($hashIndex -lt 0) {
        return $Text
    }
    return $Text.Substring(0, $hashIndex).TrimEnd()
}

function ConvertTo-YamlScalar {
    param([Parameter(Mandatory)] [AllowEmptyString()] [string]$Text)
    $t = $Text.Trim()
    if ($t.Length -ge 2 -and (
            ($t.StartsWith("'") -and $t.EndsWith("'")) -or
            ($t.StartsWith('"') -and $t.EndsWith('"'))
        )) {
        return $t.Substring(1, $t.Length - 2)
    }
    switch ($t.ToLowerInvariant()) {
        'true' { return $true }
        'yes' { return $true }
        'false' { return $false }
        'no' { return $false }
        default { return $t }
    }
}

function ConvertFrom-YamlInlineList {
    param([Parameter(Mandatory)] [string]$Text)
    $inner = $Text.Trim()
    $inner = $inner.Substring(1, $inner.Length - 2).Trim()
    if ($inner -eq '') {
        # The leading comma prevents PowerShell from unrolling a 0/1-element
        # array into $null/a bare scalar when this return value is captured.
        return , @()
    }
    return , @($inner -split ',' | ForEach-Object { ConvertTo-YamlScalar $_.Trim() })
}

function Split-YamlKeyValue {
    param([Parameter(Mandatory)] [string]$Content)
    $match = [regex]::Match($Content, '^([A-Za-z_][\w-]*)\s*:(\s+(.*))?$')
    if (-not $match.Success) {
        return $null
    }
    $key = $match.Groups[1].Value
    $rest = if ($match.Groups[3].Success) { $match.Groups[3].Value.Trim() } else { '' }
    return @($key, (Remove-YamlTrailingComment $rest))
}

function Read-YamlBlockScalar {
    param(
        [Parameter(Mandatory)] [AllowEmptyString()] [string[]]$Lines,
        [Parameter(Mandatory)] [ref]$Index,
        [Parameter(Mandatory)] [int]$ParentIndent
    )
    $collected = [System.Collections.Generic.List[string]]::new()
    $blockIndent = $null
    while ($Index.Value -lt $Lines.Count) {
        $line = $Lines[$Index.Value]
        if ($line.Trim() -eq '') {
            if ($null -eq $blockIndent) {
                $Index.Value++
                continue
            }
            $collected.Add('')
            $Index.Value++
            continue
        }
        $currentIndent = Get-YamlIndent $line
        if ($currentIndent -le $ParentIndent) {
            break
        }
        if ($null -eq $blockIndent) {
            $blockIndent = $currentIndent
        }
        if ($currentIndent -lt $blockIndent) {
            break
        }
        $collected.Add($line.Substring($blockIndent))
        $Index.Value++
    }
    return ($collected -join "`n")
}

function Read-YamlValue {
    param(
        [Parameter(Mandatory)] [AllowEmptyString()] [string[]]$Lines,
        [Parameter(Mandatory)] [ref]$Index,
        [Parameter(Mandatory)] [int]$KeyIndent,
        [Parameter(Mandatory)] [AllowEmptyString()] [string]$Rest
    )
    if ($Rest -eq '|') {
        return Read-YamlBlockScalar -Lines $Lines -Index $Index -ParentIndent $KeyIndent
    }
    if ($Rest -eq '') {
        return Read-YamlBlock -Lines $Lines -Index $Index -Indent ($KeyIndent + 2)
    }
    if ($Rest.StartsWith('[') -and $Rest.EndsWith(']')) {
        return ConvertFrom-YamlInlineList -Text $Rest
    }
    return ConvertTo-YamlScalar -Text $Rest
}

function Read-YamlMapping {
    param(
        [Parameter(Mandatory)] [AllowEmptyString()] [string[]]$Lines,
        [Parameter(Mandatory)] [ref]$Index,
        [Parameter(Mandatory)] [int]$Indent
    )
    $map = [ordered]@{}
    while ($true) {
        Skip-YamlBlankAndComments -Lines $Lines -Index $Index
        if ($Index.Value -ge $Lines.Count) {
            break
        }
        $line = $Lines[$Index.Value]
        $lineIndent = Get-YamlIndent $line
        if ($lineIndent -lt $Indent) {
            break
        }
        if ($lineIndent -gt $Indent) {
            throw "Unexpected indentation at config line $($Index.Value + 1): '$line'"
        }
        $content = $line.Substring($lineIndent)
        if ($content -eq '-' -or $content.StartsWith('- ')) {
            throw "Expected 'key: value' but found a list item at config line $($Index.Value + 1): '$line'"
        }
        $parts = Split-YamlKeyValue -Content $content
        if ($null -eq $parts) {
            throw "Could not parse 'key: value' at config line $($Index.Value + 1): '$line'"
        }
        $key = $parts[0]
        $rest = $parts[1]
        $Index.Value++
        $map[$key] = Read-YamlValue -Lines $Lines -Index $Index -KeyIndent $lineIndent -Rest $rest
    }
    return $map
}

function Read-YamlSequence {
    param(
        [Parameter(Mandatory)] [AllowEmptyString()] [string[]]$Lines,
        [Parameter(Mandatory)] [ref]$Index,
        [Parameter(Mandatory)] [int]$Indent
    )
    $list = [System.Collections.Generic.List[object]]::new()
    while ($true) {
        Skip-YamlBlankAndComments -Lines $Lines -Index $Index
        if ($Index.Value -ge $Lines.Count) {
            break
        }
        $line = $Lines[$Index.Value]
        $lineIndent = Get-YamlIndent $line
        if ($lineIndent -lt $Indent) {
            break
        }
        if ($lineIndent -gt $Indent) {
            throw "Unexpected indentation at config line $($Index.Value + 1): '$line'"
        }
        $content = $line.Substring($lineIndent)
        if (-not ($content -eq '-' -or $content.StartsWith('- '))) {
            break
        }
        $itemContent = if ($content -eq '-') { '' } else { $content.Substring(1).TrimStart() }
        $Index.Value++

        if ($itemContent -eq '') {
            $list.Add((Read-YamlBlock -Lines $Lines -Index $Index -Indent ($lineIndent + 2)))
            continue
        }

        $parts = Split-YamlKeyValue -Content $itemContent
        if ($null -eq $parts) {
            $list.Add((ConvertTo-YamlScalar -Text (Remove-YamlTrailingComment $itemContent)))
            continue
        }

        $itemMap = [ordered]@{}
        $itemMap[$parts[0]] = Read-YamlValue -Lines $Lines -Index $Index -KeyIndent ($lineIndent + 2) -Rest $parts[1]
        $additional = Read-YamlMapping -Lines $Lines -Index $Index -Indent ($lineIndent + 2)
        foreach ($additionalKey in $additional.Keys) {
            $itemMap[$additionalKey] = $additional[$additionalKey]
        }
        $list.Add($itemMap)
    }
    # The leading comma prevents PowerShell from unrolling a 0/1-element
    # array into $null/a bare scalar when this return value is captured -
    # without it, a single-entry YAML list (e.g. one root_ca entry) silently
    # turns into that one entry's map itself instead of a 1-item array.
    return , $list.ToArray()
}

function Read-YamlBlock {
    param(
        [Parameter(Mandatory)] [AllowEmptyString()] [string[]]$Lines,
        [Parameter(Mandatory)] [ref]$Index,
        [Parameter(Mandatory)] [int]$Indent
    )
    Skip-YamlBlankAndComments -Lines $Lines -Index $Index
    if ($Index.Value -ge $Lines.Count) {
        return $null
    }
    $line = $Lines[$Index.Value]
    $lineIndent = Get-YamlIndent $line
    if ($lineIndent -lt $Indent) {
        return $null
    }
    if ($lineIndent -gt $Indent) {
        throw "Unexpected indentation at config line $($Index.Value + 1): '$line'"
    }
    $content = $line.Substring($lineIndent)
    if ($content -eq '-' -or $content.StartsWith('- ')) {
        return Read-YamlSequence -Lines $Lines -Index $Index -Indent $Indent
    }
    return Read-YamlMapping -Lines $Lines -Index $Index -Indent $Indent
}

function ConvertFrom-BootstrapYaml {
    param([AllowEmptyString()] [AllowNull()] [string]$Text)
    if ([string]::IsNullOrWhiteSpace($Text)) {
        # An empty/whitespace-only config is valid - it just means every step
        # is skipped, same as any other config that only sets a few keys.
        return $null
    }
    if ($Text -match "`t") {
        throw 'Tab characters are not supported in the config YAML; use 2-space indentation.'
    }
    $lines = $Text -split "`r?`n"
    $index = 0
    return Read-YamlBlock -Lines $lines -Index ([ref]$index) -Indent 0
}

function Get-ConfigValue {
    param(
        $Config,
        [Parameter(Mandatory)] [string[]]$Path,
        $Default = $null
    )
    $current = $Config
    $resolved = $true
    foreach ($segment in $Path) {
        if ($current -isnot [System.Collections.IDictionary] -or -not $current.Contains($segment)) {
            $resolved = $false
            break
        }
        $current = $current[$segment]
    }
    if (-not $resolved -or $null -eq $current) {
        $current = $Default
    }
    # The leading comma prevents PowerShell from unrolling a 0/1-element
    # array into $null/a bare scalar when this return value is captured -
    # without it, callers asking for a list config value (apps,
    # defender_exclusions, authorized_keys, platforms, ...) would silently
    # get back a single bare item instead of a 1-item array whenever that
    # list happens to have exactly one (or zero) entries.
    if ($current -is [array]) {
        return , $current
    }
    return $current
}

# List-shaped config sections (apps, root_ca, defender_exclusions,
# smb_shares, local_users) normally parse to a bare list, but also accept
# an alternate map shape - "<key>: { disabled: true, items: [...] }" -
# to disable the whole section at once without deleting it, the same way
# firewall/recovery_partition's own "disabled: true" already does for
# map-shaped sections. Fully backward compatible: a bare list still means
# exactly what it always did (Disabled = $false).
function Resolve-ConfigList {
    param(
        $Config,
        [Parameter(Mandatory)] [string]$Key
    )
    $raw = Get-ConfigValue $Config @($Key) @()
    if ($raw -is [System.Collections.IDictionary]) {
        return [pscustomobject]@{
            Disabled = Get-ConfigValue $raw @('disabled') $false
            Items    = Get-ConfigValue $raw @('items') @()
        }
    }
    return [pscustomobject]@{ Disabled = $false; Items = $raw }
}

# Recursively walks a parsed config tree (nested [ordered] dictionaries and
# lists, as produced by ConvertFrom-BootstrapYaml) collecting every key
# ending in "_secret_id" that has a non-empty value, with a breadcrumb path
# (e.g. "root_ca[0].cert_secret_id") for a clear error message. Needed
# because that suffix can appear at multiple, differently-nested locations
# (and more may be added later) - a hardcoded per-field list would itself
# need manual upkeep every time a new one is added.
function Find-ConfigSecretIdFields {
    param(
        $Node,
        [string]$Path = ''
    )
    $found = [System.Collections.Generic.List[string]]::new()
    if ($Node -is [System.Collections.IDictionary]) {
        foreach ($key in $Node.Keys) {
            $childPath = if ($Path) { "$Path.$key" } else { $key }
            if ($key -like '*_secret_id' -and $Node[$key]) {
                $found.Add($childPath)
            }
            else {
                # AddRange requires a strongly-typed IEnumerable[string] -
                # the recursive call's return value is a loosely-typed
                # System.Object[] (even though every element is a string),
                # which AddRange rejects outright. A plain foreach+Add
                # sidesteps that type-matching entirely.
                foreach ($nestedPath in (Find-ConfigSecretIdFields -Node $Node[$key] -Path $childPath)) {
                    $found.Add($nestedPath)
                }
            }
        }
    }
    elseif ($Node -is [System.Collections.IEnumerable] -and $Node -isnot [string]) {
        $i = 0
        foreach ($item in $Node) {
            foreach ($nestedPath in (Find-ConfigSecretIdFields -Node $item -Path "$Path[$i]")) {
                $found.Add($nestedPath)
            }
            $i++
        }
    }
    # The leading comma prevents PowerShell from unrolling a 0/1-element
    # array back into $null/a bare scalar when this return value is
    # captured - same pitfall/fix used throughout this file.
    return , @($found)
}

# Statically validates an entire parsed config against the rules every step
# already enforces at runtime (required fields, enum values, mutual
# exclusivity) - no machine-state inspection, no network/registry/file
# access beyond the config text itself already in memory. This is the
# single source of truth both -ValidateConfig (works on any machine, no
# elevation) and the real-run pre-flight gate (Assert-ConfigNoConflicts,
# below) call into - kept as one function specifically so it can never
# drift from what the steps themselves accept, the same failure mode that
# retired this project's old standalone verify-bootstrap.ps1.
function Test-BootstrapConfig {
    param(
        $Config,
        $InstallPowershell7Config,
        [string[]]$Powershell7Dependents = @()
    )
    $problems = [System.Collections.Generic.List[string]]::new()

    function Test-ExactlyOneSource {
        param([string]$Description, [hashtable]$Sources)
        $provided = @($Sources.Keys | Where-Object { $Sources[$_] })
        if ($provided.Count -ne 1) {
            $problems.Add("${Description}: specify exactly one of $($Sources.Keys -join '/') (found $($provided.Count)).")
        }
    }

    # Each item in an ssh_server.authorized_keys/local_users[].ssh_keys
    # list is either a literal string (fine, no check needed) or a map -
    # the only map shape Resolve-SshKeyList accepts is one with a
    # 'key_secret_id' key, so flag anything else here rather than let it
    # surface as a runtime error mid-deployment.
    function Test-SshKeyListShape {
        param([string]$Description, $Keys)
        for ($i = 0; $i -lt $Keys.Count; $i++) {
            $item = $Keys[$i]
            if ($item -is [System.Collections.IDictionary] -and -not (Get-ConfigValue $item @('key_secret_id'))) {
                $problems.Add("${Description}[$i]: a map entry must have a 'key_secret_id' key.")
            }
        }
    }

    function Test-PowerTimeoutValue {
        param([string]$Description, $Value)
        if (-not $Value) { return }
        if ($Value.ToString().Trim().ToLowerInvariant() -eq 'never') { return }
        $parsed = 0
        if (-not [int]::TryParse($Value.ToString().Trim(), [ref]$parsed) -or $parsed -lt 0) {
            $problems.Add("${Description} '$Value' is invalid - must be 'never' or a non-negative whole number of minutes.")
        }
    }

    function Test-Ipv4Address {
        param([string]$Address)
        if ($Address -notmatch '^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$') { return $false }
        foreach ($i in 1..4) {
            if ([int]$Matches[$i] -gt 255) { return $false }
        }
        return $true
    }

    if ($InstallPowershell7Config -eq $false -and $Powershell7Dependents.Count -gt 0) {
        $problems.Add("'install_powershell7' is set to false, but $($Powershell7Dependents -join ' and ') requires PowerShell 7 - remove the conflicting setting or set 'install_powershell7' to true.")
    }

    # windows_product_key
    $winKeyInline = Get-ConfigValue $Config @('windows_product_key')
    $winKeyPath = Get-ConfigValue $Config @('windows_product_key_path')
    $winKeyUrl = Get-ConfigValue $Config @('windows_product_key_url')
    $winKeySecretId = Get-ConfigValue $Config @('windows_product_key_secret_id')
    if ($winKeyInline -or $winKeyPath -or $winKeyUrl -or $winKeySecretId) {
        Test-ExactlyOneSource -Description 'windows_product_key' -Sources @{
            windows_product_key            = $winKeyInline
            windows_product_key_path       = $winKeyPath
            windows_product_key_url        = $winKeyUrl
            windows_product_key_secret_id  = $winKeySecretId
        }
    }
    if ($winKeyInline -and $winKeyInline -notmatch '^[A-Za-z0-9]{5}(-[A-Za-z0-9]{5}){4}$') {
        $problems.Add("windows_product_key '$winKeyInline' is not in the expected XXXXX-XXXXX-XXXXX-XXXXX-XXXXX format.")
    }

    # root_ca
    $rootCa = (Resolve-ConfigList -Config $Config -Key 'root_ca').Items
    for ($i = 0; $i -lt $rootCa.Count; $i++) {
        $entry = $rootCa[$i]
        $name = Get-ConfigValue $entry @('name')
        $label = if ($name) { "root_ca[$i] ('$name')" } else { "root_ca[$i]" }
        if (-not $name) { $problems.Add("root_ca[$i]: missing required 'name'.") }
        Test-ExactlyOneSource -Description $label -Sources @{
            cert            = Get-ConfigValue $entry @('cert')
            cert_path       = Get-ConfigValue $entry @('cert_path')
            cert_url        = Get-ConfigValue $entry @('cert_url')
            cert_secret_id  = Get-ConfigValue $entry @('cert_secret_id')
        }
    }

    # defender_exclusions
    $defenderExclusions = (Resolve-ConfigList -Config $Config -Key 'defender_exclusions').Items
    for ($i = 0; $i -lt $defenderExclusions.Count; $i++) {
        if (-not (Get-ConfigValue $defenderExclusions[$i] @('path'))) {
            $problems.Add("defender_exclusions[$i]: missing required 'path'.")
        }
    }

    # apps
    $apps = (Resolve-ConfigList -Config $Config -Key 'apps').Items
    for ($i = 0; $i -lt $apps.Count; $i++) {
        $entry = $apps[$i]
        $id = Get-ConfigValue $entry @('id')
        $label = if ($id) { "apps[$i] ('$id')" } else { "apps[$i]" }
        if (-not $id) { $problems.Add("apps[$i]: missing required 'id'.") }
        $scope = Get-ConfigValue $entry @('scope') 'machine'
        if ($scope -notin $script:ValidAppScopes) {
            $problems.Add("${label}: invalid 'scope' '$scope' - must be one of: $($script:ValidAppScopes -join ', ').")
        }
        foreach ($platform in (Get-ConfigValue $entry @('platforms') @())) {
            if ($platform -notin $script:ValidArchitectures) {
                $problems.Add("${label}: invalid 'platforms' entry '$platform' - must be one of: $($script:ValidArchitectures -join ', ').")
            }
        }
    }

    # windows_terminal
    $windowsTerminalDefaultProfile = Get-ConfigValue $Config @('windows_terminal', 'default_profile')
    if ($windowsTerminalDefaultProfile -and $windowsTerminalDefaultProfile -notin $script:ValidShellNames) {
        $problems.Add("windows_terminal.default_profile '$windowsTerminalDefaultProfile' is invalid - must be one of: $($script:ValidShellNames -join ', ').")
    }

    # ssh_server
    $sshDefaultShell = Get-ConfigValue $Config @('ssh_server', 'default_shell')
    if ($sshDefaultShell -and $sshDefaultShell -notin $script:ValidShellNames) {
        $problems.Add("ssh_server.default_shell '$sshDefaultShell' is invalid - must be one of: $($script:ValidShellNames -join ', ').")
    }
    $hostKeys = Get-ConfigValue $Config @('ssh_server', 'host_keys') @()
    for ($i = 0; $i -lt $hostKeys.Count; $i++) {
        $hostKey = $hostKeys[$i]
        $keyType = Get-ConfigValue $hostKey @('type')
        $label = "ssh_server.host_keys[$i]"
        if ($keyType -and $keyType -notin $script:ValidSshHostKeyTypes) {
            $problems.Add("${label}: invalid 'type' '$keyType' - must be one of: $($script:ValidSshHostKeyTypes -join ', ').")
        }
        elseif (-not $keyType) {
            $problems.Add("${label}: missing required 'type'.")
        }
        Test-ExactlyOneSource -Description $label -Sources @{
            private_key            = Get-ConfigValue $hostKey @('private_key')
            private_key_path       = Get-ConfigValue $hostKey @('private_key_path')
            private_key_url        = Get-ConfigValue $hostKey @('private_key_url')
            private_key_secret_id  = Get-ConfigValue $hostKey @('private_key_secret_id')
        }
    }
    Test-SshKeyListShape -Description 'ssh_server.authorized_keys' -Keys (Get-ConfigValue $Config @('ssh_server', 'authorized_keys') @())

    # uac
    $uacLevel = Get-ConfigValue $Config @('uac_level')
    if ($uacLevel -and $uacLevel -notin $script:ValidUacLevels) {
        $problems.Add("uac_level '$uacLevel' is invalid - must be one of: $($script:ValidUacLevels -join ', ').")
    }

    # power
    Test-PowerTimeoutValue -Description 'power.sleep_after.on_power' -Value (Get-ConfigValue $Config @('power', 'sleep_after', 'on_power'))
    Test-PowerTimeoutValue -Description 'power.sleep_after.on_battery' -Value (Get-ConfigValue $Config @('power', 'sleep_after', 'on_battery'))
    Test-PowerTimeoutValue -Description 'power.display_off_after.on_power' -Value (Get-ConfigValue $Config @('power', 'display_off_after', 'on_power'))
    Test-PowerTimeoutValue -Description 'power.display_off_after.on_battery' -Value (Get-ConfigValue $Config @('power', 'display_off_after', 'on_battery'))

    # network
    $networkIp = Get-ConfigValue $Config @('network', 'ip')
    $networkGateway = Get-ConfigValue $Config @('network', 'gateway')
    $networkDns = Get-ConfigValue $Config @('network', 'dns') @()
    if ($networkIp -and $networkIp -notmatch '^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2}$') {
        $problems.Add("network.ip '$networkIp' is not in the expected address/prefix (CIDR) format, e.g. 192.168.1.50/24.")
    } elseif ($networkIp) {
        $ipPart, $prefixPart = $networkIp -split '/'
        if (-not (Test-Ipv4Address $ipPart)) { $problems.Add("network.ip '$networkIp' has an invalid IPv4 address part.") }
        if ([int]$prefixPart -gt 32) { $problems.Add("network.ip '$networkIp' has an invalid prefix length - must be 0-32.") }
    }
    if ($networkGateway) {
        if (-not (Test-Ipv4Address $networkGateway)) { $problems.Add("network.gateway '$networkGateway' is not a valid IPv4 address.") }
        if (-not $networkIp) { $problems.Add("network.gateway is set but network.ip is not - a gateway is only applied together with a static IP.") }
    }
    foreach ($dnsEntry in $networkDns) {
        if (-not (Test-Ipv4Address $dnsEntry)) { $problems.Add("network.dns entry '$dnsEntry' is not a valid IPv4 address.") }
    }
    $networkMac = Get-ConfigValue $Config @('network', 'mac_address')
    if ($networkMac -and $networkMac -notmatch '^([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}$') {
        $problems.Add("network.mac_address '$networkMac' is not in the expected XX:XX:XX:XX:XX:XX format.")
    }

    # firewall
    $firewallProfile = Get-ConfigValue $Config @('firewall', 'profile')
    if ($firewallProfile -and $firewallProfile -notin $script:ValidFirewallProfiles) {
        $problems.Add("firewall.profile '$firewallProfile' is invalid - must be one of: $($script:ValidFirewallProfiles -join ', ').")
    }
    foreach ($field in @('ping', 'smb')) {
        $value = Get-ConfigValue $Config @('firewall', $field)
        if ($value -and $value -notin $script:ValidFirewallRuleModes) {
            $problems.Add("firewall.$field '$value' is invalid - must be one of: $($script:ValidFirewallRuleModes -join ', ').")
        }
    }

    # smb_shares
    $smbShares = (Resolve-ConfigList -Config $Config -Key 'smb_shares').Items
    for ($i = 0; $i -lt $smbShares.Count; $i++) {
        $entry = $smbShares[$i]
        $name = Get-ConfigValue $entry @('name')
        $label = if ($name) { "smb_shares[$i] ('$name')" } else { "smb_shares[$i]" }
        if (-not $name) { $problems.Add("smb_shares[$i]: missing required 'name'.") }
        if (-not (Get-ConfigValue $entry @('path'))) { $problems.Add("${label}: missing required 'path'.") }
        $access = Get-ConfigValue $entry @('access') 'read'
        if ($access -notin $script:ValidSmbAccessLevels) {
            $problems.Add("${label}: invalid 'access' '$access' - must be one of: $($script:ValidSmbAccessLevels -join ', ').")
        }
    }

    # local_users
    $localUsers = (Resolve-ConfigList -Config $Config -Key 'local_users').Items
    for ($i = 0; $i -lt $localUsers.Count; $i++) {
        $entry = $localUsers[$i]
        $name = Get-ConfigValue $entry @('name')
        $label = if ($name) { "local_users[$i] ('$name')" } else { "local_users[$i]" }
        if (-not $name) { $problems.Add("local_users[$i]: missing required 'name'.") }
        Test-ExactlyOneSource -Description $label -Sources @{
            password            = Get-ConfigValue $entry @('password')
            password_path       = Get-ConfigValue $entry @('password_path')
            password_url        = Get-ConfigValue $entry @('password_url')
            password_secret_id  = Get-ConfigValue $entry @('password_secret_id')
            generate            = Get-ConfigValue $entry @('generate') $false
            ask                 = Get-ConfigValue $entry @('ask') $false
        }
        $sshKeys = Get-ConfigValue $entry @('ssh_keys')
        if ($sshKeys -and $sshKeys -ne 'default') {
            Test-SshKeyListShape -Description "${label}.ssh_keys" -Keys @($sshKeys)
        }
    }

    # sudo
    $sudoMode = Get-ConfigValue $Config @('sudo', 'mode')
    if ($sudoMode -and $sudoMode -notin $script:ValidSudoModes) {
        $problems.Add("sudo.mode '$sudoMode' is invalid - must be one of: $($script:ValidSudoModes -join ', ').")
    }

    # crash_dump
    $crashDumpType = Get-ConfigValue $Config @('crash_dump', 'type')
    if ($crashDumpType -and $crashDumpType -notin $script:ValidCrashDumpTypes) {
        $problems.Add("crash_dump.type '$crashDumpType' is invalid - must be one of: $($script:ValidCrashDumpTypes -join ', ').")
    }

    # kernel_debugging
    $kernelDebugTarget = Get-ConfigValue $Config @('kernel_debugging', 'target') 'current'
    if ($kernelDebugTarget -notin $script:ValidKernelDebugTargets) {
        $problems.Add("kernel_debugging.target '$kernelDebugTarget' is invalid - must be one of: $($script:ValidKernelDebugTargets -join ', ').")
    }
    $kernelDebugDefaultProfile = Get-ConfigValue $Config @('kernel_debugging', 'default_profile') 'current'
    if ($kernelDebugDefaultProfile -notin $script:ValidKernelDebugTargets) {
        $problems.Add("kernel_debugging.default_profile '$kernelDebugDefaultProfile' is invalid - must be one of: $($script:ValidKernelDebugTargets -join ', ').")
    }
    $kernelDebugTransport = Get-ConfigValue $Config @('kernel_debugging', 'transport')
    if ($kernelDebugTransport -and $kernelDebugTransport -notin $script:ValidKernelDebugTransports) {
        $problems.Add("kernel_debugging.transport '$kernelDebugTransport' is invalid - must be one of: $($script:ValidKernelDebugTransports -join ', ').")
    }
    if ($kernelDebugTransport -eq 'network') {
        if (-not (Get-ConfigValue $Config @('kernel_debugging', 'network', 'host_ip'))) {
            $problems.Add("kernel_debugging.network: missing required 'host_ip'.")
        }
        if (-not (Get-ConfigValue $Config @('kernel_debugging', 'network', 'port'))) {
            $problems.Add("kernel_debugging.network: missing required 'port'.")
        }
        Test-ExactlyOneSource -Description 'kernel_debugging.network' -Sources @{
            key           = Get-ConfigValue $Config @('kernel_debugging', 'network', 'key')
            key_path      = Get-ConfigValue $Config @('kernel_debugging', 'network', 'key_path')
            key_url       = Get-ConfigValue $Config @('kernel_debugging', 'network', 'key_url')
            key_secret_id = Get-ConfigValue $Config @('kernel_debugging', 'network', 'key_secret_id')
            generate      = Get-ConfigValue $Config @('kernel_debugging', 'network', 'generate') $false
        }
    }

    # secret_manager / _secret_id consistency
    $secretManager = Get-ConfigValue $Config @('secret_manager')
    if ($secretManager -and $secretManager -notin $script:ValidSecretManagers) {
        $problems.Add("'secret_manager' is set to '$secretManager', which is not supported - must be one of: $($script:ValidSecretManagers -join ', ').")
    }
    $secretIdFields = Find-ConfigSecretIdFields -Node $Config
    if ($secretIdFields.Count -gt 0 -and $secretManager -notin $script:ValidSecretManagers) {
        $problems.Add("Config uses '_secret_id' at $($secretIdFields -join ', '), but 'secret_manager' is not set to a supported value ('bws' is the only one supported today) - add 'secret_manager: bws' at the top level.")
    }

    return , @($problems)
}

function Assert-ConfigNoConflicts {
    param(
        $Config,
        $InstallPowershell7Config,
        [string[]]$Powershell7Dependents
    )

    # Checked once, right after parsing and before any step runs, so a
    # config-authoring mistake is reported before any real, system-modifying
    # step has run. Delegates every actual check to Test-BootstrapConfig,
    # the same function -ValidateConfig uses - see that function's header
    # comment for why this matters.
    $problems = Test-BootstrapConfig -Config $Config -InstallPowershell7Config $InstallPowershell7Config -Powershell7Dependents $Powershell7Dependents
    if ($problems.Count -gt 0) {
        throw "Config problem(s):`n - $($problems -join "`n - ")"
    }
}

# ----------------------------------------------------------------------------
# Config source resolution and fetching
# ----------------------------------------------------------------------------

function Resolve-ConfigSource {
    param(
        [string]$ConfigPath,
        [string]$ConfigUrl
    )
    if ($ConfigPath -and $ConfigUrl) {
        throw '-ConfigPath and -ConfigUrl are mutually exclusive; specify only one.'
    }
    if ($ConfigPath) {
        return [pscustomobject]@{ Kind = 'Path'; Value = $ConfigPath }
    }
    if ($ConfigUrl) {
        return [pscustomobject]@{ Kind = 'Url'; Value = $ConfigUrl }
    }

    $envPath = $env:BOOTSTRAP_CONFIG_PATH
    $envUrl = $env:BOOTSTRAP_CONFIG_URL
    if ($envPath -and $envUrl) {
        throw 'BOOTSTRAP_CONFIG_PATH and BOOTSTRAP_CONFIG_URL are mutually exclusive; set only one.'
    }
    if ($envPath) {
        return [pscustomobject]@{ Kind = 'Path'; Value = $envPath }
    }
    if ($envUrl) {
        return [pscustomobject]@{ Kind = 'Url'; Value = $envUrl }
    }

    $defaultPath = Join-Path $PSScriptRoot 'win-bootstrap.config.yaml'
    if (Test-Path $defaultPath) {
        return [pscustomobject]@{ Kind = 'Path'; Value = $defaultPath }
    }

    throw "No configuration source found. Provide -ConfigPath, -ConfigUrl, set BOOTSTRAP_CONFIG_PATH/BOOTSTRAP_CONFIG_URL, or place a config at '$defaultPath'."
}

# PowerShell 7's Invoke-WebRequest only decodes .Content to a string for a
# handful of recognized Content-Types (text/*, application/json, etc.) - for
# anything else (e.g. a CA download served as "application/pem-certificate-
# chain", confirmed against a PEM endpoint) .Content comes back
# as a raw byte[] instead, which silently corrupts any code assuming a
# string. PEM/YAML content fetched by this script is always plain ASCII
# text regardless of what Content-Type a given server happens to set.
function ConvertTo-WebResponseText {
    param([Parameter(Mandatory)] $Content)
    if ($Content -is [byte[]]) {
        return [System.Text.Encoding]::UTF8.GetString($Content)
    }
    return $Content
}

function Get-UrlOrigin {
    param([Parameter(Mandatory)] [string]$Url)
    try {
        $uri = [Uri]$Url
    }
    catch {
        throw "Invalid URL '$Url'."
    }
    if (-not $uri.IsAbsoluteUri -or $uri.Scheme -notin @('http', 'https')) {
        throw "URL '$Url' must be an absolute HTTP(S) URL."
    }
    return '{0}://{1}:{2}' -f $uri.Scheme.ToLowerInvariant(), $uri.Host.ToLowerInvariant(), $uri.Port
}

function Get-RedirectLocation {
    param([Parameter(Mandatory)] $Response)
    $headersProperty = $Response.PSObject.Properties['Headers']
    $headers = $null
    if ($headersProperty) {
        # Assign directly instead of through an if-expression: PS 7 header
        # collections are enumerable, and the expression would unroll them
        # into KeyValuePair objects before the lookup below.
        $headers = $headersProperty.Value
    }
    if (-not $headers) { return $null }

    # Windows PowerShell exposes WebHeaderCollection as an indexable map;
    # PowerShell 7 may expose HttpResponseHeaders, where GetValues/Location
    # is the portable access path. Keep all forms here so redirect handling
    # remains identical across both runtimes.
    try {
        $indexedLocation = $headers['Location']
        if ($indexedLocation) { return [string]$indexedLocation }
    }
    catch { }
    $locationProperty = $headers.PSObject.Properties['Location']
    if ($locationProperty -and $locationProperty.Value) {
        return [string]$locationProperty.Value
    }
    try {
        $values = @($headers.GetValues('Location'))
        if ($values.Count -gt 0) { return [string]$values[0] }
    }
    catch { }
    try {
        $headerText = $headers.ToString()
        if ($headerText -match '(?im)(?:^|\r?\n)Location:\s*([^\r\n]+)') {
            return $Matches[1].Trim()
        }
    }
    catch { }
    return $null
}

function Test-ConfigTokenAllowedForUrl {
    param([Parameter(Mandatory)] [string]$Url)
    if ($env:BOOTSTRAP_CONFIG_TOKEN -and $env:BOOTSTRAP_CONFIG_TOKEN -match '[\r\n]') {
        throw 'BOOTSTRAP_CONFIG_TOKEN must not contain CR or LF characters.'
    }
    return [bool]($env:BOOTSTRAP_CONFIG_TOKEN -and $script:ConfigAuthOrigin -and
        ((Get-UrlOrigin -Url $Url) -eq $script:ConfigAuthOrigin))
}

function Get-ConfigText {
    param(
        [Parameter(Mandatory)] $Source,
        [switch]$SkipCertCheck
    )

    if ($Source.Kind -eq 'Path') {
        if (-not (Test-Path $Source.Value)) {
            throw "Config file not found: $($Source.Value)"
        }
        return Get-Content -Path $Source.Value -Raw
    }

    $requestUrl = [string]$Source.Value
    $redirectCount = 0
    $tokenEligible = Test-ConfigTokenAllowedForUrl -Url $requestUrl
    if (-not $SkipCertCheck) {
        while ($true) {
            $headers = @{}
            if ($tokenEligible -and (Get-UrlOrigin -Url $requestUrl) -eq $script:ConfigAuthOrigin) {
                $headers['Authorization'] = "Bearer $($env:BOOTSTRAP_CONFIG_TOKEN)"
            }
            try {
                # Disable automatic redirects so a bearer token can never be
                # copied to a different origin by the HTTP stack.
                # PS 5.1 emits the 3xx response plus a non-terminating
                # maximum-redirection error. Promoting that error to Stop
                # loses the response (including Location).
                $requestErrors = @()
                $response = Invoke-WebRequest -Uri $requestUrl -Headers $headers -UseBasicParsing -MaximumRedirection 0 -ErrorAction SilentlyContinue -ErrorVariable requestErrors
                if (-not $response) {
                    if ($requestErrors.Count -gt 0) { throw $requestErrors[0] }
                    throw "No HTTP response while fetching '$requestUrl'."
                }
                $statusCode = [int]$response.StatusCode
            }
            catch {
                # WebException has Response; ordinary command/binding errors
                # do not. Inspect the property safely so the original error
                # is preserved instead of being replaced by a StrictMode
                # "property Response was not found" failure.
                $responseProperty = $_.Exception.PSObject.Properties['Response']
                $redirectResponse = if ($responseProperty) { $responseProperty.Value } else { $null }
                if (-not $redirectResponse) { throw }
                $statusCode = [int]$redirectResponse.StatusCode
                if ($statusCode -lt 300 -or $statusCode -ge 400) { throw }
                $location = Get-RedirectLocation -Response $redirectResponse
                if (-not $location) { throw "HTTP $statusCode redirect from '$requestUrl' had no Location header." }
                $nextUrl = ([Uri]::new(([Uri]$requestUrl), $location)).AbsoluteUri
                if ($tokenEligible -and
                    (Get-UrlOrigin -Url $nextUrl) -ne $script:ConfigAuthOrigin) {
                    throw "Refusing authenticated config redirect from '$requestUrl' to a different origin."
                }
                $requestUrl = $nextUrl
                $redirectCount++
                if ($redirectCount -gt 10) { throw "Too many redirects while fetching '$($Source.Value)'." }
                continue
            }
            if ($statusCode -ge 300 -and $statusCode -lt 400) {
                $location = Get-RedirectLocation -Response $response
                if (-not $location) { throw "HTTP $statusCode redirect from '$requestUrl' had no Location header." }
                $nextUrl = ([Uri]::new(([Uri]$requestUrl), $location)).AbsoluteUri
                if ($tokenEligible -and
                    (Get-UrlOrigin -Url $nextUrl) -ne $script:ConfigAuthOrigin) {
                    throw "Refusing authenticated config redirect from '$requestUrl' to a different origin."
                }
                $requestUrl = $nextUrl
                $redirectCount++
                if ($redirectCount -gt 10) { throw "Too many redirects while fetching '$($Source.Value)'." }
                continue
            }
            if ($statusCode -ge 400) { throw "HTTP $statusCode fetching '$requestUrl'." }
            return ConvertTo-WebResponseText -Content $response.Content
        }
    }

    Write-Warning "TLS certificate validation was skipped for the config URL fetch ($($Source.Value)) - only safe if you already trust this URL's destination by other means, e.g. an internal server you control."

    # Shells out to curl.exe (bundled with Windows since 10 version
    # 1803/Server 2019) instead of PowerShell's own HTTP stack. This used to
    # be two separate PS-version-specific implementations - PS7+'s
    # Invoke-WebRequest has a native -SkipCertificateCheck switch (HttpClient
    # doesn't consult [Net.ServicePointManager] at all), while PS5.1 needed a
    # compiled ICertificatePolicy via Add-Type (a plain scriptblock assigned
    # to ServerCertificateValidationCallback isn't reliable: .NET's SSL layer
    # can invoke it on a worker thread with no PowerShell runspace,
    # confirmed live against a real corporate CA) - curl's own -k flag
    # replaces both with one code path that behaves identically everywhere.
    if (-not (Get-Command curl.exe -ErrorAction SilentlyContinue)) {
        throw 'curl.exe not found - required for -ConfigUrlInsecureSkipCertCheck (bundled with Windows 10 1803+/Server 2019+; if genuinely missing, use -ConfigCaPath/-ConfigCaUrl instead).'
    }

    # Do not use curl's -L here: curl would replay -H Authorization on every
    # redirected host. A temporary header file keeps the bearer token out of
    # curl's process arguments; it is protected and removed in the same
    # transcript-free block as the fetch.
    $initialUrl = $requestUrl
    $result = Invoke-WithoutBootstrapTranscript {
        $tempFile = Join-Path $env:TEMP "bootstrap-config-$([guid]::NewGuid().ToString('N')).tmp"
        $headerFile = Join-Path $env:TEMP "bootstrap-config-header-$([guid]::NewGuid().ToString('N')).tmp"
        $responseHeadersFile = Join-Path $env:TEMP "bootstrap-config-response-$([guid]::NewGuid().ToString('N')).tmp"
        try {
            $requestUrl = $initialUrl
            $redirectCount = 0
            while ($true) {
                $curlArgs = @('-k', '-sS', '-D', $responseHeadersFile, '-o', $tempFile, '-w', '%{http_code}', $requestUrl)
                if ($tokenEligible -and (Get-UrlOrigin -Url $requestUrl) -eq $script:ConfigAuthOrigin) {
                    if (-not (Test-Path $headerFile)) {
                        New-Item -ItemType File -Path $headerFile -Force | Out-Null
                        Set-BootstrapTranscriptAcl -Path $headerFile -AllowCurrentUser
                    }
                    Set-Content -Path $headerFile -Value "Authorization: Bearer $($env:BOOTSTRAP_CONFIG_TOKEN)" -NoNewline -Encoding ascii
                    $curlArgs += @('-H', "@$headerFile")
                }
                $statusText = & curl.exe @curlArgs
                if ($LASTEXITCODE -ne 0) {
                    throw "curl.exe exited with code $LASTEXITCODE fetching '$requestUrl' (insecure/skip-cert-check mode)."
                }
                $statusCode = 0
                if (-not [int]::TryParse(([string]$statusText).Trim(), [ref]$statusCode)) {
                    throw "curl.exe did not return an HTTP status while fetching '$requestUrl'."
                }
                if ($statusCode -ge 300 -and $statusCode -lt 400) {
                    $location = $null
                    $headersText = @(Get-Content -Path $responseHeadersFile -ErrorAction SilentlyContinue)
                    foreach ($line in $headersText) {
                        if ($line -match '^Location:\s*(.+)$') { $location = $Matches[1].Trim(); break }
                    }
                    if (-not $location) { throw "HTTP $statusCode redirect from '$requestUrl' had no Location header." }
                    $nextUrl = ([Uri]::new(([Uri]$requestUrl), $location)).AbsoluteUri
                    if ($tokenEligible -and
                        (Get-UrlOrigin -Url $nextUrl) -ne $script:ConfigAuthOrigin) {
                        throw "Refusing authenticated config redirect from '$requestUrl' to a different origin."
                    }
                    $requestUrl = $nextUrl
                    $redirectCount++
                    if ($redirectCount -gt 10) { throw "Too many redirects while fetching '$($Source.Value)'." }
                    continue
                }
                if ($statusCode -ge 400) { throw "HTTP $statusCode fetching '$requestUrl'." }
                Get-Content -Path $tempFile -Raw
                break
            }
        }
        finally {
            Remove-Item -Path $tempFile, $headerFile, $responseHeadersFile -Force -ErrorAction SilentlyContinue
        }
    }
    return $result
}

# Shared by the normal/-Verify flow (section 3 below, after the CA
# pre-trust block) and the -ValidateConfig early-exit branch (before the
# elevation gate, no CA pre-trust involved) - resolves the config source,
# fetches its text, and honors -Download. Kept as one function so both
# paths stay in sync.
function Get-BootstrapConfigSourceText {
    param(
        [string]$ConfigPath,
        [string]$ConfigUrl,
        [switch]$ConfigUrlInsecureSkipCertCheck,
        [switch]$Download,
        [switch]$Quiet
    )
    $configSource = Resolve-ConfigSource -ConfigPath $ConfigPath -ConfigUrl $ConfigUrl
    if ($configSource.Kind -eq 'Url') {
        $script:ConfigAuthOrigin = Get-UrlOrigin -Url $configSource.Value
    }
    Write-Host "Using config from $($configSource.Kind): $($configSource.Value)" -ForegroundColor Cyan
    $configText = Get-ConfigText -Source $configSource -SkipCertCheck:$ConfigUrlInsecureSkipCertCheck
    if ([string]::IsNullOrWhiteSpace($configText)) {
        Write-Warning "Config from $($configSource.Kind) '$($configSource.Value)' is empty - every step below will be skipped. If that's not intentional, check that the file was transferred/saved correctly (e.g. its size is not 0 bytes)."
    }

    if ($Download) {
        if ($configSource.Kind -eq 'Url') {
            $downloadPath = Join-Path $PSScriptRoot 'win-bootstrap.config.yaml'
            $shouldWrite = $true
            if (Test-Path $downloadPath) {
                if ($Quiet) {
                    throw "-Download: '$downloadPath' already exists - refusing to overwrite it in -Quiet mode. Remove it first, or run without -Quiet to be prompted."
                }
                Write-Warning "-Download would overwrite the existing file '$downloadPath'."
                $response = Read-Host 'Type YES to overwrite, anything else to skip downloading'
                $shouldWrite = ($response -ceq 'YES')
                if (-not $shouldWrite) {
                    Write-Host 'Skipped downloading the config (existing file left untouched).'
                }
            }
            if ($shouldWrite) {
                Set-Content -Path $downloadPath -Value $configText -NoNewline -Encoding utf8
                Write-Host "Config downloaded to '$downloadPath'."
            }
        }
        else {
            Write-Host "-Download has no effect: config was already loaded from a local path ($($configSource.Value))."
        }
    }

    return $configText
}

function Resolve-ConfigResource {
    param(
        $InlineValue,
        [string]$PathValue,
        [string]$UrlValue,
        [string]$SecretIdValue,
        [Parameter(Mandatory)] [string]$Description
    )
    $providedCount = 0
    if ($InlineValue) { $providedCount++ }
    if ($PathValue) { $providedCount++ }
    if ($UrlValue) { $providedCount++ }
    if ($SecretIdValue) { $providedCount++ }
    if ($providedCount -gt 1) {
        throw "${Description}: specify only one of an inline value, a path, a url, or a secret_id."
    }

    if ($InlineValue) {
        return $InlineValue
    }
    if ($PathValue) {
        if (-not (Test-Path $PathValue)) {
            throw "${Description}: path not found: $PathValue"
        }
        return Get-Content -Path $PathValue -Raw
    }
    if ($UrlValue) {
        return Get-ConfigText -Source ([pscustomobject]@{ Kind = 'Url'; Value = $UrlValue })
    }
    if ($SecretIdValue) {
        return Get-BwsSecretValue -SecretId $SecretIdValue
    }
    throw "${Description}: no inline value, path, url, or secret_id provided."
}

# ssh_server.authorized_keys and local_users[].ssh_keys are lists where
# each item is either a literal public-key string, or a map with a
# single "key_secret_id" key resolved via Bitwarden Secrets Manager -
# lets a shared/personal access key live in one place instead of being
# pasted into every machine's config. The YAML parser (Read-YamlSequence)
# already decides each list item's shape independently, so a list mixing
# both forms parses correctly with no parser changes needed.
function Resolve-SshKeyList {
    param([Parameter(Mandatory)] [AllowEmptyCollection()] [array]$Keys)
    $resolved = [System.Collections.Generic.List[string]]::new()
    foreach ($item in $Keys) {
        if ($item -is [string]) {
            $resolved.Add($item)
        }
        elseif ($item -is [System.Collections.IDictionary]) {
            $secretId = $item['key_secret_id']
            if (-not $secretId) {
                throw "ssh key list entry is a map but has no 'key_secret_id' key."
            }
            # .Trim() guards against a trailing newline in the fetched
            # secret value breaking the exact-string matching/writing
            # done by callers.
            $resolved.Add((Get-BwsSecretValue -SecretId $secretId).Trim())
        }
        else {
            throw "ssh key list entry has an unsupported type: $($item.GetType().Name)."
        }
    }
    # The leading comma prevents PowerShell from unrolling a 0/1-element
    # array into $null/a bare scalar when this return value is captured -
    # same pitfall/fix used throughout this file.
    return , @($resolved)
}

function Install-TrustedRootCertificate {
    param(
        [Parameter(Mandatory)] [string]$CertPath,
        [Parameter(Mandatory)] [string]$Name
    )
    if (-not (Test-Path $CertPath)) {
        throw "Certificate file not found: $CertPath"
    }
    $newCert = [Security.Cryptography.X509Certificates.X509Certificate2]::new($CertPath)
    $existing = Invoke-WithTransientRetry { Get-ChildItem Cert:\LocalMachine\Root | Where-Object { $_.Thumbprint -eq $newCert.Thumbprint } }
    if ($existing) {
        Write-Host "Root CA certificate '$Name' already installed, skipping."
        return
    }
    Import-Certificate -FilePath $CertPath -CertStoreLocation Cert:\LocalMachine\Root | Out-Null
    Write-Host "Root CA certificate '$Name' installed."
}

# Read-only companion to Install-TrustedRootCertificate, used by -Verify -
# checks whether a cert is already trusted without ever importing it.
function Test-TrustedRootCertificateInstalled {
    param(
        [Parameter(Mandatory)] [string]$CertPath
    )
    if (-not (Test-Path $CertPath)) {
        throw "Certificate file not found: $CertPath"
    }
    $cert = [Security.Cryptography.X509Certificates.X509Certificate2]::new($CertPath)
    $existing = Invoke-WithTransientRetry { Get-ChildItem Cert:\LocalMachine\Root | Where-Object { $_.Thumbprint -eq $cert.Thumbprint } }
    return [bool]$existing
}

# Installs the Bitwarden Secrets Manager CLI (bws.exe), idempotently and
# permanently (not cleaned up after this run) - needed to resolve any
# config field ending in "_secret_id". No dedicated Invoke-Step/tag: this
# mirrors how Resolve-ConfigResource's own URL fetch isn't a visible step
# either, it's a helper invoked transparently by whichever step actually
# needs a secret.
$script:BwsInstallDir = Join-Path $env:ProgramData 'bws'
$script:BwsExePath = Join-Path $script:BwsInstallDir 'bws.exe'

function Install-BwsCli {
    if (Test-Path $script:BwsExePath) {
        return $script:BwsExePath
    }

    # Never installs anything under -Verify - this genuinely would be a
    # real mutation (download, extract, permanently modify the machine
    # PATH), which would violate "-Verify never modifies machine state".
    # Once bws.exe is already present (installed by an earlier real run),
    # -Verify freely reuses it below to read a secret for comparison -
    # reading isn't a mutation, exactly like -Verify's existing live _url
    # fetches elsewhere in this script.
    if ($script:VerifyMode) {
        throw 'bws CLI is not installed - cannot resolve a secret_id value under -Verify without installing it first; run once for real, or install bws manually.'
    }

    # Always resolve the latest bws-v* release rather than a version
    # pinned in this script - github.com/bitwarden/sdk-sm also hosts
    # unrelated release trains (other SDK language bindings), so a plain
    # "latest release" lookup can't be trusted; filter explicitly.
    $headers = @{ 'User-Agent' = 'win-bootstrap.ps1' }
    $releasesResponse = Invoke-WebRequest -Uri 'https://api.github.com/repos/bitwarden/sdk-sm/releases' -Headers $headers -UseBasicParsing
    $releases = ConvertTo-WebResponseText -Content $releasesResponse.Content | ConvertFrom-Json
    $bwsReleases = @($releases | Where-Object { $_.tag_name -like 'bws-v*' } | Sort-Object -Property published_at -Descending)
    if ($bwsReleases.Count -eq 0) {
        throw 'Could not find any bws-v* release at github.com/bitwarden/sdk-sm/releases.'
    }
    $release = $bwsReleases[0]

    # Matched by substring against the release's own asset list (not a
    # string-templated URL) so this keeps working even if Bitwarden's
    # exact asset-name convention shifts slightly, as long as these
    # substrings remain - a safe assumption given Rust's standard
    # target-triple naming.
    $archToken = if ($Arch -eq 'arm64') { 'aarch64' } else { 'x86_64' }
    $zipAsset = $release.assets | Where-Object { $_.name -like "*$archToken*" -and $_.name -like '*pc-windows-msvc*' } | Select-Object -First 1
    $checksumsAsset = $release.assets | Where-Object { $_.name -like '*sha256-checksums*' } | Select-Object -First 1
    if (-not $zipAsset) {
        throw "Could not find a pc-windows-msvc/$archToken asset in bws release '$($release.tag_name)'."
    }
    if (-not $checksumsAsset) {
        throw "Could not find a sha256-checksums asset in bws release '$($release.tag_name)'."
    }

    $scratchDir = Join-Path $env:TEMP "bws-install-$([guid]::NewGuid().ToString('N'))"
    New-Item -Path $scratchDir -ItemType Directory -Force | Out-Null
    try {
        $zipPath = Join-Path $scratchDir $zipAsset.name
        $checksumsPath = Join-Path $scratchDir $checksumsAsset.name
        Invoke-WebRequest -Uri $zipAsset.browser_download_url -OutFile $zipPath -Headers $headers -UseBasicParsing
        Invoke-WebRequest -Uri $checksumsAsset.browser_download_url -OutFile $checksumsPath -Headers $headers -UseBasicParsing

        # This tool will hold the decrypted value of every secret this
        # script ever fetches, so it gets the same integrity-verification
        # rigor already applied to certs (thumbprint checks) and SSH host
        # keys elsewhere in this script.
        $expectedHashLine = Get-Content -Path $checksumsPath | Where-Object { $_ -match [regex]::Escape($zipAsset.name) } | Select-Object -First 1
        if (-not $expectedHashLine) {
            throw "Could not find a checksum entry for '$($zipAsset.name)' in $($checksumsAsset.name)."
        }
        $expectedHash = ($expectedHashLine -split '\s+')[0]
        $actualHash = (Get-FileHash -Path $zipPath -Algorithm SHA256).Hash
        if ($actualHash -ne $expectedHash) {
            throw "Checksum mismatch for '$($zipAsset.name)' - expected $expectedHash, got $actualHash. Refusing to install a bws.exe build that doesn't match Bitwarden's own published checksum."
        }

        $extractDir = Join-Path $scratchDir 'extracted'
        Expand-Archive -Path $zipPath -DestinationPath $extractDir -Force
        $extractedExe = Get-ChildItem -Path $extractDir -Filter 'bws.exe' -Recurse | Select-Object -First 1
        if (-not $extractedExe) {
            throw "bws.exe not found inside '$($zipAsset.name)' after extraction."
        }

        if (-not (Test-Path $script:BwsInstallDir)) {
            New-Item -Path $script:BwsInstallDir -ItemType Directory -Force | Out-Null
        }
        Copy-Item -Path $extractedExe.FullName -Destination $script:BwsExePath -Force
        Write-Host "bws CLI ($($release.tag_name), $archToken) installed to '$script:BwsExePath'."
    }
    finally {
        Remove-Item -Path $scratchDir -Recurse -Force -ErrorAction SilentlyContinue
    }

    # Add to the machine PATH, idempotently, so bws is also usable as a
    # normal command afterward - not just invoked internally by this
    # script.
    $currentPath = [Environment]::GetEnvironmentVariable('Path', 'Machine')
    $pathEntries = $currentPath -split ';' | Where-Object { $_ }
    $alreadyOnPath = $pathEntries | Where-Object { $_.TrimEnd('\') -ieq $script:BwsInstallDir.TrimEnd('\') }
    if (-not $alreadyOnPath) {
        $newPath = ($pathEntries + $script:BwsInstallDir) -join ';'
        [Environment]::SetEnvironmentVariable('Path', $newPath, 'Machine')
        Write-Host "Added '$script:BwsInstallDir' to the machine PATH (open a new shell to use 'bws' directly)."
    }

    return $script:BwsExePath
}

function Get-BwsSecretValue {
    param([Parameter(Mandatory)] [string]$SecretId)

    if (-not $env:BWS_ACCESS_TOKEN) {
        throw "Secret '$SecretId' requires `$env:BWS_ACCESS_TOKEN to be set before running bootstrap (a Bitwarden Secrets Manager machine access token)."
    }
    if ($script:BwsSecretCache.ContainsKey($SecretId)) {
        return $script:BwsSecretCache[$SecretId]
    }

    $bwsPath = Install-BwsCli
    $output = & $bwsPath secret get $SecretId 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "bws secret get '$SecretId' failed (exit $LASTEXITCODE): $output"
    }
    $value = ($output | ConvertFrom-Json).value
    $script:BwsSecretCache[$SecretId] = $value
    return $value
}

# ----------------------------------------------------------------------------
# Other helpers
# ----------------------------------------------------------------------------

function Test-IsAdmin {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Test-BitwardenInstalled {
    # Deliberately independent of whether this script's own winget step
    # installed Bitwarden — this must also detect a pre-existing install
    # (Microsoft Store, manual download, previous run with a different
    # apps list, etc.), so it checks actual machine state instead of
    # relying on the config.
    $uninstallKeys = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*'
    )
    $registryMatch = Get-ItemProperty -Path $uninstallKeys -ErrorAction SilentlyContinue |
        Where-Object { $_.PSObject.Properties['DisplayName'] -and $_.DisplayName -like '*Bitwarden*' } |
        Select-Object -First 1

    if ($registryMatch) {
        return $true
    }

    # Bitwarden's desktop app is a per-user Squirrel install with no
    # HKLM/HKCU uninstall entry in some versions, so also check its default
    # install location directly.
    $exePath = Join-Path $env:LOCALAPPDATA 'Programs\Bitwarden\Bitwarden.exe'
    return Test-Path $exePath
}

function Confirm-RiskyAction {
    param(
        [Parameter(Mandatory)] [string]$Message
    )

    if ($Quiet) {
        return $true
    }

    Write-Warning $Message
    $response = Read-Host "Type YES to proceed, anything else to skip this step"
    return $response -ceq 'YES'
}

# Collects the outcome of every step so a final summary can be printed even
# though individual step failures do not stop the script.
$script:StepResults = [System.Collections.Generic.List[pscustomobject]]::new()
$script:RebootRequired = $false
$script:SshdRestartNeeded = $false
$script:BootstrapUserToDelete = $null
$script:NetworkConfigToApplyNow = $null

# Same-run, in-memory-only cache of secrets already fetched via
# Get-BwsSecretValue, so a SecretId referenced more than once doesn't
# trigger a second `bws` process. Never written to disk, never persisted
# across runs.
$script:BwsSecretCache = @{}

function Invoke-Step {
    param(
        [Parameter(Mandatory)] [string]$Name,
        [Parameter(Mandatory)] [scriptblock]$Action,
        # Optional read-only re-check of the same condition -Action uses to
        # decide "already correct, skip" - used only under -Verify. Must
        # return [pscustomobject]@{ Ok = <bool>; Detail = '<string>' }.
        [scriptblock]$Verify,
        [string]$SkipReason,
        [string[]]$Tag = @()
    )

    # -Only/-Skip filtering takes priority over (and is independent of)
    # whatever SkipReason the caller already computed from config - either
    # way the step just ends up SKIPPED with a reason explaining why.
    $tagSkipReason = $null
    if ($Tag.Count -gt 0) {
        if ($script:OnlyTags.Count -gt 0 -and @($Tag | Where-Object { $_ -in $script:OnlyTags }).Count -eq 0) {
            $tagSkipReason = "tag(s) '$($Tag -join ', ')' not included in -Only ($($script:OnlyTags -join ', '))"
        }
        elseif ($script:SkipTags.Count -gt 0 -and @($Tag | Where-Object { $_ -in $script:SkipTags }).Count -gt 0) {
            $tagSkipReason = "tag(s) '$($Tag -join ', ')' excluded via -Skip"
        }
    }
    $effectiveSkipReason = if ($tagSkipReason) { $tagSkipReason } else { $SkipReason }

    Write-Host "==> $Name" -ForegroundColor Cyan

    if ($effectiveSkipReason) {
        Write-Host "Skipped: $effectiveSkipReason"
        $script:StepResults.Add([pscustomobject]@{ Step = $Name; Status = 'SKIPPED'; Detail = $effectiveSkipReason })
        return
    }

    if ($script:VerifyMode) {
        # -Action is never called here - this is what guarantees -Verify
        # can't mutate the machine even if a -Verify block itself has a bug.
        if (-not $Verify) {
            Write-Host 'Not verifiable: no verification check implemented for this step.'
            $script:StepResults.Add([pscustomobject]@{ Step = $Name; Status = 'UNKNOWN'; Detail = 'no verification implemented for this step' })
            return
        }
        try {
            $result = & $Verify
            if ($result.Ok) {
                Write-Host "OK: $($result.Detail)"
                $script:StepResults.Add([pscustomobject]@{ Step = $Name; Status = 'OK'; Detail = $result.Detail })
            }
            else {
                Write-Warning "Not applied: $($result.Detail)"
                $script:StepResults.Add([pscustomobject]@{ Step = $Name; Status = 'NOT APPLIED'; Detail = $result.Detail })
            }
        }
        catch {
            Write-Warning "Verification of '$Name' errored: $($_.Exception.Message)"
            $script:StepResults.Add([pscustomobject]@{ Step = $Name; Status = 'ERROR'; Detail = $_.Exception.Message })
        }
        return
    }

    try {
        & $Action
        $script:StepResults.Add([pscustomobject]@{ Step = $Name; Status = 'OK'; Detail = '' })
    }
    catch {
        Write-Warning "Step '$Name' failed: $($_.Exception.Message)"
        $script:StepResults.Add([pscustomobject]@{ Step = $Name; Status = 'FAILED'; Detail = $_.Exception.Message })
    }
}

# winget exit codes meaning "nothing to do, the package is effectively already
# installed" rather than a real failure — without this, re-running the
# bootstrap on a machine that already has these packages reports every
# install as FAILED even though there's nothing wrong.
# https://github.com/microsoft/winget-cli/blob/master/doc/windows/package-manager/winget/returnCodes.md
$script:WingetAlreadyInstalledExitCodes = @(
    0x8A15002B, # APPINSTALLER_CLI_ERROR_UPDATE_NOT_APPLICABLE - no applicable update found
    0x8A150061, # APPINSTALLER_CLI_ERROR_PACKAGE_ALREADY_INSTALLED
    0x8A15010D, # APPINSTALLER_CLI_ERROR_INSTALL_ALREADY_INSTALLED
    0x8A15004F  # APPINSTALLER_CLI_ERROR_UPGRADE_VERSION_NOT_NEWER
)

function Test-WingetAlreadyInstalledExitCode {
    param(
        [Parameter(Mandatory)] [int]$ExitCode
    )
    # Reinterpret the signed 32-bit exit code as the unsigned HRESULT-style
    # value winget's docs list (PowerShell surfaces it as a large negative
    # number, e.g. -1978335189 for 0x8A15002B).
    $unsignedExitCode = $ExitCode -band 0xFFFFFFFF
    return $script:WingetAlreadyInstalledExitCodes -contains $unsignedExitCode
}

function Test-WingetPackageInstalled {
    param(
        [Parameter(Mandatory)] [string]$Id
    )
    # Scoped to just this one package (-e --id), not a dump of everything
    # installed. Exits 0 when winget finds a matching installed package, and a
    # non-zero "no installed package found" code otherwise. Pinned to the
    # winget source so a flaky/unreachable msstore source can't affect the
    # check for a package that isn't even published there.
    & winget list -e --id $Id --source winget --accept-source-agreements | Out-Null
    return $LASTEXITCODE -eq 0
}

function Install-WingetPackage {
    param(
        [Parameter(Mandatory)] [string]$Id,
        [Parameter(Mandatory)] [string]$Scope,
        # Optional. Only pass this when a package must be pinned to a specific
        # architecture — winget already picks the best available build (native
        # arm64, falling back to x64 emulation) on its own. If the pinned
        # architecture turns out not to exist for this package (e.g. Total
        # Commander has no arm64 build, some packages have no x64 build), the
        # install is retried once letting winget pick automatically — this
        # protects both arm64 and x64 hosts equally, without having to
        # hand-track which packages ship which architectures.
        [string]$Architecture,
        # Optional. Forces a specific winget installer type (e.g. 'wix' for
        # Microsoft.PowerShell's native MSI build, as opposed to its default
        # 'msix' Store package). Note: winget will NOT switch installer
        # types on a machine that already has any variant of the package
        # installed - it treats it as an upgrade check and no-ops with
        # "No available upgrade found" (confirmed empirically) rather than
        # installing the alternate type side by side. Migrating an
        # already-installed package to a different installer type requires
        # manually uninstalling it first, then re-running this script.
        [string]$InstallerType
    )

    if (Test-WingetPackageInstalled -Id $Id) {
        Write-Host "'$Id' is already installed, skipping."
        return
    }

    $baseArgs = @(
        'install', '-e', '--id', $Id,
        '--source', 'winget',
        '--accept-package-agreements',
        '--accept-source-agreements'
    )
    if ($Scope -eq 'User') {
        $baseArgs += @('--scope', 'user')
    }
    if ($InstallerType) {
        $baseArgs += @('--installer-type', $InstallerType)
    }
    if ($Quiet) {
        # Suppress the underlying installer's UI too, not just winget's own
        # prompts. Only enabled under -Quiet: some installers ignore this if
        # their manifest has no silent switch, but most winget packages honor it.
        $baseArgs += @('--silent', '--disable-interactivity')
    }

    if ($Architecture) {
        & winget @baseArgs '--architecture' $Architecture
        if ($LASTEXITCODE -eq 0) {
            return
        }
        if (Test-WingetAlreadyInstalledExitCode -ExitCode $LASTEXITCODE) {
            Write-Host "'$Id' is already installed, skipping."
            return
        }
        Write-Warning "winget install of '$Id' pinned to architecture '$Architecture' failed (exit $LASTEXITCODE); retrying with winget's automatic architecture selection."
    }

    & winget @baseArgs
    if ($LASTEXITCODE -eq 0) {
        return
    }
    if (Test-WingetAlreadyInstalledExitCode -ExitCode $LASTEXITCODE) {
        Write-Host "'$Id' is already installed, skipping."
        return
    }
    throw "winget exited with code $LASTEXITCODE for package '$Id'"
}

function Resolve-DesktopShortcutSource {
    # Picks which newly-appeared item (if any) should represent an app's
    # desktop shortcut, from a before/after diff of both a desktop folder
    # and a Start Menu Programs folder. Priority (confirmed live for
    # Ghisler.TotalCommander): an installer's OWN desktop icon, if it
    # made one, is always a single, correctly-iconed shortcut - far more
    # reliable than guessing from the Start Menu, where some installers
    # (also confirmed live for Total Commander) create a subfolder with
    # extra Help/Uninstall shortcuts alongside the real one instead of a
    # single flat .lnk.
    param(
        [Parameter(Mandatory)] [AllowEmptyCollection()] [string[]]$DesktopBefore,
        [Parameter(Mandatory)] [string]$DesktopPath,
        [Parameter(Mandatory)] [AllowEmptyCollection()] [string[]]$StartMenuBefore,
        [Parameter(Mandatory)] [string]$StartMenuPath
    )
    $skipKeywords = @('uninstall', 'unins', 'help', 'readme', 'license', 'changelog', 'manual', 'documentation', 'website', 'update', 'repair')

    $newDesktopItems = @(Get-ChildItem -Path $DesktopPath -ErrorAction SilentlyContinue | Where-Object { $DesktopBefore -notcontains $_.Name })
    if ($newDesktopItems.Count -gt 0) {
        return [pscustomobject]@{ Items = $newDesktopItems; AlreadyOnDesktop = $true; Warning = $null }
    }

    $newStartMenuItems = @(Get-ChildItem -Path $StartMenuPath -ErrorAction SilentlyContinue | Where-Object { $StartMenuBefore -notcontains $_.Name })
    if ($newStartMenuItems.Count -eq 0) {
        return [pscustomobject]@{ Items = @(); AlreadyOnDesktop = $false; Warning = $null }
    }
    if ($newStartMenuItems.Count -eq 1 -and -not $newStartMenuItems[0].PSIsContainer) {
        return [pscustomobject]@{ Items = @($newStartMenuItems[0]); AlreadyOnDesktop = $false; Warning = $null }
    }
    if ($newStartMenuItems.Count -eq 1 -and $newStartMenuItems[0].PSIsContainer) {
        $candidates = @(Get-ChildItem -Path $newStartMenuItems[0].FullName -Filter '*.lnk' -ErrorAction SilentlyContinue | Where-Object {
            $lowerName = $_.BaseName.ToLowerInvariant()
            -not ($skipKeywords | Where-Object { $lowerName.Contains($_) })
        })
        if ($candidates.Count -eq 1) {
            return [pscustomobject]@{ Items = @($candidates[0]); AlreadyOnDesktop = $false; Warning = $null }
        }
        return [pscustomobject]@{
            Items            = @()
            AlreadyOnDesktop = $false
            Warning          = "new Start Menu folder '$($newStartMenuItems[0].Name)' has $($candidates.Count) ambiguous shortcut candidate(s) after filtering out help/uninstall/etc. - not creating a desktop shortcut automatically, add one by hand if needed"
        }
    }
    return [pscustomobject]@{
        Items            = @()
        AlreadyOnDesktop = $false
        Warning          = "$($newStartMenuItems.Count) new Start Menu items appeared at once - not creating a desktop shortcut automatically, add one by hand if needed"
    }
}

function Resolve-DesktopShortcutSourceWithRetry {
    # Some installers write their Start Menu shortcuts non-atomically -
    # confirmed live for Ghisler.TotalCommander: its "Uninstall or
    # Repair" shortcut appeared a full 14 seconds after the other two,
    # well after winget itself already reported the install complete.
    # Calling Resolve-DesktopShortcutSource exactly once right after
    # install can catch that folder mid-populate and wrongly conclude
    # "ambiguous" or "nothing new" - retrying gives slow installers time
    # to finish first.
    param(
        [Parameter(Mandatory)] [AllowEmptyCollection()] [string[]]$DesktopBefore,
        [Parameter(Mandatory)] [string]$DesktopPath,
        [Parameter(Mandatory)] [AllowEmptyCollection()] [string[]]$StartMenuBefore,
        [Parameter(Mandatory)] [string]$StartMenuPath
    )
    $maxAttempts = 10
    for ($attempt = 1; $attempt -le $maxAttempts; $attempt++) {
        $resolved = Resolve-DesktopShortcutSource -DesktopBefore $DesktopBefore -DesktopPath $DesktopPath -StartMenuBefore $StartMenuBefore -StartMenuPath $StartMenuPath
        if ($resolved.Items.Count -gt 0) { return $resolved }
        if ($attempt -lt $maxAttempts) { Start-Sleep -Seconds 2 }
    }
    return $resolved
}

function Resolve-ShellExecutablePath {
    param(
        # Kept as a literal ValidateSet rather than referencing
        # $script:ValidShellNames - attribute arguments must be compile-time
        # constants, not runtime variables. Keep these values in sync with
        # $script:ValidShellNames if either ever changes.
        [Parameter(Mandatory)] [ValidateSet('cmd', 'pwsh5', 'pwsh7')] [string]$Shell,
        # OpenSSH's sshd spawns DefaultShell outside of any interactive
        # desktop/Explorer session, which App Execution Alias / MSIX package
        # activation depends on - a Store/MSIX-packaged pwsh.exe (the ONLY
        # installer type winget's Microsoft.PowerShell package offers on at
        # least arm64 - confirmed via `winget show --installer-type msi`
        # returning "No applicable installer found") is not reliably usable
        # this way. Windows Terminal, by contrast, launches profiles from an
        # already-interactive session and handles MSIX/alias activation
        # fine, so it doesn't need this restriction.
        [switch]$RequireNativeWin32Install
    )
    # Get-Command is the "real on-machine detection" fallback for the
    # non-SSH case: it finds whatever is actually on PATH, including a
    # winget user-scope pwsh install's App Execution Alias under
    # %LOCALAPPDATA%\Microsoft\WindowsApps\pwsh.exe - without hardcoding any
    # particular username. That alias is also per-user-ACL'd (verified: it
    # grants access only to the owning account, not BUILTIN\Users), so it's
    # unsuitable for a machine-wide setting like OpenSSH's DefaultShell
    # regardless of the MSIX-activation issue above.
    switch ($Shell) {
        'cmd' {
            $path = Join-Path $env:SystemRoot 'System32\cmd.exe'
            if (-not (Test-Path $path)) {
                throw "cmd.exe not found at expected path '$path'."
            }
            return $path
        }
        'pwsh5' {
            $path = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
            if (Test-Path $path) {
                return $path
            }
            $command = Get-Command powershell.exe -ErrorAction SilentlyContinue
            if ($command) {
                return $command.Source
            }
            throw 'Windows PowerShell 5.1 (powershell.exe) was not found on this machine.'
        }
        'pwsh7' {
            $path = 'C:\Program Files\PowerShell\7\pwsh.exe'
            if (Test-Path $path) {
                return $path
            }
            if ($RequireNativeWin32Install) {
                throw 'PowerShell 7 was not found as a native Win32 install (C:\Program Files\PowerShell\7\pwsh.exe). The default Microsoft Store/MSIX-packaged build is not reliably usable as an OpenSSH default shell. Set "install_powershell7: true" in config (installs winget''s native "wix" MSI build) - if it was already installed via MSIX, run "winget uninstall --id Microsoft.PowerShell --source winget" first, since winget refuses to switch installer types on an already-installed package, then re-run this script.'
            }
            $command = Get-Command pwsh.exe -ErrorAction SilentlyContinue
            if ($command) {
                return $command.Source
            }
            throw 'PowerShell 7 (pwsh.exe) was not found on this machine. Set "install_powershell7: true" in config before selecting it here.'
        }
    }
}

function New-RandomPassword {
    param([int]$Length = 20)
    # Excludes visually-ambiguous characters (0/O, 1/l/I) since this may be
    # read off a console and retyped by a human. Uses a cryptographically
    # strong RNG (not Get-Random) since this becomes a real account
    # credential, even if only a short-lived one.
    $upper = 'ABCDEFGHJKLMNPQRSTUVWXYZ'
    $lower = 'abcdefghijkmnopqrstuvwxyz'
    $digits = '23456789'
    $symbols = '!@#$%^&*()-_=+'
    $all = $upper + $lower + $digits + $symbols

    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try {
        $randomBytes = [byte[]]::new(4)
        $getRandomIndex = {
            param([int]$Max)
            $rng.GetBytes($randomBytes)
            return [System.BitConverter]::ToUInt32($randomBytes, 0) % $Max
        }

        # Guarantee at least one character from each class first (satisfies
        # Windows' default local password complexity policy), then fill the
        # rest from the combined set.
        $passwordChars = [System.Collections.Generic.List[char]]::new()
        $passwordChars.Add($upper[(& $getRandomIndex $upper.Length)])
        $passwordChars.Add($lower[(& $getRandomIndex $lower.Length)])
        $passwordChars.Add($digits[(& $getRandomIndex $digits.Length)])
        $passwordChars.Add($symbols[(& $getRandomIndex $symbols.Length)])
        for ($i = $passwordChars.Count; $i -lt $Length; $i++) {
            $passwordChars.Add($all[(& $getRandomIndex $all.Length)])
        }

        # Shuffle (Fisher-Yates) so the guaranteed classes above aren't
        # always in the same leading positions.
        for ($i = $passwordChars.Count - 1; $i -gt 0; $i--) {
            $j = & $getRandomIndex ($i + 1)
            $tmp = $passwordChars[$i]
            $passwordChars[$i] = $passwordChars[$j]
            $passwordChars[$j] = $tmp
        }

        return -join $passwordChars
    }
    finally {
        $rng.Dispose()
    }
}

function ConvertFrom-SecureStringPlain {
    param([Parameter(Mandatory)] [System.Security.SecureString]$SecureString)
    $ptr = [System.Runtime.InteropServices.Marshal]::SecureStringToGlobalAllocUnicode($SecureString)
    try {
        return [System.Runtime.InteropServices.Marshal]::PtrToStringUni($ptr)
    }
    finally {
        [System.Runtime.InteropServices.Marshal]::ZeroFreeGlobalAllocUnicode($ptr)
    }
}

function Resolve-RealUserProfilePath {
    # A local account's actual profile directory is NOT reliably
    # "C:\Users\<name>" until Windows has created it for real at that
    # account's first logon - confirmed live: pre-creating a folder at the
    # guessed path for an account that had never logged on caused Windows
    # to assign a *different*, computer-name-suffixed path instead
    # (e.g. "C:\Users\<name>.<COMPUTERNAME>") the first time it actually
    # did log on, since it saw the guessed folder already "taken". Returns
    # $null if the account has no ProfileList entry yet (never logged on) -
    # callers must not guess/pre-create a path in that case.
    param([Parameter(Mandatory)] [string]$UserName)
    $sid = (Get-LocalUser -Name $UserName -ErrorAction SilentlyContinue).SID.Value
    if (-not $sid) { return $null }
    $profileKey = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$sid"
    if (-not (Test-Path $profileKey)) { return $null }
    return (Get-ItemProperty -Path $profileKey).ProfileImagePath
}

function Grant-BatchLogonRight {
    # Confirmed live: contrary to commonly-cited advice, Task Scheduler on
    # current Windows does NOT auto-grant "Log on as a batch job" to a
    # task's principal - a scheduled task for an account that doesn't
    # already hold this right registers fine but silently fails to run
    # (schtasks /Query shows a non-zero Last Result), so the profile it
    # was meant to create never materializes. secedit.exe's USER_RIGHTS
    # area is the standard script-friendly way to grant it (no P/Invoke,
    # consistent with this file's all-cmdlet/native-tool style).
    param([Parameter(Mandatory)] [string]$UserName)
    $sid = (Get-LocalUser -Name $UserName -ErrorAction Stop).SID.Value
    $cfgPath = Join-Path ([System.IO.Path]::GetTempPath()) "win-bootstrap-secpol-$([guid]::NewGuid().ToString('N')).cfg"
    $dbPath = Join-Path ([System.IO.Path]::GetTempPath()) "win-bootstrap-secpol-$([guid]::NewGuid().ToString('N')).sdb"
    try {
        secedit.exe /export /cfg $cfgPath /areas USER_RIGHTS | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "secedit /export failed (exit $LASTEXITCODE)" }

        $lines = [System.Collections.Generic.List[string]](Get-Content -Path $cfgPath)
        $found = $false
        for ($i = 0; $i -lt $lines.Count; $i++) {
            if ($lines[$i] -match '^SeBatchLogonRight\s*=\s*(.*)$') {
                $found = $true
                if ($Matches[1] -notmatch [regex]::Escape("*$sid")) {
                    $lines[$i] = "SeBatchLogonRight = $($Matches[1]),*$sid"
                }
            }
        }
        if (-not $found) {
            $idx = $lines.IndexOf('[Privilege Rights]')
            if ($idx -lt 0) { throw "secedit export has no [Privilege Rights] section" }
            $lines.Insert($idx + 1, "SeBatchLogonRight = *$sid")
        }
        Set-Content -Path $cfgPath -Value $lines

        secedit.exe /configure /db $dbPath /cfg $cfgPath /areas USER_RIGHTS | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "secedit /configure failed (exit $LASTEXITCODE)" }
    }
    finally {
        Remove-Item -Path $cfgPath, $dbPath -ErrorAction SilentlyContinue
    }
}

function Initialize-UserProfile {
    # Windows only creates a local account's real profile (folder,
    # NTUSER.DAT hive, ProfileList entry) at that account's first
    # interactive logon. Registering a one-shot Scheduled Task with real
    # credentials forces the same profile-loading Windows normally does
    # at logon, without needing an actual interactive session. Only
    # meaningful for a password this script actually knows to be current
    # (see the 'local_users' step for why that's only true for accounts
    # created in this same run).
    param(
        [Parameter(Mandatory)] [string]$UserName,
        [Parameter(Mandatory)] [securestring]$Password
    )
    if (Resolve-RealUserProfilePath -UserName $UserName) {
        return $true
    }
    $plainPassword = ConvertFrom-SecureStringPlain $Password
    $taskName = "win-bootstrap-profile-init-$([guid]::NewGuid().ToString('N').Substring(0, 8))"
    try {
        Grant-BatchLogonRight -UserName $UserName

        $action = New-ScheduledTaskAction -Execute 'cmd.exe' -Argument '/c exit'
        $trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddSeconds(1)
        Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger `
            -User $UserName -Password $plainPassword -RunLevel Limited -Force | Out-Null
        Start-ScheduledTask -TaskName $taskName

        $deadline = (Get-Date).AddSeconds(20)
        do {
            Start-Sleep -Milliseconds 500
            $state = (Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue).State
        } while ($state -eq 'Running' -and (Get-Date) -lt $deadline)
    }
    catch {
        Write-Warning "Could not run the profile-initialization scheduled task for '$UserName': $($_.Exception.Message)"
    }
    finally {
        Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
        $plainPassword = $null
    }
    return [bool](Resolve-RealUserProfilePath -UserName $UserName)
}

function Register-FirstLoginTask {
    # 'scope: user' winget installs can only ever succeed in the target
    # account's own real interactive session (a batch logon, as used by
    # Initialize-UserProfile above, never starts a real shell - confirmed
    # live that this is also why "Hi, we are preparing things for you"
    # still shows up at that account's first real logon regardless of
    # any profile pre-initialization). So instead of faking a session,
    # this defers the installs to a Scheduled Task that only fires at
    # that specific account's actual next interactive logon, then
    # deletes itself so it never runs a second time.
    #
    # Writes a real .ps1 file to C:\ProgramData\win-bootstrap (stable,
    # not tied to any user profile, same idea as C:\ProgramData\bws)
    # rather than an inline -EncodedCommand like Invoke-SshdRestart uses
    # for its one-liner - this is a multi-step script with its own log
    # output, much easier to read/re-run by hand if something needs
    # debugging later.
    param(
        [Parameter(Mandatory)] [string]$UserName,
        # Each entry: @{ Id = 'Publisher.App'; DesktopShortcut = $true/$false }
        [Parameter(Mandatory)] [pscustomobject[]]$Apps
    )
    $taskName = "win-bootstrap-first-login-$UserName"
    $baseDir = 'C:\ProgramData\win-bootstrap'
    $markerPath = Join-Path $baseDir "first-login-$UserName.done"
    if (Test-Path $markerPath) {
        Write-Host "First-login setup for '$UserName' already completed (marker file present), skipping."
        return
    }
    if (Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue) {
        Write-Host "First-login setup task for '$UserName' is already scheduled, leaving it alone."
        return
    }

    if (-not (Test-Path $baseDir)) { New-Item -ItemType Directory -Path $baseDir -Force | Out-Null }
    $scriptPath = Join-Path $baseDir "first-login-$UserName.ps1"
    $logPath = Join-Path $baseDir "first-login-$UserName.log"
    $appsLiteral = ($Apps | ForEach-Object { "@{ Id = '$($_.Id)'; DesktopShortcut = `$$($_.DesktopShortcut) }" }) -join ', '
    $appIdsDisplay = ($Apps | ForEach-Object { $_.Id }) -join ', '

    # Single-quoted (non-interpolating) template - substituted via plain
    # string replacement below, so every $variable in here is left
    # exactly as-is for the generated script's OWN parser to evaluate
    # when it actually runs, rather than being interpolated by this
    # (the bootstrap script's) parser right now.
    #
    # Confirmed live (twice): winget's App Execution Alias
    # (%LOCALAPPDATA%\Microsoft\WindowsApps\winget.exe) does NOT
    # reliably resolve yet in the environment an -AtLogOn task starts
    # in, whether called by bare name or by its full alias path - a
    # genuine race against the rest of logon processing (AppX
    # activation for the new session isn't done yet), not just a
    # missing PATH entry. A manually-triggered test task run against an
    # already-long-active session showed every invocation style working
    # fine, confirming this is specifically a just-after-logon timing
    # issue rather than something wrong with Scheduled-Task-launched
    # processes in general. So this retries for up to ~100 seconds,
    # resolving winget.exe via its real Microsoft.DesktopAppInstaller
    # package install location (not the alias) each attempt.
    #
    # Also confirmed live: schtasks.exe /Delete from within the task
    # itself (RunLevel Limited, i.e. deliberately not elevated, since a
    # per-user winget install shouldn't run elevated) can silently fail
    # to remove a task that was originally registered by bootstrap's own
    # elevated process - UAC token filtering means even an admin
    # account's non-elevated token doesn't reliably get to modify it. So
    # this doesn't rely on the task deleting itself for correctness: a
    # marker file makes every step after the first one a fast no-op
    # regardless of whether the task or script file ever get cleaned up.
    #
    # Runs in a visible, normal window (not hidden) - this is a real
    # interactive logon, so the account it's running for can watch it
    # happen instead of wondering why software silently never appeared.
    $template = @'
$markerPath = '__MARKER_PATH__'
if (Test-Path $markerPath) { exit }
$logPath = '__LOG_PATH__'
$apps = @(__APPS__)

Write-Host "Bootstrap: finishing setup for this account (__APP_COUNT__ app(s) to install)."
Write-Host "This window closes automatically when done."
Write-Host ''

function Resolve-WingetPath {
    $pkg = Get-AppxPackage -Name Microsoft.DesktopAppInstaller -ErrorAction SilentlyContinue
    if (-not $pkg) { return $null }
    $candidate = Join-Path $pkg.InstallLocation 'winget.exe'
    if (Test-Path $candidate) { return $candidate }
    return $null
}

function Test-WingetInstallSuccess {
    param([Parameter(Mandatory)] [int]$ExitCode)
    if ($ExitCode -eq 0) { return $true }
    $alreadyInstalledCodes = @(0x8A15002B, 0x8A150061, 0x8A15010D, 0x8A15004F)
    return $alreadyInstalledCodes -contains ($ExitCode -band 0xFFFFFFFF)
}

# Literal copy of Resolve-DesktopShortcutSource and
# Resolve-DesktopShortcutSourceWithRetry from win-bootstrap.ps1 itself
# (this runs as a standalone script, so it can't just call back into the
# main script's functions) - keep all copies in sync if this logic ever
# changes.
function Resolve-DesktopShortcutSource {
    param(
        [Parameter(Mandatory)] [AllowEmptyCollection()] [string[]]$DesktopBefore,
        [Parameter(Mandatory)] [string]$DesktopPath,
        [Parameter(Mandatory)] [AllowEmptyCollection()] [string[]]$StartMenuBefore,
        [Parameter(Mandatory)] [string]$StartMenuPath
    )
    $skipKeywords = @('uninstall', 'unins', 'help', 'readme', 'license', 'changelog', 'manual', 'documentation', 'website', 'update', 'repair')

    $newDesktopItems = @(Get-ChildItem -Path $DesktopPath -ErrorAction SilentlyContinue | Where-Object { $DesktopBefore -notcontains $_.Name })
    if ($newDesktopItems.Count -gt 0) {
        return [pscustomobject]@{ Items = $newDesktopItems; AlreadyOnDesktop = $true; Warning = $null }
    }

    $newStartMenuItems = @(Get-ChildItem -Path $StartMenuPath -ErrorAction SilentlyContinue | Where-Object { $StartMenuBefore -notcontains $_.Name })
    if ($newStartMenuItems.Count -eq 0) {
        return [pscustomobject]@{ Items = @(); AlreadyOnDesktop = $false; Warning = $null }
    }
    if ($newStartMenuItems.Count -eq 1 -and -not $newStartMenuItems[0].PSIsContainer) {
        return [pscustomobject]@{ Items = @($newStartMenuItems[0]); AlreadyOnDesktop = $false; Warning = $null }
    }
    if ($newStartMenuItems.Count -eq 1 -and $newStartMenuItems[0].PSIsContainer) {
        $candidates = @(Get-ChildItem -Path $newStartMenuItems[0].FullName -Filter '*.lnk' -ErrorAction SilentlyContinue | Where-Object {
            $lowerName = $_.BaseName.ToLowerInvariant()
            -not ($skipKeywords | Where-Object { $lowerName.Contains($_) })
        })
        if ($candidates.Count -eq 1) {
            return [pscustomobject]@{ Items = @($candidates[0]); AlreadyOnDesktop = $false; Warning = $null }
        }
        return [pscustomobject]@{
            Items            = @()
            AlreadyOnDesktop = $false
            Warning          = "new Start Menu folder '$($newStartMenuItems[0].Name)' has $($candidates.Count) ambiguous shortcut candidate(s) after filtering out help/uninstall/etc. - not creating a desktop shortcut automatically, add one by hand if needed"
        }
    }
    return [pscustomobject]@{
        Items            = @()
        AlreadyOnDesktop = $false
        Warning          = "$($newStartMenuItems.Count) new Start Menu items appeared at once - not creating a desktop shortcut automatically, add one by hand if needed"
    }
}

function Resolve-DesktopShortcutSourceWithRetry {
    # Some installers write their Start Menu shortcuts non-atomically -
    # confirmed live for Ghisler.TotalCommander: its "Uninstall or
    # Repair" shortcut appeared a full 14 seconds after the other two,
    # well after winget itself already reported the install complete.
    # Calling Resolve-DesktopShortcutSource exactly once right after
    # install can catch that folder mid-populate and wrongly conclude
    # "ambiguous" or "nothing new" - retrying gives slow installers time
    # to finish first.
    param(
        [Parameter(Mandatory)] [AllowEmptyCollection()] [string[]]$DesktopBefore,
        [Parameter(Mandatory)] [string]$DesktopPath,
        [Parameter(Mandatory)] [AllowEmptyCollection()] [string[]]$StartMenuBefore,
        [Parameter(Mandatory)] [string]$StartMenuPath
    )
    $maxAttempts = 10
    for ($attempt = 1; $attempt -le $maxAttempts; $attempt++) {
        $resolved = Resolve-DesktopShortcutSource -DesktopBefore $DesktopBefore -DesktopPath $DesktopPath -StartMenuBefore $StartMenuBefore -StartMenuPath $StartMenuPath
        if ($resolved.Items.Count -gt 0) { return $resolved }
        if ($attempt -lt $maxAttempts) { Start-Sleep -Seconds 2 }
    }
    return $resolved
}

$wingetPath = $null
$maxAttempts = 10
for ($attempt = 1; $attempt -le $maxAttempts; $attempt++) {
    $wingetPath = Resolve-WingetPath
    if ($wingetPath) { break }
    Write-Host "Waiting for Windows to finish setting up this account (attempt $attempt/$maxAttempts)..."
    Start-Sleep -Seconds 10
}

if (-not $wingetPath) {
    "$(Get-Date -Format o) - winget did not become available after $maxAttempts attempts" | Out-File -FilePath $logPath -Append
    Write-Host ''
    Write-Host 'winget is still not available - giving up for now.'
    Write-Host "Re-run bootstrap, or install these app(s) manually: __APP_IDS_DISPLAY__"
    Write-Host 'Press any key to close this window...'
    $null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')
    exit 1
}

$allSucceeded = $true
foreach ($app in $apps) {
    $id = $app.Id
    Write-Host "Installing $id ..."
    try {
        # This runs in the account's own real interactive session, so
        # 'Desktop'/'Programs' here resolve to ITS OWN folders (unlike the
        # shared all-users copy the main bootstrap run does for scope:
        # machine apps).
        $userStartMenu = [Environment]::GetFolderPath('Programs')
        $userDesktop = [Environment]::GetFolderPath('Desktop')
        # Confirmed live on PowerShell 5.1 with Set-StrictMode -Version
        # Latest (both in effect for this script): '$x = if (cond) {
        # @(possibly-empty-pipeline) } else { @() }' can evaluate to
        # $null instead of an empty array when the pipeline produces zero
        # objects (e.g. a genuinely empty Desktop) - silently breaking
        # Resolve-DesktopShortcutSourceWithRetry's Mandatory parameter
        # binding below. Initializing to @() first and only conditionally
        # overwriting avoids the if-expression-as-assignment shape that
        # triggers it.
        $startMenuBefore = @()
        if ($app.DesktopShortcut -and (Test-Path $userStartMenu)) {
            $startMenuBefore = @(Get-ChildItem -Path $userStartMenu -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name)
        }
        $desktopBefore = @()
        if ($app.DesktopShortcut -and (Test-Path $userDesktop)) {
            $desktopBefore = @(Get-ChildItem -Path $userDesktop -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name)
        }

        & $wingetPath install --scope user --id $id --source winget --accept-package-agreements --accept-source-agreements --silent
        $exitCode = $LASTEXITCODE
        if (-not (Test-WingetInstallSuccess -ExitCode $exitCode)) {
            $allSucceeded = $false
            "$(Get-Date -Format o) - $id - FAILED exit $exitCode" | Out-File -FilePath $logPath -Append
            Write-Host "  FAILED: winget exited with code $exitCode"
            continue
        }

        if ($app.DesktopShortcut -and (Test-Path $userStartMenu)) {
            $resolved = Resolve-DesktopShortcutSourceWithRetry -DesktopBefore $desktopBefore -DesktopPath $userDesktop -StartMenuBefore $startMenuBefore -StartMenuPath $userStartMenu
            if ($resolved.Warning) {
                Write-Host "  $($resolved.Warning)"
            }
            if (-not $resolved.AlreadyOnDesktop) {
                foreach ($item in $resolved.Items) {
                    $destPath = Join-Path $userDesktop $item.Name
                    if (-not (Test-Path $destPath)) {
                        Copy-Item -Path $item.FullName -Destination $destPath -Recurse -Force
                        Write-Host "  copied desktop shortcut for '$($item.Name)'"
                    }
                }
            }
        }

        "$(Get-Date -Format o) - $id - exit $exitCode" | Out-File -FilePath $logPath -Append
        Write-Host "  done (exit $exitCode)"
    } catch {
        $allSucceeded = $false
        "$(Get-Date -Format o) - $id - ERROR: $($_.Exception.Message)" | Out-File -FilePath $logPath -Append
        Write-Host "  FAILED: $($_.Exception.Message)"
    }
}

if (-not $allSucceeded) {
    Write-Host ''
    Write-Host 'One or more first-login installations failed. The task and script remain for a retry; no completion marker was written.'
    exit 1
}

New-Item -ItemType File -Path $markerPath -Force | Out-Null
Write-Host ''
Write-Host 'Done. This window closes in 5 seconds.'
Start-Sleep -Seconds 5
schtasks.exe /Delete /F /TN '__TASK_NAME__' | Out-Null
Remove-Item -Path $PSCommandPath -Force -ErrorAction SilentlyContinue
'@
    $scriptContent = $template.Replace('__MARKER_PATH__', $markerPath).Replace('__LOG_PATH__', $logPath).Replace('__APPS__', $appsLiteral).Replace('__APP_IDS_DISPLAY__', $appIdsDisplay).Replace('__APP_COUNT__', $Apps.Count).Replace('__TASK_NAME__', $taskName)
    Set-Content -Path $scriptPath -Value $scriptContent

    $action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "-NoProfile -ExecutionPolicy Bypass -WindowStyle Normal -File `"$scriptPath`""
    # A short delay reduces the odds of racing the rest of logon
    # processing, on top of the in-script retry loop above - cheap
    # insurance, though the retry loop is what actually makes this
    # reliable (a fixed delay alone wasn't enough - confirmed live).
    $trigger = New-ScheduledTaskTrigger -AtLogOn -User $UserName
    $trigger.Delay = 'PT10S'
    $principal = New-ScheduledTaskPrincipal -UserId $UserName -LogonType Interactive -RunLevel Limited
    Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Principal $principal -Force | Out-Null
    Write-Host "Scheduled $($Apps.Count) scope:user app(s) to install for '$UserName' at their next interactive logon (log: $logPath)."
}

function Register-ProfileCleanupTask {
    # Remove-LocalUser (called on the account currently running this very
    # script, right at the end - see 'Delete bootstrap user account')
    # only removes the SAM account, never the C:\Users\<name> folder or
    # its ProfileList registry entry. Left alone, a later bootstrap run
    # that creates a new local account with the SAME name (confirmed
    # live: the disposable account this whole mechanism is for is
    # typically recreated with a fixed name between test runs) can end
    # up reusing that same leftover folder - and stale filenames left
    # over from whatever the PREVIOUS run installed silently poison the
    # before/after diffs 'apps' desktop_shortcut/Start Menu copying rely
    # on (a same-named file that already existed doesn't look "new"),
    # even though its contents get overwritten fresh each time. The only
    # Microsoft-supported way to remove a profile completely (folder +
    # registry + any loaded hive) is the Win32_UserProfile CIM class -
    # not manual file/registry deletion, which risks corrupting an
    # unrelated loaded hive (deliberately avoided elsewhere in this
    # script for the same reason).
    #
    # Timing: the account being cleaned up is (almost always) the one
    # whose session is still actively running this script when this is
    # called, so its profile hive is essentially guaranteed to still be
    # loaded - Win32_UserProfile can't delete a loaded profile. Deferred
    # to a SYSTEM-context -AtStartup scheduled task instead, same
    # reasoning as Invoke-SshdRestart above deferring past this session
    # ending. Bootstrap already routinely ends with "reboot required" for
    # unrelated steps, so a reboot being needed here too fits the
    # existing workflow.
    param(
        [Parameter(Mandatory)] [string]$UserName,
        [Parameter(Mandatory)] [string]$Sid
    )
    $taskName = "win-bootstrap-profile-cleanup-$UserName"
    $baseDir = 'C:\ProgramData\win-bootstrap'
    $markerPath = Join-Path $baseDir "profile-cleanup-$UserName.done"
    if (Test-Path $markerPath) {
        Write-Host "Profile cleanup for '$UserName' already completed (marker file present), skipping."
        return
    }
    if (Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue) {
        Write-Host "Profile cleanup task for '$UserName' is already scheduled, leaving it alone."
        return
    }

    if (-not (Test-Path $baseDir)) { New-Item -ItemType Directory -Path $baseDir -Force | Out-Null }
    $scriptPath = Join-Path $baseDir "profile-cleanup-$UserName.ps1"
    $logPath = Join-Path $baseDir "profile-cleanup-$UserName.log"

    # Single-quoted (non-interpolating) template, same reasoning as
    # Register-FirstLoginTask above. The marker is only written on
    # confirmed success - a locked profile file (confirmed live earlier
    # this session for UsrClass.dat) can take another reboot or two to
    # release, so leaving the task in place (not self-deleting) lets it
    # keep retrying on every subsequent boot until it actually succeeds,
    # rather than silently giving up after one failed attempt.
    $template = @'
$markerPath = '__MARKER_PATH__'
if (Test-Path $markerPath) { exit }
$logPath = '__LOG_PATH__'
$sid = '__SID__'
$taskName = '__TASK_NAME__'

$maxAttempts = 5
$deleted = $false
for ($attempt = 1; $attempt -le $maxAttempts; $attempt++) {
    $targetProfile = Get-CimInstance -ClassName Win32_UserProfile -ErrorAction SilentlyContinue | Where-Object { $_.SID -eq $sid }
    if (-not $targetProfile) {
        "$(Get-Date -Format o) - no profile found for SID $sid (already removed)" | Out-File -FilePath $logPath -Append
        $deleted = $true
        break
    }
    if ($targetProfile.Loaded) {
        "$(Get-Date -Format o) - attempt $attempt/$maxAttempts - profile still loaded, waiting" | Out-File -FilePath $logPath -Append
    } else {
        try {
            Remove-CimInstance -InputObject $targetProfile -ErrorAction Stop
            "$(Get-Date -Format o) - profile for SID $sid deleted" | Out-File -FilePath $logPath -Append
            $deleted = $true
            break
        } catch {
            "$(Get-Date -Format o) - attempt $attempt/$maxAttempts - Remove-CimInstance failed: $($_.Exception.Message)" | Out-File -FilePath $logPath -Append
        }
    }
    if ($attempt -lt $maxAttempts) { Start-Sleep -Seconds 10 }
}

if ($deleted) {
    New-Item -ItemType File -Path $markerPath -Force | Out-Null
    schtasks.exe /Delete /F /TN $taskName | Out-Null
    Remove-Item -Path $PSCommandPath -Force -ErrorAction SilentlyContinue
} else {
    "$(Get-Date -Format o) - giving up for now, will retry on next boot" | Out-File -FilePath $logPath -Append
}
'@
    $scriptContent = $template.Replace('__MARKER_PATH__', $markerPath).Replace('__LOG_PATH__', $logPath).Replace('__SID__', $Sid).Replace('__TASK_NAME__', $taskName)
    Set-Content -Path $scriptPath -Value $scriptContent

    $action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$scriptPath`""
    $trigger = New-ScheduledTaskTrigger -AtStartup
    $trigger.Delay = 'PT30S'
    $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
    Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Principal $principal -Force | Out-Null
    Write-Host "Scheduled full profile cleanup for '$UserName' at next reboot (log: $logPath)."
}

function Get-BcdEntryIdByDescription {
    # bcdedit.exe has no structured/object output - parses its `/enum`
    # text into identifier/description pairs and returns the identifier
    # whose description matches. Used to find the one dedicated debug
    # boot entry this script manages, so kernel_debugging's
    # target: dedicated is idempotent across reruns instead of creating a
    # duplicate entry every time.
    param([Parameter(Mandatory)] [string]$Description)
    $output = & bcdedit.exe /enum
    if ($LASTEXITCODE -ne 0) { throw "bcdedit /enum failed (exit $LASTEXITCODE)" }
    $currentId = $null
    foreach ($line in $output) {
        if ($line -match '^identifier\s+(\{[^}]+\})') {
            $currentId = $Matches[1]
        }
        elseif ($line -match '^description\s+(.+?)\s*$' -and $currentId -and $Matches[1] -eq $Description) {
            return $currentId
        }
    }
    return $null
}

# `bootmenupolicy` is per-boot-loader-entry, not a single global switch -
# confirmed via Microsoft's own bcdedit docs and real-world multi-boot
# troubleshooting reports: setting it on {default}/{current} only affects
# that one entry, and {bootmgr} is a different BCD object that doesn't
# carry this property the same way. To make "legacy vs modern" an
# all-or-nothing choice as intended, every OSLOADER entry needs it set
# individually.
function Get-BcdOsLoaderEntries {
    $output = & bcdedit.exe /enum OSLOADER
    if ($LASTEXITCODE -ne 0) { throw "bcdedit /enum OSLOADER failed (exit $LASTEXITCODE)" }
    $entries = [System.Collections.Generic.List[pscustomobject]]::new()
    $currentGuid = $null
    $currentPolicy = $null
    foreach ($line in $output) {
        if ($line -match '^identifier\s+(\{[^}]+\})') {
            if ($currentGuid) { $entries.Add([pscustomobject]@{ Guid = $currentGuid; BootMenuPolicy = $currentPolicy }) }
            $currentGuid = $Matches[1]
            $currentPolicy = $null
        }
        elseif ($line -match '^bootmenupolicy\s+(\S+)') {
            $currentPolicy = $Matches[1]
        }
    }
    if ($currentGuid) { $entries.Add([pscustomobject]@{ Guid = $currentGuid; BootMenuPolicy = $currentPolicy }) }
    return , @($entries)
}

# On a freshly bootstrapped machine, Get-ExecutionPolicy/the Cert:\ drive/
# Get-Acl (all backed by the Microsoft.PowerShell.Security module) can
# transiently fail with "the module could not be loaded" right after heavy
# disk activity (winget installs, recovery partition resize, VBS registry
# changes) - observed live, most likely Windows Defender/Smart App Control
# actively scanning the module's freshly-touched files at that exact
# moment (same theory already noted for Set-ExecutionPolicy's own
# "Security error" below - this is the same class of issue, just hitting
# more than one cmdlet from that module). Retrying briefly clears it.
function Invoke-WithTransientRetry {
    param(
        [Parameter(Mandatory)] [scriptblock]$ScriptBlock,
        [int]$MaxAttempts = 5,
        [int]$DelaySeconds = 3
    )
    for ($attempt = 1; $attempt -le $MaxAttempts; $attempt++) {
        try {
            return & $ScriptBlock
        }
        catch {
            $isTransient = $_.Exception.Message -match 'module could not be loaded'
            if (-not $isTransient -or $attempt -eq $MaxAttempts) {
                throw
            }
            Write-Host "Transient module-load error ($($_.Exception.Message)), retrying ($attempt/$MaxAttempts)..."
            Start-Sleep -Seconds $DelaySeconds
        }
    }
}

# ----------------------------------------------------------------------------
# -ValidateConfig: a purely static check - resolve, fetch, parse, and
# validate structure/values - deliberately placed BEFORE the elevation
# gate below. No elevation, no CA pre-trust, no machine-state inspection
# of any kind: this must be runnable on any machine (not just the eventual
# deploy target) to catch config-authoring mistakes before deployment,
# not discovered deep inside a step at deploy time. Exits here either way
# - never falls through into a real/-Verify run.
# ----------------------------------------------------------------------------

if ($ValidateConfig) {
    $configText = Get-BootstrapConfigSourceText -ConfigPath $ConfigPath -ConfigUrl $ConfigUrl `
        -ConfigUrlInsecureSkipCertCheck:$ConfigUrlInsecureSkipCertCheck -Download:$Download -Quiet:$Quiet

    if ([string]::IsNullOrWhiteSpace($configText)) {
        Write-Host 'INVALID: config is empty.' -ForegroundColor Red
        exit 1
    }

    try {
        $parsedConfig = ConvertFrom-BootstrapYaml -Text $configText
    }
    catch {
        Write-Host "INVALID: could not parse config - $($_.Exception.Message)" -ForegroundColor Red
        exit 1
    }

    $installPowershell7Config = Get-ConfigValue $parsedConfig @('install_powershell7')
    $windowsTerminalWantsPowershell7 = (Get-ConfigValue $parsedConfig @('windows_terminal', 'default_profile')) -eq 'pwsh7'
    $sshWantsPowershell7 = (Get-ConfigValue $parsedConfig @('ssh_server', 'enable') $false) -and
        ((Get-ConfigValue $parsedConfig @('ssh_server', 'default_shell')) -eq 'pwsh7')
    $powershell7Dependents = @()
    if ($windowsTerminalWantsPowershell7) { $powershell7Dependents += 'windows_terminal.default_profile: pwsh7' }
    if ($sshWantsPowershell7) { $powershell7Dependents += 'ssh_server.default_shell: pwsh7' }

    $problems = Test-BootstrapConfig -Config $parsedConfig -InstallPowershell7Config $installPowershell7Config -Powershell7Dependents $powershell7Dependents
    if ($problems.Count -eq 0) {
        Write-Host 'Config is valid.' -ForegroundColor Green
        exit 0
    }
    Write-Host "Found $($problems.Count) problem(s):" -ForegroundColor Red
    $problems | ForEach-Object { Write-Host " - $_" }
    exit 1
}

# ----------------------------------------------------------------------------
# 1. Elevation gate
# ----------------------------------------------------------------------------

if (-not (Test-IsAdmin)) {
    if ($Quiet) {
        Write-Error 'This script must be run as Administrator. Re-run from an elevated prompt (or without -Quiet to be offered elevation).'
        exit 1
    }

    Write-Warning 'This script must be run as Administrator.'
    $response = Read-Host 'Relaunch elevated now? (Y/N)'
    if ($response -notmatch '^(y|yes)$') {
        Write-Host 'Exiting without making changes.'
        exit 1
    }

    # Forwards every current parameter to the elevated re-invocation - a
    # previous version of this only forwarded -ConfigPath/-ConfigUrl/-Quiet,
    # which silently dropped -Only/-Skip/-ConfigCaPath/
    # -ConfigUrlInsecureSkipCertCheck/-Verify/-Download whenever elevation
    # was actually needed (the common case, since this script always
    # requires it).
    $scriptArgs = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', "`"$PSCommandPath`"")
    if ($ConfigPath) { $scriptArgs += @('-ConfigPath', "`"$ConfigPath`"") }
    if ($ConfigUrl) { $scriptArgs += @('-ConfigUrl', "`"$ConfigUrl`"") }
    if ($ConfigCaPath) { $scriptArgs += @('-ConfigCaPath', "`"$ConfigCaPath`"") }
    if ($ConfigCaUrl) { $scriptArgs += @('-ConfigCaUrl', "`"$ConfigCaUrl`"") }
    if ($ConfigUrlInsecureSkipCertCheck) { $scriptArgs += '-ConfigUrlInsecureSkipCertCheck' }
    if ($Only.Count -gt 0) { $scriptArgs += @('-Only', ($Only -join ',')) }
    if ($Skip.Count -gt 0) { $scriptArgs += @('-Skip', ($Skip -join ',')) }
    if ($Verify) { $scriptArgs += '-Verify' }
    if ($Download) { $scriptArgs += '-Download' }
    if ($Quiet) { $scriptArgs += '-Quiet' }
    Start-Process -FilePath 'powershell.exe' -ArgumentList $scriptArgs -Verb RunAs
    exit 0
}

# The protected transcript directory requires elevation. Starting it only
# after this gate prevents a non-admin parent process from producing a
# misleading access-denied warning before it relaunches elevated.
if (-not $ValidateConfig -and -not $Verify) {
    Start-BootstrapTranscript
}

# ----------------------------------------------------------------------------
# 2. Architecture detection
# ----------------------------------------------------------------------------

$Arch = if ($env:PROCESSOR_ARCHITECTURE -eq 'ARM64') { 'arm64' } else { 'x64' }
Write-Host "Detected architecture: $Arch" -ForegroundColor Cyan

# ----------------------------------------------------------------------------
# 3. Resolve, fetch, and parse the config
# ----------------------------------------------------------------------------

# Pre-trust an optional CA certificate before resolving/fetching the config -
# breaks the chicken-and-egg of a corporate TLS-inspecting proxy whose CA can
# only otherwise be declared *inside* the config being fetched.
# -ConfigCaPath must be a local file: fetching it via URL through that same
# untrusted chain would just move the trust problem one level.
# -ConfigCaUrl is the other case - the CA cert is published on its own URL
# that's ALREADY served with a normal, publicly-trusted certificate (e.g. a
# corporate IT download page), so fetching it has no chicken-and-egg problem
# and is validated normally, same as any other HTTPS call this script makes.
$configCaPath = if ($ConfigCaPath) { $ConfigCaPath } else { $env:BOOTSTRAP_CONFIG_CA_PATH }
$configCaUrl = if ($ConfigCaUrl) { $ConfigCaUrl } else { $env:BOOTSTRAP_CONFIG_CA_URL }
$configUrlForAuth = if ($ConfigUrl) { $ConfigUrl } else { $env:BOOTSTRAP_CONFIG_URL }
if ($configUrlForAuth) {
    $script:ConfigAuthOrigin = Get-UrlOrigin -Url $configUrlForAuth
}
if ($configCaPath -and $configCaUrl) {
    throw '-ConfigCaPath and -ConfigCaUrl (and their environment variable equivalents) are mutually exclusive; specify only one.'
}
if ($configCaPath -or $configCaUrl) {
    if ($script:VerifyMode) {
        Write-Host "-ConfigCaPath/-ConfigCaUrl: skipped - -Verify never modifies machine state. If the config fetch below fails due to an untrusted certificate, trust it for real first (run without -Verify) or verify against a local file instead."
    }
    elseif ($configCaPath) {
        if (-not (Test-Path $configCaPath)) {
            throw "-ConfigCaPath/BOOTSTRAP_CONFIG_CA_PATH file not found: $configCaPath"
        }
        Install-TrustedRootCertificate -CertPath $configCaPath -Name 'config-ca-path'
    }
    else {
        $caCertText = Get-ConfigText -Source ([pscustomobject]@{ Kind = 'Url'; Value = $configCaUrl })
        $tempCaPath = Join-Path $env:TEMP 'config-ca-url.pem'
        Set-Content -Path $tempCaPath -Value $caCertText -Encoding ascii
        try {
            Install-TrustedRootCertificate -CertPath $tempCaPath -Name 'config-ca-url'
        }
        finally {
            Remove-Item -Path $tempCaPath -Force -ErrorAction SilentlyContinue
        }
    }
}

$configText = Get-BootstrapConfigSourceText -ConfigPath $ConfigPath -ConfigUrl $ConfigUrl `
    -ConfigUrlInsecureSkipCertCheck:$ConfigUrlInsecureSkipCertCheck -Download:$Download -Quiet:$Quiet

$Config = ConvertFrom-BootstrapYaml -Text $configText

# Computed once here (rather than separately inside Assert-ConfigNoConflicts
# and again at the "Install PowerShell 7" step below) since both need the
# same answer to "does anything in this config require PowerShell 7?".
$installPowershell7Config = Get-ConfigValue $Config @('install_powershell7')
$windowsTerminalWantsPowershell7 = (Get-ConfigValue $Config @('windows_terminal', 'default_profile')) -eq 'pwsh7'
$sshWantsPowershell7 = (Get-ConfigValue $Config @('ssh_server', 'enable') $false) -and
    ((Get-ConfigValue $Config @('ssh_server', 'default_shell')) -eq 'pwsh7')
$powershell7Dependents = @()
if ($windowsTerminalWantsPowershell7) { $powershell7Dependents += 'windows_terminal.default_profile: pwsh7' }
if ($sshWantsPowershell7) { $powershell7Dependents += 'ssh_server.default_shell: pwsh7' }

Assert-ConfigNoConflicts -Config $Config -InstallPowershell7Config $installPowershell7Config -Powershell7Dependents $powershell7Dependents

# -Only/-Skip filter by tag with no awareness of cross-tag dependencies -
# only the config-level conflict above (install_powershell7: false vs. a
# dependent) is checked before this point. Without this, e.g. -Only ssh
# would predictably fail "Set SSH default shell" on a machine that doesn't
# already have PowerShell 7, since the 'powershell7' tag (and therefore the
# "Install PowerShell 7" step) never runs. -Only implicitly pulls the
# dependency back in - same "install it if something needs it" philosophy
# already used for install_powershell7 in config; -Skip explicitly
# excluding it is instead treated as a real conflict, same as config's own
# install_powershell7: false check above.
if ($powershell7Dependents.Count -gt 0) {
    $sshTagActive = ($script:OnlyTags.Count -eq 0 -or 'ssh' -in $script:OnlyTags) -and 'ssh' -notin $script:SkipTags
    $windowsTerminalTagActive = ($script:OnlyTags.Count -eq 0 -or 'windows_terminal' -in $script:OnlyTags) -and 'windows_terminal' -notin $script:SkipTags
    $dependentTagActive = ($sshWantsPowershell7 -and $sshTagActive) -or ($windowsTerminalWantsPowershell7 -and $windowsTerminalTagActive)
    $powershell7TagExcluded = ($script:OnlyTags.Count -gt 0 -and 'powershell7' -notin $script:OnlyTags) -or ('powershell7' -in $script:SkipTags)

    if ($dependentTagActive -and $powershell7TagExcluded) {
        if ('powershell7' -in $script:SkipTags) {
            throw "-Skip excludes 'powershell7', but $($powershell7Dependents -join ' and ') requires it and would still run this invocation - remove 'powershell7' from -Skip, or also -Skip the dependent tag(s)."
        }
        Write-Host "-Only doesn't include 'powershell7', but $($powershell7Dependents -join ' and ') requires it - including it automatically." -ForegroundColor Cyan
        $script:OnlyTags += 'powershell7'
    }
}

# ----------------------------------------------------------------------------
# 4. Create local user accounts and initialize their profiles
# ----------------------------------------------------------------------------
# Deliberately run this early, right after config parsing - so any account
# this config creates (and its real Windows profile) already exists by the
# time later steps run, rather than only at the very end of the run.
# Configuring SSH keys for these same accounts still has to wait until
# after OpenSSH Server is installed (see "Configure SSH keys for local
# user accounts" further below) - only account creation and profile
# initialization move up here.

$localUsersResolved = Resolve-ConfigList -Config $Config -Key 'local_users'
$localUsersDisabled = $localUsersResolved.Disabled
$localUsers = $localUsersResolved.Items
if ($localUsers.Count -eq 0) {
    Invoke-Step -Name 'Create local user accounts and initialize their profiles' -SkipReason 'no local_users entries configured' -Tag 'local_users' -Action {}
}
else {
    foreach ($entry in $localUsers) {
        # Reset per-iteration so a previous user's password can never be
        # mistaken for this one's by the profile-initialization step below.
        $script:LastCreatedUserPassword = $null

        $userName = Get-ConfigValue $entry @('name')
        $isAdmin = Get-ConfigValue $entry @('admin') $false
        $passwordNeverExpires = Get-ConfigValue $entry @('password_never_expires') $false
        $generate = Get-ConfigValue $entry @('generate') $false
        $ask = Get-ConfigValue $entry @('ask') $false
        $userDisabled = Get-ConfigValue $entry @('disabled') $false
        $userSkip = if ($localUsersDisabled) {
            "'local_users.disabled' is set to true"
        } elseif ($userDisabled) {
            "'disabled: true' for user '$userName'"
        } else { $null }

        Invoke-Step -Name "Create local user '$userName'" -SkipReason $userSkip -Tag 'local_users' -Verify {
            if (-not $userName) {
                throw "local_users entry is missing 'name'."
            }
            $existing = Get-LocalUser -Name $userName -ErrorAction SilentlyContinue
            $isMember = [bool](Get-LocalGroupMember -Group 'Administrators' -ErrorAction SilentlyContinue |
                Where-Object { $_.Name -eq $userName -or $_.Name -like "*\$userName" })
            $ok = [bool]$existing -and ($isMember -eq [bool]$isAdmin)
            [pscustomobject]@{ Ok = $ok; Detail = "account exists: $([bool]$existing); Administrators member: $isMember (expected: $isAdmin) - password correctness is not verifiable (one-way hash)" }
        } -Action {
            if (-not $userName) {
                throw "local_users entry is missing 'name'."
            }

            $existing = Get-LocalUser -Name $userName -ErrorAction SilentlyContinue
            if (-not $existing) {
                $inlinePassword = Get-ConfigValue $entry @('password')
                $passwordPath = Get-ConfigValue $entry @('password_path')
                $passwordUrl = Get-ConfigValue $entry @('password_url')
                $passwordSecretId = Get-ConfigValue $entry @('password_secret_id')
                $sourceCount = 0
                if ($generate) { $sourceCount++ }
                if ($ask) { $sourceCount++ }
                if ($inlinePassword) { $sourceCount++ }
                if ($passwordPath) { $sourceCount++ }
                if ($passwordUrl) { $sourceCount++ }
                if ($passwordSecretId) { $sourceCount++ }
                if ($sourceCount -ne 1) {
                    throw "local_users '$userName': specify exactly one of 'password', 'password_path', 'password_url', 'password_secret_id', 'generate: true', or 'ask: true'."
                }

                # A password auto-generated by the script (either via generate: true, or
                # via ask: true falling back to it in -Quiet mode, where there's no
                # console to prompt on) is only ever meant as a one-time bootstrap
                # handoff - it gets revealed once (console or file, see below) and the
                # account is forced to change it at next logon. A password the operator
                # explicitly supplied (password/password_path/password_url, or typed in
                # response to an ask: true prompt) is left alone - they chose it on
                # purpose.
                $wasGenerated = $false
                if ($generate) {
                    $plainPassword = New-RandomPassword
                    $wasGenerated = $true
                }
                elseif ($ask) {
                    if ($Quiet) {
                        $plainPassword = New-RandomPassword
                        $wasGenerated = $true
                    }
                    else {
                        $maxAttempts = 3
                        $plainPassword = $null
                        for ($attempt = 1; $attempt -le $maxAttempts; $attempt++) {
                            $firstSecure = Read-Host -Prompt "Password for local user '$userName'" -AsSecureString
                            $secondSecure = Read-Host -Prompt "Confirm password for local user '$userName'" -AsSecureString
                            $firstPlain = ConvertFrom-SecureStringPlain $firstSecure
                            $secondPlain = ConvertFrom-SecureStringPlain $secondSecure
                            if ($firstPlain -eq $secondPlain) {
                                $plainPassword = $firstPlain
                                break
                            }
                            Write-Warning "Passwords did not match, try again ($attempt/$maxAttempts)."
                        }
                        if (-not $plainPassword) {
                            throw "local_users '$userName': passwords did not match after $maxAttempts attempts."
                        }
                    }
                }
                else {
                    $plainPassword = Resolve-ConfigResource -InlineValue $inlinePassword -PathValue $passwordPath `
                        -UrlValue $passwordUrl -SecretIdValue $passwordSecretId -Description "local_users '$userName' password"
                }

                $secure = ConvertTo-SecureString -String $plainPassword -AsPlainText -Force
                New-LocalUser -Name $userName -Password $secure -PasswordNeverExpires:$passwordNeverExpires | Out-Null
                Write-Host "Created local user '$userName'."
                # Known-current password, available to the profile-initialization
                # step right below for this same user (this run only).
                $script:LastCreatedUserPassword = $secure

                if ($wasGenerated) {
                    # Forces a password change at next interactive logon - New-LocalUser/
                    # Set-LocalUser have no parameter for this, ADSI is the standard way.
                    $adsiUser = [ADSI]"WinNT://./$userName,user"
                    $adsiUser.PasswordExpired = 1
                    $adsiUser.SetInfo()

                    if ($Quiet) {
                        # No console to reveal it on in -Quiet mode (and output may just
                        # go to an unattended log) - drop it in a file next to the script
                        # instead, locked down the same way ssh host keys are, so it
                        # survives for the operator to read, change, then delete.
                        Invoke-WithoutBootstrapTranscript {
                            $dumpPath = Join-Path $PSScriptRoot "$userName.generated-password.txt"
                            Set-Content -Path $dumpPath -Value $plainPassword -NoNewline -Encoding ascii
                            icacls.exe $dumpPath /inheritance:r | Out-Null
                            if ($LASTEXITCODE -ne 0) { throw "icacls /inheritance:r failed (exit $LASTEXITCODE) for $dumpPath" }
                            icacls.exe $dumpPath /grant 'SYSTEM:F' | Out-Null
                            if ($LASTEXITCODE -ne 0) { throw "icacls /grant SYSTEM:F failed (exit $LASTEXITCODE) for $dumpPath" }
                            icacls.exe $dumpPath /grant 'Administrators:F' | Out-Null
                            if ($LASTEXITCODE -ne 0) { throw "icacls /grant Administrators:F failed (exit $LASTEXITCODE) for $dumpPath" }
                            Write-Warning "Generated password for '$userName' written to '$dumpPath' - read it, change the password, then delete this file."
                        }
                    }
                    else {
                        Invoke-WithoutBootstrapTranscript {
                            Write-Host '================================================================'
                            Write-Host "GENERATED PASSWORD for '$userName' (save now - shown only once):"
                            Write-Host "  $plainPassword"
                            Write-Host 'Must be changed at next interactive logon.'
                            Write-Host '================================================================'
                        }
                    }
                }
            }
            else {
                Write-Host "Local user '$userName' already exists - leaving password untouched."
            }

            # Get-LocalGroupMember returns names as "COMPUTERNAME\username" for local
            # accounts, so match on the suffix rather than an exact string.
            $isMember = [bool](Get-LocalGroupMember -Group 'Administrators' -ErrorAction SilentlyContinue |
                Where-Object { $_.Name -eq $userName -or $_.Name -like "*\$userName" })
            if ($isAdmin -and -not $isMember) {
                Add-LocalGroupMember -Group 'Administrators' -Member $userName
                Write-Host "Added '$userName' to Administrators."
            }
            elseif (-not $isAdmin -and $isMember) {
                Remove-LocalGroupMember -Group 'Administrators' -Member $userName
                Write-Host "Removed '$userName' from Administrators."
            }
        }

        $initializeProfile = Get-ConfigValue $entry @('initialize_profile') $true
        $profileInitSkip = if ($localUsersDisabled) {
            "'local_users.disabled' is set to true"
        } elseif ($userDisabled) {
            "'disabled: true' for user '$userName'"
        } elseif (-not $initializeProfile) {
            "'initialize_profile: false' for user '$userName'"
        } else { $null }

        Invoke-Step -Name "Initialize profile for local user '$userName'" -SkipReason $profileInitSkip -Tag 'local_users' -Verify {
            $profilePath = Resolve-RealUserProfilePath -UserName $userName
            [pscustomobject]@{ Ok = [bool]$profilePath; Detail = if ($profilePath) { "profile already exists at '$profilePath'" } else { "no profile yet for '$userName' (never logged on)" } }
        } -Action {
            if (Resolve-RealUserProfilePath -UserName $userName) {
                Write-Host "Profile for '$userName' already exists, skipping."
                return
            }
            if (-not $script:LastCreatedUserPassword) {
                Write-Warning "local_users '$userName': cannot force-initialize its profile - this account already existed before this run, so its current password isn't known to this script. Log on once manually and re-run bootstrap to initialize it (the SSH-keys step below will do the same until then)."
                return
            }
            if (Initialize-UserProfile -UserName $userName -Password $script:LastCreatedUserPassword) {
                Write-Host "Initialized profile for '$userName'."
            } else {
                Write-Warning "local_users '$userName': attempted to force-initialize its profile via a one-shot scheduled task, but it still doesn't exist afterward. Log on once manually and re-run bootstrap."
            }
        }
    }
}

# ----------------------------------------------------------------------------
# 5. Allow running local PowerShell scripts
# ----------------------------------------------------------------------------

$executionPolicySkip = if (-not (Get-ConfigValue $Config @('disable_pwsh_execution_policy') $false)) {
    "'disable_pwsh_execution_policy' is not set to true in config"
} else { $null }

Invoke-Step -Name 'Set execution policy to Unrestricted' -SkipReason $executionPolicySkip -Tag 'execution_policy' -Verify {
    $machinePolicy = Invoke-WithTransientRetry { Get-ExecutionPolicy -Scope MachinePolicy }
    $userPolicy = Invoke-WithTransientRetry { Get-ExecutionPolicy -Scope UserPolicy }
    if ($machinePolicy -ne 'Undefined' -or $userPolicy -ne 'Undefined') {
        return [pscustomobject]@{ Ok = $true; Detail = "enforced by Group Policy (MachinePolicy=$machinePolicy, UserPolicy=$userPolicy), not something this script can or needs to change" }
    }
    $current = Invoke-WithTransientRetry { Get-ExecutionPolicy -Scope LocalMachine }
    [pscustomobject]@{ Ok = ($current -eq 'Unrestricted'); Detail = "LocalMachine execution policy is currently '$current'" }
} -Action {
    $machinePolicy = Invoke-WithTransientRetry { Get-ExecutionPolicy -Scope MachinePolicy }
    $userPolicy = Invoke-WithTransientRetry { Get-ExecutionPolicy -Scope UserPolicy }
    if ($machinePolicy -ne 'Undefined' -or $userPolicy -ne 'Undefined') {
        Write-Host "Execution policy is enforced by Group Policy (MachinePolicy=$machinePolicy, UserPolicy=$userPolicy) and cannot be changed by this script. This script itself already runs under an execution-policy bypass, so the rest of the bootstrap is unaffected. Skipping."
        return
    }

    if ((Invoke-WithTransientRetry { Get-ExecutionPolicy -Scope LocalMachine }) -eq 'Unrestricted') {
        Write-Host 'LocalMachine execution policy is already Unrestricted, skipping.'
        return
    }

    # On a freshly installed Windows image, the very first Set-ExecutionPolicy
    # call in a session can throw a generic "Security error." even though the
    # underlying registry write goes through (observed in practice, likely
    # Smart App Control still being in its initial post-install evaluation
    # window). Retry a couple of times before giving up.
    $maxAttempts = 3
    for ($attempt = 1; $attempt -le $maxAttempts; $attempt++) {
        try {
            Set-ExecutionPolicy -ExecutionPolicy Unrestricted -Scope LocalMachine -Force
            return
        }
        catch {
            if ((Invoke-WithTransientRetry { Get-ExecutionPolicy -Scope LocalMachine }) -eq 'Unrestricted') {
                # The write actually succeeded despite the exception.
                return
            }
            if ($attempt -eq $maxAttempts) {
                throw
            }
            Write-Host "Set-ExecutionPolicy attempt $attempt/$maxAttempts failed ($($_.Exception.Message)), retrying..."
            Start-Sleep -Seconds 2
        }
    }
}

# ----------------------------------------------------------------------------
# 6. Install root CA certificates
# ----------------------------------------------------------------------------

$rootCaResolved = Resolve-ConfigList -Config $Config -Key 'root_ca'
$rootCaDisabled = $rootCaResolved.Disabled
$rootCaEntries = $rootCaResolved.Items
if ($rootCaEntries.Count -eq 0) {
    Invoke-Step -Name 'Install root CA certificates' -SkipReason 'no root_ca entries configured' -Tag 'root_ca' -Action {}
}
else {
    foreach ($entry in $rootCaEntries) {
        $certName = Get-ConfigValue $entry @('name') 'unnamed'
        $install = Get-ConfigValue $entry @('install') $false
        $stepName = "Install root CA certificate '$certName'"

        $certSkip = if ($rootCaDisabled) {
            "'root_ca.disabled' is set to true"
        } elseif (-not $install) {
            "install: false for '$certName'"
        } else { $null }
        Invoke-Step -Name $stepName -SkipReason $certSkip -Tag 'root_ca' -Verify {
            $certText = Resolve-ConfigResource -InlineValue (Get-ConfigValue $entry @('cert')) `
                -PathValue (Get-ConfigValue $entry @('cert_path')) `
                -UrlValue (Get-ConfigValue $entry @('cert_url')) `
                -SecretIdValue (Get-ConfigValue $entry @('cert_secret_id')) `
                -Description "root_ca '$certName'"
            $tempCertPath = Join-Path $env:TEMP "$certName.verify.pem"
            Set-Content -Path $tempCertPath -Value $certText -Encoding ascii
            try {
                $installed = Test-TrustedRootCertificateInstalled -CertPath $tempCertPath
            }
            finally {
                Remove-Item -Path $tempCertPath -Force -ErrorAction SilentlyContinue
            }
            [pscustomobject]@{ Ok = $installed; Detail = "certificate '$certName' $(if ($installed) { 'is' } else { 'is not' }) present in Cert:\LocalMachine\Root" }
        } -Action {
            $certText = Resolve-ConfigResource -InlineValue (Get-ConfigValue $entry @('cert')) `
                -PathValue (Get-ConfigValue $entry @('cert_path')) `
                -UrlValue (Get-ConfigValue $entry @('cert_url')) `
                -SecretIdValue (Get-ConfigValue $entry @('cert_secret_id')) `
                -Description "root_ca '$certName'"

            $tempCertPath = Join-Path $env:TEMP "$certName.pem"
            Set-Content -Path $tempCertPath -Value $certText -Encoding ascii
            try {
                Install-TrustedRootCertificate -CertPath $tempCertPath -Name $certName
            }
            finally {
                Remove-Item -Path $tempCertPath -Force -ErrorAction SilentlyContinue
            }
        }
    }
}

# ----------------------------------------------------------------------------
# 7. Remove Recovery Partition (destructive, confirmation-gated) and extend
#    the system drive into the space it freed up.
# ----------------------------------------------------------------------------

$deleteRecoveryPartition = Get-ConfigValue $Config @('recovery_partition', 'delete') $false
$extendSystemDrive = Get-ConfigValue $Config @('recovery_partition', 'extend_system_drive') $false
$recoveryPartitionDisabled = Get-ConfigValue $Config @('recovery_partition', 'disabled') $false
$recoveryPartitionSkip = if ($recoveryPartitionDisabled) {
    "'recovery_partition.disabled' is set to true"
} elseif (-not $deleteRecoveryPartition) {
    "'recovery_partition.delete' is not set to true in config"
} else { $null }

Invoke-Step -Name 'Remove recovery partition and extend system drive' -SkipReason $recoveryPartitionSkip -Tag 'recovery_partition' -Verify {
    $recoveryPartition = Get-Partition | Where-Object { $_.Type -eq 'Recovery' }
    $systemDriveLetter = $env:SystemDrive.TrimEnd(':')
    $systemPartition = Get-Partition -DriveLetter $systemDriveLetter
    $sizeGb = [math]::Round($systemPartition.Size / 1GB, 1)
    $detail = "system drive $systemDriveLetter`: is currently $sizeGb GB"
    [pscustomobject]@{ Ok = (-not $recoveryPartition); Detail = "$detail; recovery partition $(if ($recoveryPartition) { 'is still present' } else { 'is absent' }) (extend_system_drive sizing outcome is not independently verified)" }
} -Action {
    $recoveryPartition = Get-Partition | Where-Object { $_.Type -eq 'Recovery' }

    if (-not $recoveryPartition) {
        Write-Host 'No recovery partition found, skipping.'
        return
    }

    $confirmMessage = 'This will permanently delete the Windows Recovery partition. This cannot be undone and disables "Reset this PC" from Windows RE.'
    if ($extendSystemDrive) {
        $confirmMessage += ' The freed space will be added to the system drive.'
    }
    $proceed = Confirm-RiskyAction -Message $confirmMessage
    if (-not $proceed) {
        Write-Host 'Skipped by user.'
        return
    }

    # Deregisters Windows RE (removes the BCD recovery-sequence entry that
    # points at this partition's winre.wim) BEFORE the partition itself is
    # removed - confirmed live: skipping this leaves Windows still
    # expecting a recovery partition to exist, and ANY later imperfect
    # shutdown (crash, hang, even a plain forced restart) makes the boot
    # manager try to launch recovery from the now-missing partition,
    # failing outright with "0xc0000225 - a required device isn't
    # connected or can't be accessed" instead of just booting normally.
    # reagentc exits non-zero if WinRE is already disabled/not configured -
    # not worth failing this whole step over, so its exit code is ignored.
    & reagentc /disable | Out-Null

    $systemDriveLetter = $env:SystemDrive.TrimEnd(':')
    $recoveryPartition | Remove-Partition -Confirm:$false
    $script:RebootRequired = $true

    if (-not $extendSystemDrive) {
        Write-Host "Recovery partition removed. 'recovery_partition.extend_system_drive' is not set to true in config, leaving the freed space unallocated."
        return
    }

    # Only works when the recovery partition was directly adjacent to the
    # system partition (the standard Windows layout), so the freed space is
    # contiguous with it and Resize-Partition can claim it.
    $supportedSize = Get-PartitionSupportedSize -DriveLetter $systemDriveLetter
    $systemPartition = Get-Partition -DriveLetter $systemDriveLetter

    if ($supportedSize.SizeMax -le $systemPartition.Size) {
        Write-Warning "Recovery partition removed, but no adjacent free space was found to extend $systemDriveLetter`: into (freed space may not be contiguous)."
        return
    }

    Resize-Partition -DriveLetter $systemDriveLetter -Size $supportedSize.SizeMax
    Write-Host "Extended $systemDriveLetter`: to $([math]::Round($supportedSize.SizeMax / 1GB, 1)) GB."
}

# ----------------------------------------------------------------------------
# 8. Disable Virtualization-Based Security (Core Isolation / Memory Integrity)
# ----------------------------------------------------------------------------

$vbsSkip = if (-not (Get-ConfigValue $Config @('disable_vbs') $false)) {
    "'disable_vbs' is not set to true in config"
} else { $null }

Invoke-Step -Name 'Disable Virtualization-Based Security (Core Isolation)' -SkipReason $vbsSkip -Tag 'vbs' -Verify {
    $keyProperties = @{
        'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard'                                          = @{
            'EnableVirtualizationBasedSecurity' = 0
            'RequirePlatformSecurityFeatures'   = 0
        }
        'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity' = @{
            'Enabled' = 0
        }
    }
    $mismatches = [System.Collections.Generic.List[string]]::new()
    foreach ($keyPath in $keyProperties.Keys) {
        $existing = Get-ItemProperty -Path $keyPath -ErrorAction SilentlyContinue
        foreach ($name in $keyProperties[$keyPath].Keys) {
            $desiredValue = $keyProperties[$keyPath][$name]
            $currentValue = if ($existing -and $existing.PSObject.Properties[$name]) { $existing.$name } else { $null }
            if ($currentValue -ne $desiredValue) {
                $mismatches.Add("$keyPath\$name = $currentValue (expected $desiredValue)")
            }
        }
    }
    [pscustomobject]@{ Ok = ($mismatches.Count -eq 0); Detail = if ($mismatches.Count -eq 0) { 'all VBS registry values already disabled' } else { "mismatched: $($mismatches -join '; ')" } }
} -Action {
    # Typically run inside a VM, where Windows running its own hypervisor
    # in-guest for VBS is pure double-virtualization overhead. Memory
    # Integrity alone (HypervisorEnforcedCodeIntegrity) isn't the whole
    # story - the DeviceGuard master switches below govern whether VBS is
    # used at all, e.g. by "Local Security Authority protection".
    $keyProperties = @{
        'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard'                                          = @{
            'EnableVirtualizationBasedSecurity' = 0
            'RequirePlatformSecurityFeatures'   = 0
        }
        'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity' = @{
            'Enabled' = 0
        }
    }

    $changed = $false
    foreach ($keyPath in $keyProperties.Keys) {
        if (-not (Test-Path $keyPath)) {
            New-Item -Path $keyPath -Force | Out-Null
        }
        # Get-ItemPropertyValue -Name throws "Property ... does not exist" as
        # a terminating error when the value is missing, even with
        # -ErrorAction SilentlyContinue - so check existence explicitly
        # instead of relying on ErrorAction to suppress that.
        $existing = Get-ItemProperty -Path $keyPath -ErrorAction SilentlyContinue
        foreach ($name in $keyProperties[$keyPath].Keys) {
            $desiredValue = $keyProperties[$keyPath][$name]
            $currentValue = if ($existing -and $existing.PSObject.Properties[$name]) { $existing.$name } else { $null }
            if ($currentValue -ne $desiredValue) {
                Set-ItemProperty -Path $keyPath -Name $name -Value $desiredValue -Type DWord
                $changed = $true
            }
        }
    }

    if (-not $changed) {
        Write-Host 'Virtualization-Based Security is already disabled, skipping.'
        return
    }

    $script:RebootRequired = $true
    Write-Host 'Virtualization-Based Security disabled via registry. If Windows Security still shows features as On after reboot, they were likely enabled with a UEFI lock and need the Microsoft DG_Readiness_Tool (or a fresh VM image) to fully clear - verify with: Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard'
}

# ----------------------------------------------------------------------------
# 9. Remove OneDrive
# ----------------------------------------------------------------------------

$oneDriveSkip = if (-not (Get-ConfigValue $Config @('remove_onedrive') $false)) {
    "'remove_onedrive' is not set to true in config"
} else { $null }

Invoke-Step -Name 'Remove OneDrive' -SkipReason $oneDriveSkip -Tag 'onedrive' -Verify {
    $process = Get-Process -Name 'OneDrive' -ErrorAction SilentlyContinue
    $exePath = Join-Path $env:LOCALAPPDATA 'Microsoft\OneDrive\OneDrive.exe'
    $stillInstalled = $process -or (Test-Path $exePath)
    $policyValue = Get-ItemPropertyValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive' -Name 'DisableFileSyncNGSC' -ErrorAction SilentlyContinue
    $policySet = ($policyValue -eq 1)
    [pscustomobject]@{
        Ok     = (-not $stillInstalled) -and $policySet
        Detail = "current-user OneDrive $(if ($stillInstalled) { 'still appears present' } else { 'absent' }) (process running: $([bool]$process), exe at '$exePath': $(Test-Path $exePath)); machine policy DisableFileSyncNGSC=$(if ($null -eq $policyValue) { '<unset>' } else { $policyValue }) ($(if ($policySet) { 'blocks future accounts' } else { 'future accounts would still get OneDrive provisioned' }))"
    }
} -Action {
    $uninstallerCandidates = @(
        (Join-Path $env:SystemRoot 'SysWOW64\OneDriveSetup.exe'),
        (Join-Path $env:SystemRoot 'System32\OneDriveSetup.exe')
    )
    $uninstaller = $uninstallerCandidates | Where-Object { Test-Path $_ } | Select-Object -First 1

    if ($uninstaller) {
        Get-Process -Name 'OneDrive' -ErrorAction SilentlyContinue | Stop-Process -Force
        Start-Process -FilePath $uninstaller -ArgumentList '/uninstall' -Wait

        # -Force on Get-ChildItem is required here, not just on Remove-Item:
        # without it, a hidden/system-attributed leftover like desktop.ini
        # (which Windows auto-creates in this folder) is invisible to the
        # emptiness check, so it wrongly looks empty - then Remove-Item (no
        # -Recurse) hits a real non-empty directory and pops an interactive
        # "Confirm"/"has children" prompt instead of failing quietly
        # (confirmed live: exactly this happened on a second run).
        $leftoverFolder = Join-Path $env:USERPROFILE 'OneDrive'
        $leftoverContents = Get-ChildItem -Path $leftoverFolder -Force -ErrorAction SilentlyContinue | Where-Object { $_.Name -ne 'desktop.ini' }
        if ((Test-Path $leftoverFolder) -and -not $leftoverContents) {
            Remove-Item -Path $leftoverFolder -Recurse -Force -Confirm:$false -ErrorAction SilentlyContinue
        }
    } else {
        Write-Host 'OneDrive uninstaller not found, assuming OneDrive is not installed for this account.'
    }

    # Machine-wide Group Policy equivalent of "Prevent the usage of OneDrive
    # for file storage" - without this, uninstalling OneDrive above only
    # affects the current user; Windows still auto-runs OneDriveSetup.exe at
    # first logon for every NEW account regardless (confirmed live: a
    # local_users account created after this step still got OneDrive
    # provisioned). This blocks it at the source for every future account
    # too, not just cleans up after the fact for the current one.
    $policyPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive'
    if (-not (Test-Path $policyPath)) {
        New-Item -Path $policyPath -Force | Out-Null
    }
    Set-ItemProperty -Path $policyPath -Name 'DisableFileSyncNGSC' -Value 1 -Type DWord
}

# ----------------------------------------------------------------------------
# 10. Remove Microsoft Teams
# ----------------------------------------------------------------------------

$teamsSkip = if (-not (Get-ConfigValue $Config @('remove_teams') $false)) {
    "'remove_teams' is not set to true in config"
} else { $null }

Invoke-Step -Name 'Remove Microsoft Teams' -SkipReason $teamsSkip -Tag 'teams' -Verify {
    $provisioned = Get-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -like '*Teams*' }
    $installed = Get-AppxPackage -AllUsers -Name '*Teams*' -ErrorAction SilentlyContinue
    $machineWideInstaller = Get-Package -Name 'Teams Machine-Wide Installer' -ErrorAction SilentlyContinue
    $stillInstalled = $provisioned -or $installed -or $machineWideInstaller
    [pscustomobject]@{
        Ok     = (-not $stillInstalled)
        Detail = if ($stillInstalled) { "Teams still appears present (provisioned: $([bool]$provisioned), per-user package: $([bool]$installed), machine-wide installer: $([bool]$machineWideInstaller))" } else { 'no Teams AppX package, provisioned package, or machine-wide installer found' }
    }
} -Action {
    $provisioned = Get-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -like '*Teams*' }
    foreach ($p in $provisioned) {
        Remove-AppxProvisionedPackage -Online -PackageName $p.PackageName -ErrorAction SilentlyContinue | Out-Null
    }

    $installed = Get-AppxPackage -AllUsers -Name '*Teams*' -ErrorAction SilentlyContinue
    foreach ($p in $installed) {
        Remove-AppxPackage -Package $p.PackageFullName -AllUsers -ErrorAction SilentlyContinue
    }

    $machineWideInstaller = Get-Package -Name 'Teams Machine-Wide Installer' -ErrorAction SilentlyContinue
    if ($machineWideInstaller) {
        $machineWideInstaller | Uninstall-Package -Force -ErrorAction SilentlyContinue | Out-Null
    }

    if (-not $provisioned -and -not $installed -and -not $machineWideInstaller) {
        Write-Host 'No Teams installation found, nothing to remove.'
    }

    # Classic Teams' own per-user updater normally cleans this up; only
    # remove if left behind empty (ignoring desktop.ini, an OS-generated
    # artifact, not user data), same caution and the same -Force/-Recurse
    # requirement as OneDrive's leftover-folder cleanup above.
    $leftoverFolder = Join-Path $env:LOCALAPPDATA 'Microsoft\Teams'
    $leftoverContents = Get-ChildItem -Path $leftoverFolder -Force -ErrorAction SilentlyContinue | Where-Object { $_.Name -ne 'desktop.ini' }
    if ((Test-Path $leftoverFolder) -and -not $leftoverContents) {
        Remove-Item -Path $leftoverFolder -Recurse -Force -Confirm:$false -ErrorAction SilentlyContinue
    }
}

# ----------------------------------------------------------------------------
# 11. Remove Outlook (new)
# ----------------------------------------------------------------------------

$outlookSkip = if (-not (Get-ConfigValue $Config @('remove_outlook') $false)) {
    "'remove_outlook' is not set to true in config"
} else { $null }

Invoke-Step -Name 'Remove Outlook (new)' -SkipReason $outlookSkip -Tag 'outlook' -Verify {
    # Exact match, not a wildcard like Teams' '*Teams*' - "new" Outlook for
    # Windows has one well-known package ID, and a wildcard here risks
    # matching unrelated things (e.g. classic desktop Outlook's own COM/Office
    # registrations, which this step doesn't touch and isn't equipped to).
    $provisioned = Get-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -eq 'Microsoft.OutlookForWindows' }
    $installed = Get-AppxPackage -AllUsers -Name 'Microsoft.OutlookForWindows' -ErrorAction SilentlyContinue
    $stillInstalled = $provisioned -or $installed
    [pscustomobject]@{
        Ok     = (-not $stillInstalled)
        Detail = if ($stillInstalled) { "Outlook (new) still appears present (provisioned: $([bool]$provisioned), per-user package: $([bool]$installed))" } else { 'no Microsoft.OutlookForWindows AppX package or provisioned package found' }
    }
} -Action {
    # Provisioned removal matters here exactly like it did for Teams -
    # confirmed live that Microsoft.OutlookForWindows is provisioned
    # machine-wide on a stock Windows 11 image, so skipping this half would
    # leave it reappearing for every new local_users account.
    $provisioned = Get-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -eq 'Microsoft.OutlookForWindows' }
    foreach ($p in $provisioned) {
        Remove-AppxProvisionedPackage -Online -PackageName $p.PackageName -ErrorAction SilentlyContinue | Out-Null
    }

    $installed = Get-AppxPackage -AllUsers -Name 'Microsoft.OutlookForWindows' -ErrorAction SilentlyContinue
    foreach ($p in $installed) {
        Remove-AppxPackage -Package $p.PackageFullName -AllUsers -ErrorAction SilentlyContinue
    }

    if (-not $provisioned -and -not $installed) {
        Write-Host 'No Outlook (new) installation found, nothing to remove.'
    }
}

# ----------------------------------------------------------------------------
# 12. Defender exclusions
# ----------------------------------------------------------------------------

$defenderExclusionsResolved = Resolve-ConfigList -Config $Config -Key 'defender_exclusions'
$defenderExclusionsDisabled = $defenderExclusionsResolved.Disabled
$defenderExclusions = $defenderExclusionsResolved.Items
if ($defenderExclusions.Count -eq 0) {
    Invoke-Step -Name 'Configure Defender exclusions' -SkipReason 'no defender_exclusions configured' -Tag 'defender' -Action {}
}
else {
    foreach ($exclusion in $defenderExclusions) {
        $exclusionPath = Get-ConfigValue $exclusion @('path')
        $createIfMissing = Get-ConfigValue $exclusion @('create') $false
        $exclusionDisabled = Get-ConfigValue $exclusion @('disabled') $false
        $exclusionSkip = if ($defenderExclusionsDisabled) {
            "'defender_exclusions.disabled' is set to true"
        } elseif ($exclusionDisabled) {
            "'disabled: true' for '$exclusionPath'"
        } else { $null }

        Invoke-Step -Name "Add Defender exclusion for $exclusionPath" -SkipReason $exclusionSkip -Tag 'defender' -Verify {
            $pathExists = Test-Path $exclusionPath
            $excluded = ((Get-MpPreference).ExclusionPath) -contains $exclusionPath
            [pscustomobject]@{ Ok = ($pathExists -and $excluded); Detail = "path exists: $pathExists; already excluded in Defender: $excluded" }
        } -Action {
            if (-not (Test-Path $exclusionPath)) {
                if ($createIfMissing) {
                    New-Item -Path $exclusionPath -ItemType Directory -Force | Out-Null
                }
                else {
                    Write-Warning "Path '$exclusionPath' does not exist and 'create' is not set to true; skipping this exclusion."
                    return
                }
            }

            $existingExclusions = (Get-MpPreference).ExclusionPath
            if ($existingExclusions -notcontains $exclusionPath) {
                Add-MpPreference -ExclusionPath $exclusionPath
            }
        }
    }
}

# ----------------------------------------------------------------------------
# 13. Set UAC level
# ----------------------------------------------------------------------------

$uacLevel = Get-ConfigValue $Config @('uac_level')
$uacSkip = if (-not $uacLevel) { "no 'uac_level' configured" } else { $null }

Invoke-Step -Name 'Set UAC level' -SkipReason $uacSkip -Tag 'uac' -Verify {
    if ($uacLevel -notin $script:ValidUacLevels) {
        throw "Invalid uac_level '$uacLevel' - must be one of: $($script:ValidUacLevels -join ', ')."
    }
    $keyPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
    $existing = Get-ItemProperty -Path $keyPath -ErrorAction SilentlyContinue
    $currentLUA = if ($existing -and $existing.PSObject.Properties['EnableLUA']) { $existing.EnableLUA } else { $null }

    if ($uacLevel -eq 'off') {
        [pscustomobject]@{ Ok = ($currentLUA -eq 0); Detail = if ($currentLUA -eq 0) { 'UAC already off' } else { "EnableLUA = $currentLUA (expected 0)" } }
    } else {
        $desiredMap = @{
            never_notify  = @{ ConsentPromptBehaviorAdmin = 0; PromptOnSecureDesktop = 0 }
            default       = @{ ConsentPromptBehaviorAdmin = 5; PromptOnSecureDesktop = 1 }
            always_notify = @{ ConsentPromptBehaviorAdmin = 2; PromptOnSecureDesktop = 1 }
        }
        $desired = $desiredMap[$uacLevel] + @{ EnableLUA = 1 }
        $mismatches = [System.Collections.Generic.List[string]]::new()
        foreach ($name in $desired.Keys) {
            $currentValue = if ($existing -and $existing.PSObject.Properties[$name]) { $existing.$name } else { $null }
            if ($currentValue -ne $desired[$name]) {
                $mismatches.Add("$name = $currentValue (expected $($desired[$name]))")
            }
        }
        [pscustomobject]@{ Ok = ($mismatches.Count -eq 0); Detail = if ($mismatches.Count -eq 0) { "UAC already at level '$uacLevel'" } else { "mismatched: $($mismatches -join '; ')" } }
    }
} -Action {
    if ($uacLevel -notin $script:ValidUacLevels) {
        throw "Invalid uac_level '$uacLevel' - must be one of: $($script:ValidUacLevels -join ', ')."
    }
    $keyPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
    if ($uacLevel -eq 'off') {
        Set-ItemProperty -Path $keyPath -Name 'EnableLUA' -Value 0 -Type DWord
        Write-Warning "UAC set to 'off' (EnableLUA=0) - this requires a reboot to fully take effect."
    } else {
        $desiredMap = @{
            never_notify  = @{ ConsentPromptBehaviorAdmin = 0; PromptOnSecureDesktop = 0 }
            default       = @{ ConsentPromptBehaviorAdmin = 5; PromptOnSecureDesktop = 1 }
            always_notify = @{ ConsentPromptBehaviorAdmin = 2; PromptOnSecureDesktop = 1 }
        }
        $desired = $desiredMap[$uacLevel] + @{ EnableLUA = 1 }
        foreach ($name in $desired.Keys) {
            Set-ItemProperty -Path $keyPath -Name $name -Value $desired[$name] -Type DWord
        }
    }
}

# ----------------------------------------------------------------------------
# 14. Install apps via winget
# ----------------------------------------------------------------------------

$appsResolved = Resolve-ConfigList -Config $Config -Key 'apps'
$appsDisabled = $appsResolved.Disabled
$apps = $appsResolved.Items
$deleteBootstrapUserForApps = Get-ConfigValue $Config @('delete_bootstrap_user') $false
if ($apps.Count -eq 0) {
    Invoke-Step -Name 'Install apps' -SkipReason 'no apps configured' -Tag 'apps' -Action {}
}
else {
    foreach ($package in $apps) {
        $packageId = Get-ConfigValue $package @('id')
        $packageScope = Get-ConfigValue $package @('scope') 'machine'
        $packagePlatforms = Get-ConfigValue $package @('platforms') @()
        $packageArchitecture = Get-ConfigValue $package @('architecture')
        $packageInstallerType = Get-ConfigValue $package @('installer_type')
        $packageDisabled = Get-ConfigValue $package @('disabled') $false
        $packageDesktopShortcut = Get-ConfigValue $package @('desktop_shortcut') $false

        $packageSkip = if ($appsDisabled) {
            "'apps.disabled' is set to true"
        } elseif ($packageDisabled) {
            "'disabled: true' for '$packageId'"
        } elseif ($packagePlatforms.Count -gt 0 -and ($packagePlatforms -notcontains $Arch)) {
            "not applicable to architecture '$Arch' (platforms: $($packagePlatforms -join ', '))"
        } elseif ($packageScope -eq 'user' -and $deleteBootstrapUserForApps) {
            "scope: user - skipped because 'delete_bootstrap_user' is set to true (this account is about to be deleted)"
        } else { $null }

        Invoke-Step -Name "Install $packageId" -SkipReason $packageSkip -Tag 'apps' -Verify {
            $installed = Test-WingetPackageInstalled -Id $packageId
            [pscustomobject]@{ Ok = $installed; Detail = "'$packageId' is $(if ($installed) { 'already' } else { 'not' }) installed" }
        } -Action {
            # Some installers (confirmed live: Ghisler.TotalCommander's
            # classic EXE installer) drop Start Menu shortcuts under the
            # CURRENT user's per-user Programs folder regardless of
            # --scope machine, even though the program files themselves
            # correctly go machine-wide - winget's scope only controls how
            # the installer is invoked, not where that installer decides
            # to put shortcuts. For scope: machine packages, copy any
            # shortcut/folder that appears there into the shared all-users
            # Start Menu, so accounts other than whoever ran bootstrap can
            # see it too.
            $userStartMenu = [Environment]::GetFolderPath('Programs')
            $userDesktop = [Environment]::GetFolderPath('Desktop')
            # Confirmed live on PowerShell 5.1 with Set-StrictMode -Version
            # Latest (both in effect for this script): '$x = if (cond) {
            # @(possibly-empty-pipeline) } else { @() }' can evaluate to
            # $null instead of an empty array when the pipeline produces
            # zero objects (e.g. a genuinely empty Desktop) - silently
            # breaking Resolve-DesktopShortcutSourceWithRetry's Mandatory
            # parameter binding below. Initializing to @() first and only
            # conditionally overwriting avoids the if-expression-as-
            # assignment shape that triggers it.
            $startMenuBefore = @()
            if ($packageScope -eq 'machine' -and (Test-Path $userStartMenu)) {
                $startMenuBefore = @(Get-ChildItem -Path $userStartMenu -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name)
            }
            $desktopBefore = @()
            if ($packageScope -eq 'machine' -and $packageDesktopShortcut -and (Test-Path $userDesktop)) {
                $desktopBefore = @(Get-ChildItem -Path $userDesktop -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name)
            }

            Install-WingetPackage -Id $packageId -Scope $packageScope -Architecture $packageArchitecture -InstallerType $packageInstallerType

            if ($packageScope -eq 'machine' -and (Test-Path $userStartMenu)) {
                $commonStartMenu = [Environment]::GetFolderPath('CommonPrograms')
                Get-ChildItem -Path $userStartMenu -ErrorAction SilentlyContinue | Where-Object { $startMenuBefore -notcontains $_.Name } | ForEach-Object {
                    $destPath = Join-Path $commonStartMenu $_.Name
                    if (-not (Test-Path $destPath)) {
                        Copy-Item -Path $_.FullName -Destination $destPath -Recurse -Force
                        Write-Host "Copied new Start Menu item '$($_.Name)' to the shared all-users Start Menu."
                    }
                }

                if ($packageDesktopShortcut) {
                    $resolved = Resolve-DesktopShortcutSourceWithRetry -DesktopBefore $desktopBefore -DesktopPath $userDesktop -StartMenuBefore $startMenuBefore -StartMenuPath $userStartMenu
                    if ($resolved.Warning) {
                        Write-Warning "'$packageId': $($resolved.Warning)"
                    }
                    $commonDesktop = [Environment]::GetFolderPath('CommonDesktopDirectory')
                    foreach ($item in $resolved.Items) {
                        $desktopDestPath = Join-Path $commonDesktop $item.Name
                        if (-not (Test-Path $desktopDestPath)) {
                            Copy-Item -Path $item.FullName -Destination $desktopDestPath -Recurse -Force
                            Write-Host "Copied '$($item.Name)' to the shared all-users desktop."
                        }
                    }
                }
            }
        }
    }
}

# ----------------------------------------------------------------------------
# 15. Install PowerShell 7 (dedicated step, separate from the generic apps
#     list - both windows_terminal.default_profile: pwsh7 and
#     ssh_server.default_shell: pwsh7 depend on it, so it's installed here
#     on their behalf if it wasn't already requested directly. Any
#     install_powershell7: false conflict with those was already caught by
#     Assert-ConfigNoConflicts above, before any step ran - by this point
#     it's a plain skip-or-install.
# ----------------------------------------------------------------------------

$installPowershell7 = if ($null -ne $installPowershell7Config) {
    $installPowershell7Config
}
else {
    $powershell7Dependents.Count -gt 0
}
$installPowershell7Skip = if (-not $installPowershell7) {
    "'install_powershell7' is not set to true and nothing else requires it"
} else { $null }

Invoke-Step -Name 'Install PowerShell 7' -SkipReason $installPowershell7Skip -Tag 'powershell7' -Verify {
    $installed = Test-WingetPackageInstalled -Id 'Microsoft.PowerShell'
    [pscustomobject]@{ Ok = $installed; Detail = "'Microsoft.PowerShell' is $(if ($installed) { 'already' } else { 'not' }) installed" }
} -Action {
    # Always the native MSI build (winget installer type "wix", not the
    # default MSIX/Store one) - required for ssh_server.default_shell:
    # pwsh7 to work at all (see Resolve-ShellExecutablePath), and there's
    # no reason to prefer MSIX for the Windows Terminal profile case
    # either. Note: winget will NOT switch an already-installed package to
    # a different installer type (confirmed: it treats it as an upgrade
    # check and reports "No available upgrade found") - if PowerShell 7 is
    # already installed via MSIX, this step's Install-WingetPackage call
    # will just report it as already installed and do nothing; uninstall
    # it first (winget uninstall --id Microsoft.PowerShell --source winget)
    # and re-run this script to switch to the native build.
    Install-WingetPackage -Id 'Microsoft.PowerShell' -Scope 'machine' -InstallerType 'wix'
}

# ----------------------------------------------------------------------------
# 16. Install Windows Terminal (mirrors "Install PowerShell 7" above -
#     windows_terminal.default_profile depends on Terminal actually being
#     installed; the default MSIX/Store build is exactly what's wanted
#     here, unlike PowerShell 7's OpenSSH-driven need for a native MSI).
# ----------------------------------------------------------------------------

$windowsTerminalEnabled = Get-ConfigValue $Config @('windows_terminal', 'enable') $false
$windowsTerminalDesktopShortcut = Get-ConfigValue $Config @('windows_terminal', 'desktop_shortcut') $false
$windowsTerminalShortcutPath = Join-Path ([Environment]::GetFolderPath('CommonDesktopDirectory')) 'Windows Terminal.lnk'
$windowsTerminalSkip = if (-not $windowsTerminalEnabled) {
    "'windows_terminal.enable' is not set to true"
} else { $null }

Invoke-Step -Name 'Install Windows Terminal' -SkipReason $windowsTerminalSkip -Tag 'windows_terminal' -Verify {
    $installed = Test-WingetPackageInstalled -Id 'Microsoft.WindowsTerminal'
    # Also verified here (not just installed-ness) so that turning on
    # 'desktop_shortcut: true' on a machine where Terminal is already
    # installed still creates it, instead of Invoke-Step skipping the
    # whole step because the package alone already satisfies Ok.
    $shortcutOk = -not $windowsTerminalDesktopShortcut -or (Test-Path $windowsTerminalShortcutPath)
    [pscustomobject]@{
        Ok     = $installed -and $shortcutOk
        Detail = "'Microsoft.WindowsTerminal' is $(if ($installed) { 'already' } else { 'not' }) installed" + $(if ($windowsTerminalDesktopShortcut) { "; desktop shortcut is $(if ($shortcutOk) { 'present' } else { 'missing' })" } else { '' })
    }
} -Action {
    Install-WingetPackage -Id 'Microsoft.WindowsTerminal' -Scope 'machine'
    if ($windowsTerminalDesktopShortcut -and -not (Test-Path $windowsTerminalShortcutPath)) {
        # Windows Terminal is an MSIX/Store package - it doesn't drop a
        # physical .lnk into any Start Menu folder the way classic
        # installers do (see the Start Menu diff/copy in the 'apps' step
        # above), so a UWP app needs the shell:AppsFolder approach
        # instead, pointed at Terminal's stable AppUserModelID (same
        # package identity already used below for its settings.json
        # path). TargetPath must be the shell:AppsFolder path ITSELF, not
        # explorer.exe with it passed as -Arguments - confirmed live: the
        # explorer.exe + Arguments form still launches fine but shows a
        # generic icon, while TargetPath = shell:AppsFolder\... lets
        # Windows resolve the real app icon on its own. Reading
        # TargetPath back via WScript.Shell afterwards shows blank - a
        # known COM introspection quirk, not a sign the shortcut is
        # broken (confirmed live: it still launches WindowsTerminal.exe
        # correctly, including from a different account than the one
        # that ran the install).
        $shell = New-Object -ComObject WScript.Shell
        $shortcut = $shell.CreateShortcut($windowsTerminalShortcutPath)
        $shortcut.TargetPath = 'shell:AppsFolder\Microsoft.WindowsTerminal_8wekyb3d8bbwe!App'
        $shortcut.Save()
        Write-Host "Created desktop shortcut for Windows Terminal at '$windowsTerminalShortcutPath'."
    }
}

# ----------------------------------------------------------------------------
# 17. Set the default profile in Windows Terminal (cmd / pwsh5 / pwsh7)
# ----------------------------------------------------------------------------

$defaultProfile = Get-ConfigValue $Config @('windows_terminal', 'default_profile')
# Same package family for both the inbox/Store build and the winget-installed
# one, so this path is correct either way.
$windowsTerminalSettingsPath = Join-Path $env:LOCALAPPDATA 'Packages\Microsoft.WindowsTerminal_8wekyb3d8bbwe\LocalState\settings.json'
$defaultProfileSkip = if (-not $windowsTerminalEnabled) {
    "'windows_terminal.enable' is not set to true"
} elseif (-not $defaultProfile) {
    "no 'windows_terminal.default_profile' configured"
} elseif (-not (Test-Path $windowsTerminalSettingsPath)) {
    'Windows Terminal settings.json not found (Terminal may need to run once to create it)'
} else { $null }

Invoke-Step -Name 'Set default Windows Terminal profile' -SkipReason $defaultProfileSkip -Tag 'windows_terminal' -Verify {
    $profileGuid = switch ($defaultProfile) {
        'cmd' { $CmdTerminalProfileGuid }
        'pwsh5' { $Pwsh5TerminalProfileGuid }
        'pwsh7' { $PowerShell7TerminalProfileGuid }
    }
    $settingsText = Get-Content -Path $windowsTerminalSettingsPath -Raw
    $matches = $settingsText -match "`"defaultProfile`"\s*:\s*`"$([regex]::Escape($profileGuid))`""
    [pscustomobject]@{ Ok = $matches; Detail = "settings.json defaultProfile $(if ($matches) { 'already matches' } else { 'does not match' }) '$defaultProfile' ($profileGuid)" }
} -Action {
    try {
        $shellPath = Resolve-ShellExecutablePath -Shell $defaultProfile
    }
    catch {
        Write-Warning "Could not resolve '$defaultProfile'; skipping default Windows Terminal profile change. ($($_.Exception.Message))"
        return
    }

    $profileGuid = switch ($defaultProfile) {
        'cmd' { $CmdTerminalProfileGuid }
        'pwsh5' { $Pwsh5TerminalProfileGuid }
        'pwsh7' { $PowerShell7TerminalProfileGuid }
    }

    if ($defaultProfile -eq 'pwsh7') {
        # winget-installed PowerShell 7 does not reliably register its own
        # Windows Terminal fragment (a documented issue - see
        # https://github.com/microsoft/terminal/issues/18618), so this writes
        # the fragment itself instead of depending on PowerShell's installer to
        # do it. https://learn.microsoft.com/en-us/windows/terminal/json-fragment-extensions
        # cmd/pwsh5 don't need this - they're Windows Terminal's own built-in
        # dynamic profiles, already present once Terminal has run once.
        $fragmentDir = 'C:\ProgramData\Microsoft\Windows Terminal\Fragments\Bootstrap.PowerShell7'
        if (-not (Test-Path $fragmentDir)) {
            New-Item -Path $fragmentDir -ItemType Directory -Force | Out-Null
        }
        $fragmentContent = @{
            profiles = @(
                @{
                    guid        = $profileGuid
                    name        = 'PowerShell 7'
                    commandline = $shellPath
                }
            )
        } | ConvertTo-Json -Depth 4
        Set-Content -Path (Join-Path $fragmentDir 'pwsh.json') -Value $fragmentContent -Encoding utf8
    }

    $settingsText = Get-Content -Path $windowsTerminalSettingsPath -Raw
    if ($settingsText -match '"defaultProfile"\s*:\s*"\{[0-9a-fA-F-]+\}"') {
        $settingsText = $settingsText -replace '"defaultProfile"\s*:\s*"\{[0-9a-fA-F-]+\}"', "`"defaultProfile`": `"$profileGuid`""
    }
    else {
        $firstBraceIndex = $settingsText.IndexOf('{')
        if ($firstBraceIndex -lt 0) {
            throw 'settings.json does not look like valid JSON (no opening brace found).'
        }
        $settingsText = $settingsText.Insert($firstBraceIndex + 1, "`n    `"defaultProfile`": `"$profileGuid`",")
    }

    Set-Content -Path $windowsTerminalSettingsPath -Value $settingsText -Encoding utf8
    Write-Host "Default Windows Terminal profile set to $defaultProfile ($profileGuid)."
}

# ----------------------------------------------------------------------------
# 18. Enable OpenSSH Server and allow key-based login
# ----------------------------------------------------------------------------

$sshServerEnabled = Get-ConfigValue $Config @('ssh_server', 'enable') $false
$sshServerSkip = if (-not $sshServerEnabled) { "'ssh_server.enable' is not set to true in config" } else { $null }

# A plain `Restart-Service -Name sshd` deadlocks when this script is itself
# running inside an SSH session that sshd is serving: the service can't
# finish stopping while this session (a child of sshd) is still alive, and
# this session is blocked waiting for Restart-Service to return. A detached
# child process (Start-Process) doesn't escape this either - Windows OpenSSH
# puts every process spawned for a session into a job object that gets
# killed the moment the session closes, before a short delay could elapse.
# A Scheduled Task's process is launched by the Task Scheduler service
# instead, entirely outside that job object, so it survives this session
# ending - confirmed live on windev (2026-07-31), including against the
# deadlock this replaced. $env:SSH_CONNECTION/$env:SSH_CLIENT are set by
# Windows OpenSSH for every session it spawns, confirmed live the same way.
#
# Restarting sshd this way still kills the *current* SSH session a few
# seconds later, once the scheduled restart actually fires - confirmed live
# the same day: a restart issued mid-run (right after one host key step)
# took down the very session still running the rest of this script,
# silently aborting every step after it. So individual steps only request a
# restart (Request-SshdRestart, sets $script:SshdRestartNeeded) instead of
# triggering one immediately; the real restart happens exactly once, via
# Invoke-SshdRestart at the very end of the script (see Summary section)
# once nothing else is left to run.
function Request-SshdRestart {
    $svc = Get-Service -Name sshd -ErrorAction SilentlyContinue
    if ($svc -and $svc.Status -eq 'Running') {
        $script:SshdRestartNeeded = $true
    }
}

function Invoke-SshdRestart {
    $svc = Get-Service -Name sshd -ErrorAction SilentlyContinue
    if (-not $svc -or $svc.Status -ne 'Running') {
        return
    }
    if (-not ($env:SSH_CONNECTION -or $env:SSH_CLIENT)) {
        Restart-Service -Name sshd
        return
    }

    $taskName = "win-bootstrap-sshd-restart-$([guid]::NewGuid().ToString('N').Substring(0, 8))"
    $restartCommand = "Start-Sleep -Seconds 3; Restart-Service -Name sshd -Force; schtasks.exe /Delete /F /TN `"$taskName`""
    $encodedCommand = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($restartCommand))
    $action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "-NoProfile -EncodedCommand $encodedCommand"
    $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
    $trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddSeconds(1)
    Register-ScheduledTask -TaskName $taskName -Action $action -Principal $principal -Trigger $trigger -Force | Out-Null
    Start-ScheduledTask -TaskName $taskName
    Write-Host "sshd restart deferred via a one-shot scheduled task (this script is running over an SSH session served by sshd itself - restarting synchronously here would deadlock); sshd will restart within a few seconds after this session ends."
}

Invoke-Step -Name 'Enable OpenSSH Server' -SkipReason $sshServerSkip -Tag 'ssh' -Verify {
    $packageInstalled = Test-WingetPackageInstalled -Id 'Microsoft.OpenSSH.Preview'
    $service = Get-Service -Name sshd -ErrorAction SilentlyContinue
    $serviceOk = $service -and $service.Status -eq 'Running' -and $service.StartType -eq 'Automatic'
    $rule = Get-NetFirewallRule -Name 'OpenSSH-Server-In-TCP' -ErrorAction SilentlyContinue
    $ruleOk = $rule -and $rule.Enabled -eq 'True'
    $ok = $packageInstalled -and $serviceOk -and $ruleOk
    [pscustomobject]@{ Ok = $ok; Detail = "package installed: $packageInstalled; sshd running+automatic: $serviceOk; firewall rule enabled: $ruleOk" }
} -Action {
    # The in-box OpenSSH.Server Feature-on-Demand is notoriously slow: Add-
    # WindowsCapability -Online fetches it from Windows Update, commonly
    # 10-20 minutes on a fresh VM. Microsoft.OpenSSH.Preview installs the same
    # upstream Win32-OpenSSH project via a local MSI in seconds instead -
    # "Preview" is just its release channel name, not an indicator it's unstable.
    if (-not (Test-WingetPackageInstalled -Id 'Microsoft.OpenSSH.Preview')) {
        & winget install -e --id Microsoft.OpenSSH.Preview --source winget `
            --accept-package-agreements --accept-source-agreements `
            --override 'ADDLOCAL=Server /qn /norestart'
        if ($LASTEXITCODE -ne 0 -and -not (Test-WingetAlreadyInstalledExitCode -ExitCode $LASTEXITCODE)) {
            throw "winget exited with code $LASTEXITCODE installing Microsoft.OpenSSH.Preview"
        }
    }

    Set-Service -Name sshd -StartupType Automatic
    if ((Get-Service -Name sshd).Status -ne 'Running') {
        Start-Service -Name sshd
    }

    if (-not (Get-NetFirewallRule -Name 'OpenSSH-Server-In-TCP' -ErrorAction SilentlyContinue)) {
        New-NetFirewallRule -Name 'OpenSSH-Server-In-TCP' -DisplayName 'OpenSSH Server (sshd)' `
            -Enabled True -Direction Inbound -Protocol TCP -Action Allow -LocalPort 22 | Out-Null
    }
}

# Win32-OpenSSH's own default sshd_config ships "Subsystem sftp
# sftp-server.exe" - a bare, relative executable name. That resolves fine
# via sshd's own internal lookup (relative to its own install directory)
# as long as no DefaultShell override is set, but once
# ssh_server.default_shell (below) configures one, ALL command execution -
# including subsystem/exec requests used by sftp/scp - gets routed through
# that shell instead. Confirmed live: sftp/scp then fail with "Connection
# closed" (the subsystem process starts, then exits immediately with
# status 1, before any SFTP protocol bytes are sent) - PowerShell can't
# resolve a bare .exe name that isn't on PATH. Just fully-qualifying the
# path isn't enough either: "C:\Program Files\OpenSSH\sftp-server.exe"
# passed bare to `pwsh.exe -Command <string>` gets word-split on the space
# in "Program Files", so PowerShell tries to run "C:\Program" as the
# command - same failure. Wrapping it as a call-operator expression
# (`& 'C:\Program Files\...\sftp-server.exe'`) makes PowerShell treat the
# whole quoted string as one command again - confirmed live with a full
# sftp session (pwd/ls/get/rm) and a real scp upload, both succeeding.
# This is correct regardless of whether default_shell is set, so it's
# always applied as part of enabling the server, not gated on that
# setting.
Invoke-Step -Name 'Fix SFTP subsystem path in sshd_config' -SkipReason $sshServerSkip -Tag 'ssh' -Verify {
    $sshdImagePath = (Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\sshd').ImagePath.Trim('"')
    $sftpServerPath = Join-Path (Split-Path $sshdImagePath -Parent) 'sftp-server.exe'
    if (-not (Test-Path $sftpServerPath)) {
        throw "sftp-server.exe not found at expected path '$sftpServerPath' (derived from the sshd service's own binary path)."
    }
    $desiredCommand = "& '$sftpServerPath'"
    $sshdConfigPath = Join-Path $env:ProgramData 'ssh\sshd_config'
    $currentLine = Get-Content -Path $sshdConfigPath | Where-Object { $_ -match '^\s*Subsystem\s+sftp\s' }
    $matches = $currentLine -and ($currentLine -match [regex]::Escape($desiredCommand))
    [pscustomobject]@{ Ok = [bool]$matches; Detail = if (-not $currentLine) { "no 'Subsystem sftp ...' line found in '$sshdConfigPath'" } else { "sshd_config Subsystem sftp line $(if ($matches) { 'already' } else { 'does not' }) match '$desiredCommand'" } }
} -Action {
    $sshdImagePath = (Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\sshd').ImagePath.Trim('"')
    $sftpServerPath = Join-Path (Split-Path $sshdImagePath -Parent) 'sftp-server.exe'
    if (-not (Test-Path $sftpServerPath)) {
        throw "sftp-server.exe not found at expected path '$sftpServerPath' (derived from the sshd service's own binary path)."
    }
    $desiredCommand = "& '$sftpServerPath'"

    $sshdConfigPath = Join-Path $env:ProgramData 'ssh\sshd_config'
    $sshdConfigContent = Get-Content -Path $sshdConfigPath
    $currentLine = $sshdConfigContent | Where-Object { $_ -match '^\s*Subsystem\s+sftp\s' }
    if (-not $currentLine) {
        Write-Warning "No 'Subsystem sftp ...' line found in '$sshdConfigPath' - skipping (hand-edited config?)."
        return
    }
    if ($currentLine -match [regex]::Escape($desiredCommand)) {
        Write-Host "SFTP subsystem path in sshd_config is already fully-qualified, skipping."
        return
    }

    $newContent = $sshdConfigContent -replace '^\s*Subsystem\s+sftp\s+.*$', "Subsystem`tsftp`t$desiredCommand"
    Set-Content -Path $sshdConfigPath -Value $newContent -Encoding ascii
    Write-Host "Fully-qualified the SFTP subsystem path in sshd_config to '$sftpServerPath'."
    Request-SshdRestart
}

# Optional - sshd auto-generates a fresh host key (and therefore a new
# identity/fingerprint) whenever one is missing, which silently breaks
# every client's known_hosts trust. Pinning specific key material here
# keeps the same identity across reprovisioning.
$hostKeys = Get-ConfigValue $Config @('ssh_server', 'host_keys') @()
foreach ($hostKey in $hostKeys) {
    $keyType = Get-ConfigValue $hostKey @('type')
    $hostKeySkip = if (-not $sshServerEnabled) { "'ssh_server.enable' is not set to true in config" } else { $null }

    Invoke-Step -Name "Configure SSH host key ($keyType)" -SkipReason $hostKeySkip -Tag 'ssh' -Verify {
        if ($keyType -notin $script:ValidSshHostKeyTypes) {
            throw "Invalid ssh_server.host_keys type '$keyType' - must be 'rsa', 'ecdsa', or 'ed25519'."
        }
        $privateKeyContent = Resolve-ConfigResource -InlineValue (Get-ConfigValue $hostKey @('private_key')) `
            -PathValue (Get-ConfigValue $hostKey @('private_key_path')) `
            -UrlValue (Get-ConfigValue $hostKey @('private_key_url')) `
            -SecretIdValue (Get-ConfigValue $hostKey @('private_key_secret_id')) `
            -Description "ssh_server.host_keys ($keyType)"
        $keyPath = Join-Path (Join-Path $env:ProgramData 'ssh') "ssh_host_${keyType}_key"
        $normalizedContent = (($privateKeyContent -replace "`r`n", "`n").TrimEnd("`n")) + "`n"
        $matches = (Test-Path $keyPath) -and (((Get-Content -Path $keyPath -Raw) -replace "`r`n", "`n") -eq $normalizedContent)
        [pscustomobject]@{ Ok = $matches; Detail = "SSH host key '$keyType' at '$keyPath' $(if ($matches) { 'already matches' } else { 'does not match' }) the configured value" }
    } -Action {
        if ($keyType -notin $script:ValidSshHostKeyTypes) {
            throw "Invalid ssh_server.host_keys type '$keyType' - must be 'rsa', 'ecdsa', or 'ed25519'."
        }

        $privateKeyContent = Resolve-ConfigResource -InlineValue (Get-ConfigValue $hostKey @('private_key')) `
            -PathValue (Get-ConfigValue $hostKey @('private_key_path')) `
            -UrlValue (Get-ConfigValue $hostKey @('private_key_url')) `
            -SecretIdValue (Get-ConfigValue $hostKey @('private_key_secret_id')) `
            -Description "ssh_server.host_keys ($keyType)"

        $sshDir = Join-Path $env:ProgramData 'ssh'
        $keyPath = Join-Path $sshDir "ssh_host_${keyType}_key"
        $normalizedContent = (($privateKeyContent -replace "`r`n", "`n").TrimEnd("`n")) + "`n"

        if ((Test-Path $keyPath) -and (((Get-Content -Path $keyPath -Raw) -replace "`r`n", "`n")) -eq $normalizedContent) {
            Write-Host "SSH host key '$keyType' already matches configured value, skipping."
            return
        }

        if (-not (Test-Path $sshDir)) {
            New-Item -Path $sshDir -ItemType Directory -Force | Out-Null
        }
        Set-Content -Path $keyPath -Value $normalizedContent -NoNewline -Encoding ascii

        # sshd refuses to use a host key file with overly permissive ACLs -
        # lock it down to just SYSTEM and Administrators, same technique
        # already used for administrators_authorized_keys below.
        icacls.exe $keyPath /inheritance:r | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "icacls /inheritance:r failed (exit $LASTEXITCODE) for $keyPath" }
        icacls.exe $keyPath /grant 'SYSTEM:F' | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "icacls /grant SYSTEM:F failed (exit $LASTEXITCODE) for $keyPath" }
        icacls.exe $keyPath /grant 'Administrators:F' | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "icacls /grant Administrators:F failed (exit $LASTEXITCODE) for $keyPath" }

        # Derived rather than requiring the config to supply both halves -
        # one less thing that could ever get out of sync.
        & ssh-keygen.exe -y -f $keyPath | Set-Content -Path "$keyPath.pub" -Encoding ascii
        if ($LASTEXITCODE -ne 0) { throw "ssh-keygen -y failed (exit $LASTEXITCODE) deriving the public key for $keyPath" }

        Write-Host "SSH host key '$keyType' set from config."
        Request-SshdRestart
    }
}

$authorizedKeys = Get-ConfigValue $Config @('ssh_server', 'authorized_keys') @()
$authorizedKeysSkip = if (-not $sshServerEnabled) {
    "'ssh_server.enable' is not set to true in config"
}
elseif ($authorizedKeys.Count -eq 0) {
    'no ssh_server.authorized_keys configured (password authentication remains available)'
}
else { $null }

Invoke-Step -Name 'Configure SSH key-based login' -SkipReason $authorizedKeysSkip -Tag 'ssh' -Verify {
    $resolvedKeys = Resolve-SshKeyList -Keys $authorizedKeys
    $isAdminAccount = $null -ne (Get-LocalGroupMember -Group 'Administrators' -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -like "*\$env:USERNAME" })
    $keysPath = if ($isAdminAccount) {
        Join-Path $env:ProgramData 'ssh\administrators_authorized_keys'
    }
    else {
        Join-Path (Join-Path $env:USERPROFILE '.ssh') 'authorized_keys'
    }
    $existing = if (Test-Path $keysPath) { Get-Content -Path $keysPath -Raw -ErrorAction SilentlyContinue } else { '' }
    $missing = @($resolvedKeys | Where-Object { $existing -notmatch [regex]::Escape($_) })
    [pscustomobject]@{ Ok = ($missing.Count -eq 0); Detail = if ($missing.Count -eq 0) { "all $($resolvedKeys.Count) configured key(s) already present in '$keysPath'" } else { "$($missing.Count) of $($resolvedKeys.Count) configured key(s) missing from '$keysPath'" } }
} -Action {
    $resolvedKeys = Resolve-SshKeyList -Keys $authorizedKeys
    function Add-AuthorizedKeyIfMissing {
        param(
            [Parameter(Mandatory)] [string]$Path,
            [Parameter(Mandatory)] [string]$Key
        )
        $existing = if (Test-Path $Path) { Get-Content -Path $Path -Raw -ErrorAction SilentlyContinue } else { '' }
        if ($existing -notmatch [regex]::Escape($Key)) {
            Add-Content -Path $Path -Value $Key
        }
    }

    # Windows' OpenSSH Server treats logins from members of Administrators
    # specially: for those accounts it ignores the per-user authorized_keys
    # file entirely and only honors ProgramData\ssh\administrators_authorized_keys,
    # which sshd refuses to use unless its ACL is locked down to just SYSTEM
    # and Administrators (inherited ProgramData permissions are too open).
    $isAdminAccount = $null -ne (Get-LocalGroupMember -Group 'Administrators' -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -like "*\$env:USERNAME" })

    if ($isAdminAccount) {
        $keysPath = Join-Path $env:ProgramData 'ssh\administrators_authorized_keys'
        foreach ($key in $resolvedKeys) {
            Add-AuthorizedKeyIfMissing -Path $keysPath -Key $key
        }

        icacls.exe $keysPath /inheritance:r | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "icacls /inheritance:r failed (exit $LASTEXITCODE) for $keysPath" }
        icacls.exe $keysPath /grant 'SYSTEM:F' | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "icacls /grant SYSTEM:F failed (exit $LASTEXITCODE) for $keysPath" }
        icacls.exe $keysPath /grant 'Administrators:F' | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "icacls /grant Administrators:F failed (exit $LASTEXITCODE) for $keysPath" }
    }
    else {
        $sshDir = Join-Path $env:USERPROFILE '.ssh'
        if (-not (Test-Path $sshDir)) {
            New-Item -Path $sshDir -ItemType Directory -Force | Out-Null
        }
        $authorizedKeysPath = Join-Path $sshDir 'authorized_keys'
        foreach ($key in $resolvedKeys) {
            Add-AuthorizedKeyIfMissing -Path $authorizedKeysPath -Key $key
        }
    }
}

$defaultShell = Get-ConfigValue $Config @('ssh_server', 'default_shell')
$defaultShellSkip = if (-not $sshServerEnabled) {
    "'ssh_server.enable' is not set to true in config"
}
elseif (-not $defaultShell) {
    'no ssh_server.default_shell configured (leaving the current default shell as-is)'
}
else { $null }

Invoke-Step -Name 'Set SSH default shell' -SkipReason $defaultShellSkip -Tag 'ssh' -Verify {
    $shellPath = Resolve-ShellExecutablePath -Shell $defaultShell -RequireNativeWin32Install
    $existing = Get-ItemProperty -Path 'HKLM:\SOFTWARE\OpenSSH' -ErrorAction SilentlyContinue
    $currentValue = if ($existing -and $existing.PSObject.Properties['DefaultShell']) { $existing.DefaultShell } else { $null }
    [pscustomobject]@{ Ok = ($currentValue -eq $shellPath); Detail = "DefaultShell is currently '$currentValue', expected '$shellPath'" }
} -Action {
    # Throws with a clear message if the selected shell isn't actually
    # installed on this machine - deliberately not caught here, so an
    # unavailable/misspelled shell surfaces as a FAILED step rather than
    # silently leaving the previous default in place.
    $shellPath = Resolve-ShellExecutablePath -Shell $defaultShell -RequireNativeWin32Install

    $keyPath = 'HKLM:\SOFTWARE\OpenSSH'
    if (-not (Test-Path $keyPath)) {
        New-Item -Path $keyPath -Force | Out-Null
    }
    $existing = Get-ItemProperty -Path $keyPath -ErrorAction SilentlyContinue
    $currentValue = if ($existing -and $existing.PSObject.Properties['DefaultShell']) { $existing.DefaultShell } else { $null }

    if ($currentValue -eq $shellPath) {
        Write-Host "SSH default shell is already set to '$shellPath', skipping."
        return
    }

    New-ItemProperty -Path $keyPath -Name 'DefaultShell' -Value $shellPath -PropertyType String -Force | Out-Null

    # Restart sshd (if it's already running) so the new default shell takes
    # effect for the very next SSH session instead of waiting for a reboot.
    Request-SshdRestart
    Write-Host "SSH default shell set to '$shellPath'."
}

# ----------------------------------------------------------------------------
# 19. Disable Windows ssh-agent service (Bitwarden provides the SSH agent)
# ----------------------------------------------------------------------------

$winSshAgentSkip = if (-not (Get-ConfigValue $Config @('disable_winssh_agent') $false)) {
    "'disable_winssh_agent' is not set to true in config"
} else { $null }

Invoke-Step -Name 'Disable Windows ssh-agent service (Bitwarden provides the SSH agent)' -SkipReason $winSshAgentSkip -Tag 'winssh_agent' -Verify {
    if (-not (Test-BitwardenInstalled)) {
        return [pscustomobject]@{ Ok = $true; Detail = 'Bitwarden is not installed, nothing required' }
    }
    $service = Get-Service -Name 'ssh-agent' -ErrorAction SilentlyContinue
    if (-not $service) {
        return [pscustomobject]@{ Ok = $true; Detail = 'ssh-agent service not present, nothing to disable' }
    }
    $ok = $service.Status -eq 'Stopped' -and $service.StartType -eq 'Disabled'
    [pscustomobject]@{ Ok = $ok; Detail = "ssh-agent service status: $($service.Status), start type: $($service.StartType)" }
} -Action {
    if (-not (Test-BitwardenInstalled)) {
        Write-Host 'Bitwarden is not installed, skipping.'
        return
    }

    # Bitwarden's built-in SSH agent and the Windows OpenSSH Authentication
    # Agent service both listen on the same named pipe; the Windows one has to
    # be stopped and disabled or Bitwarden's agent can't take over it.
    $service = Get-Service -Name 'ssh-agent' -ErrorAction SilentlyContinue
    if (-not $service) {
        Write-Host 'ssh-agent service not present, skipping.'
        return
    }

    if ($service.Status -ne 'Stopped') {
        Stop-Service -Name 'ssh-agent' -Force
    }
    if ($service.StartType -ne 'Disabled') {
        Set-Service -Name 'ssh-agent' -StartupType Disabled
    }
}

# ----------------------------------------------------------------------------
# 20. Set computer name
# ----------------------------------------------------------------------------

$desiredComputerName = Get-ConfigValue $Config @('computer_name') ''
$computerNameSkip = if ([string]::IsNullOrWhiteSpace($desiredComputerName)) { "'computer_name' is not set in config" } else { $null }

Invoke-Step -Name 'Set computer name' -SkipReason $computerNameSkip -Tag 'computer_name' -Verify {
    [pscustomobject]@{ Ok = ($env:COMPUTERNAME -eq $desiredComputerName); Detail = "current computer name is '$env:COMPUTERNAME', expected '$desiredComputerName'" }
} -Action {
    if ($env:COMPUTERNAME -eq $desiredComputerName) {
        Write-Host "Computer name is already '$desiredComputerName', skipping."
        return
    }

    Rename-Computer -NewName $desiredComputerName -Force
    $script:RebootRequired = $true
    Write-Host "Computer renamed from '$env:COMPUTERNAME' to '$desiredComputerName'; takes effect after reboot."
}

# ----------------------------------------------------------------------------
# 21. Set network connection category
# ----------------------------------------------------------------------------

$firewallDisabled = Get-ConfigValue $Config @('firewall', 'disabled') $false
$firewallProfileValue = Get-ConfigValue $Config @('firewall', 'profile')
$firewallProfileSkip = if ($firewallDisabled) {
    "'firewall.disabled' is set to true"
} elseif (-not $firewallProfileValue) {
    "no 'firewall.profile' configured"
} else { $null }

Invoke-Step -Name 'Set network connection category' -SkipReason $firewallProfileSkip -Tag 'firewall' -Verify {
    if ($firewallProfileValue -notin $script:ValidFirewallProfiles) {
        throw "Invalid firewall.profile '$firewallProfileValue' - must be 'public' or 'private'."
    }
    $category = if ($firewallProfileValue -eq 'private') { 'Private' } else { 'Public' }
    $mismatched = @(Get-NetConnectionProfile | Where-Object { $_.NetworkCategory -ne $category })
    [pscustomobject]@{ Ok = ($mismatched.Count -eq 0); Detail = if ($mismatched.Count -eq 0) { "all network connections already category '$category'" } else { "$($mismatched.Count) network connection(s) not category '$category': $(($mismatched | ForEach-Object { "$($_.Name)=$($_.NetworkCategory)" }) -join ', ')" } }
} -Action {
    if ($firewallProfileValue -notin $script:ValidFirewallProfiles) {
        throw "Invalid firewall.profile '$firewallProfileValue' - must be 'public' or 'private' (Windows assigns the 'Domain' category automatically on domain-joined machines; it can't be set manually)."
    }
    $category = if ($firewallProfileValue -eq 'private') { 'Private' } else { 'Public' }
    foreach ($p in Get-NetConnectionProfile) {
        if ($p.NetworkCategory -eq $category) {
            Write-Host "Network '$($p.Name)' is already category '$category', skipping."
            continue
        }
        Set-NetConnectionProfile -InterfaceIndex $p.InterfaceIndex -NetworkCategory $category
        Write-Host "Network '$($p.Name)' set to category '$category' (was '$($p.NetworkCategory)')."
    }
}

# ----------------------------------------------------------------------------
# 22. Configure ICMP ping firewall rule
# ----------------------------------------------------------------------------

$pingSetting = Get-ConfigValue $Config @('firewall', 'ping')
$pingRuleName = 'Bootstrap-AllowPingIn-ICMPv4'
$pingSkip = if ($firewallDisabled) {
    "'firewall.disabled' is set to true"
} elseif (-not $pingSetting) {
    "no 'firewall.ping' configured"
} else { $null }

Invoke-Step -Name 'Configure ICMP ping firewall rule' -SkipReason $pingSkip -Tag 'firewall' -Verify {
    if ($pingSetting -notin $script:ValidFirewallRuleModes) {
        throw "Invalid firewall.ping '$pingSetting' - must be 'block', 'allow_lan', or 'allow_all'."
    }
    $existingRule = Get-NetFirewallRule -Name $pingRuleName -ErrorAction SilentlyContinue
    if ($pingSetting -eq 'block') {
        [pscustomobject]@{ Ok = (-not $existingRule); Detail = "'$pingRuleName' $(if ($existingRule) { 'still exists' } else { 'is absent' }) (expected: absent)" }
    }
    else {
        $desiredProfile = if ($pingSetting -eq 'allow_all') { 'Any' } else { 'Private,Domain' }
        $ok = $existingRule -and $existingRule.Profile -eq $desiredProfile -and $existingRule.Enabled -eq 'True'
        [pscustomobject]@{ Ok = [bool]$ok; Detail = if (-not $existingRule) { "'$pingRuleName' does not exist (expected profile: $desiredProfile)" } else { "'$pingRuleName' profile='$($existingRule.Profile)' enabled='$($existingRule.Enabled)' (expected profile: $desiredProfile, enabled: True)" } }
    }
} -Action {
    if ($pingSetting -notin $script:ValidFirewallRuleModes) {
        throw "Invalid firewall.ping '$pingSetting' - must be 'block', 'allow_lan', or 'allow_all'."
    }

    $existingRule = Get-NetFirewallRule -Name $pingRuleName -ErrorAction SilentlyContinue
    if ($pingSetting -eq 'block') {
        if ($existingRule) {
            $existingRule | Remove-NetFirewallRule
            Write-Host "Removed '$pingRuleName' - ping is blocked (Windows default)."
        }
        else {
            Write-Host "'$pingRuleName' does not exist - ping is already blocked (Windows default)."
        }
        return
    }

    # A dedicated, script-owned rule rather than toggling the many
    # pre-existing built-in Echo Request rules - those have mismatched
    # profile groupings (e.g. Domain gets its own rule instance separate
    # from Private+Public) that don't map cleanly onto allow_lan/allow_all,
    # so owning one rule outright (same pattern as OpenSSH-Server-In-TCP
    # above) keeps this idempotent and easy to reason about.
    $desiredProfile = if ($pingSetting -eq 'allow_all') { 'Any' } else { 'Private,Domain' }
    if (-not $existingRule) {
        New-NetFirewallRule -Name $pingRuleName -DisplayName 'Bootstrap: Allow ICMPv4 Echo Request (Ping) In' `
            -Direction Inbound -Protocol ICMPv4 -IcmpType 8 -Action Allow -Profile $desiredProfile -Enabled True | Out-Null
        Write-Host "Created '$pingRuleName', scope: $desiredProfile."
    }
    elseif ($existingRule.Profile -ne $desiredProfile -or $existingRule.Enabled -ne 'True') {
        $existingRule | Set-NetFirewallRule -Profile $desiredProfile -Enabled True
        Write-Host "Updated '$pingRuleName', scope: $desiredProfile."
    }
    else {
        Write-Host "'$pingRuleName' already configured for scope $desiredProfile, skipping."
    }

    $liveCategory = (Get-NetConnectionProfile | Select-Object -First 1).NetworkCategory
    Write-Host "Current live network category: $liveCategory (rule applies when the active category matches $desiredProfile)."
}

# ----------------------------------------------------------------------------
# 23. Configure SMB shares
# ----------------------------------------------------------------------------

$smbSharesResolved = Resolve-ConfigList -Config $Config -Key 'smb_shares'
$smbSharesDisabled = $smbSharesResolved.Disabled
$smbShares = $smbSharesResolved.Items
foreach ($share in $smbShares) {
    $shareName = Get-ConfigValue $share @('name')
    $sharePath = Get-ConfigValue $share @('path')
    $shareCreate = Get-ConfigValue $share @('create') $false
    $shareAccess = Get-ConfigValue $share @('access') 'read'
    $shareDisabled = Get-ConfigValue $share @('disabled') $false
    $shareSkip = if ($smbSharesDisabled) {
        "'smb_shares.disabled' is set to true"
    } elseif ($shareDisabled) {
        "'disabled: true' for share '$shareName'"
    } else { $null }

    Invoke-Step -Name "Share '$shareName' via SMB" -SkipReason $shareSkip -Tag 'smb' -Verify {
        if ($shareAccess -notin $script:ValidSmbAccessLevels) {
            throw "Invalid access '$shareAccess' for share '$shareName' - must be 'read', 'change', or 'full'."
        }
        $pathExists = Test-Path $sharePath
        $existing = Get-SmbShare -Name $shareName -ErrorAction SilentlyContinue
        $shareExists = $existing -and $pathExists -and $existing.Path.TrimEnd('\') -eq $sharePath.TrimEnd('\')
        $accessRight = @{ read = 'Read'; change = 'Change'; full = 'Full' }[$shareAccess]
        $accessOk = $shareExists -and (Get-SmbShareAccess -Name $shareName -ErrorAction SilentlyContinue |
            Where-Object { $_.AccountName -eq 'Everyone' -and $_.AccessRight -eq $accessRight })
        $ntfsRight = @{ read = 'ReadAndExecute'; change = 'Modify'; full = 'FullControl' }[$shareAccess]
        $ntfsOk = $pathExists -and ((Invoke-WithTransientRetry { Get-Acl -Path $sharePath }).Access | Where-Object {
            $_.IdentityReference.Value -eq 'Everyone' -and $_.AccessControlType -eq 'Allow' -and
            $_.FileSystemRights.ToString().Split(',').Trim() -contains $ntfsRight
        })
        $ok = $pathExists -and $shareExists -and [bool]$accessOk -and [bool]$ntfsOk
        [pscustomobject]@{ Ok = $ok; Detail = "path exists: $pathExists; share exists at path: $([bool]$shareExists); Everyone share access '$accessRight': $([bool]$accessOk); Everyone NTFS '$ntfsRight': $([bool]$ntfsOk)" }
    } -Action {
        if (-not (Test-Path $sharePath)) {
            if (-not $shareCreate) {
                Write-Warning "Path '$sharePath' does not exist and create is not true for share '$shareName' - skipping."
                return
            }
            New-Item -Path $sharePath -ItemType Directory -Force | Out-Null
            Write-Host "Created '$sharePath'."
        }
        if ($shareAccess -notin $script:ValidSmbAccessLevels) {
            throw "Invalid access '$shareAccess' for share '$shareName' - must be 'read', 'change', or 'full'."
        }

        $existing = Get-SmbShare -Name $shareName -ErrorAction SilentlyContinue
        if ($existing -and $existing.Path.TrimEnd('\') -ne $sharePath.TrimEnd('\')) {
            throw "Share '$shareName' already exists but points at a different path ('$($existing.Path)') - remove it manually first (Remove-SmbShare -Name '$shareName') if you want to repoint it."
        }
        if (-not $existing) {
            # No access params here - New-SmbShare's -NoAccess actually takes a
            # list of trustees to deny (not a "create with no access" switch),
            # so it can't be used to mean "start blank". Left at New-SmbShare's
            # own default (Everyone: Read) instead; the Grant/Revoke block
            # below immediately overrides it to the configured access level.
            New-SmbShare -Name $shareName -Path $sharePath | Out-Null
            Write-Host "Created SMB share '$shareName' -> '$sharePath'."
        }

        # Always (re)applied idempotently here - covers both the "just
        # created" and "already existed" cases with one code path instead
        # of duplicating access-setting logic.
        $accessRight = @{ read = 'Read'; change = 'Change'; full = 'Full' }[$shareAccess]
        $currentEveryone = Get-SmbShareAccess -Name $shareName | Where-Object AccountName -eq 'Everyone'
        if (-not $currentEveryone -or $currentEveryone.AccessRight -ne $accessRight) {
            if ($currentEveryone) { Revoke-SmbShareAccess -Name $shareName -AccountName 'Everyone' -Force }
            Grant-SmbShareAccess -Name $shareName -AccountName 'Everyone' -AccessRight $accessRight -Force | Out-Null
            Write-Host "Set SMB share '$shareName' access for Everyone: $shareAccess."
        }
        else {
            Write-Host "SMB share '$shareName' already has Everyone: $shareAccess, skipping."
        }

        # A share's effective permission is the more restrictive of its SMB
        # share-level permission and its NTFS permission - relying on
        # whatever a given path happened to inherit is fragile (fine for
        # read/change, but could silently cap "full" on a differently-
        # ACL'd path), so this explicitly grants a matching NTFS ACE for
        # Everyone too. Added additively (SetAccessRule), not replacing
        # the existing ACL - same non-destructive approach as every other
        # step here.
        $ntfsRight = @{ read = 'ReadAndExecute'; change = 'Modify'; full = 'FullControl' }[$shareAccess]
        $acl = Invoke-WithTransientRetry { Get-Acl -Path $sharePath }
        $hasRule = $acl.Access | Where-Object {
            $_.IdentityReference.Value -eq 'Everyone' -and $_.AccessControlType -eq 'Allow' -and
            $_.FileSystemRights.ToString().Split(',').Trim() -contains $ntfsRight
        }
        if (-not $hasRule) {
            $rule = New-Object System.Security.AccessControl.FileSystemAccessRule('Everyone', $ntfsRight, 'ContainerInherit,ObjectInherit', 'None', 'Allow')
            $acl.SetAccessRule($rule)
            Invoke-WithTransientRetry { Set-Acl -Path $sharePath -AclObject $acl }
            Write-Host "Granted NTFS '$ntfsRight' to Everyone on '$sharePath'."
        }
    }
}

# ----------------------------------------------------------------------------
# 24. Configure SMB firewall rule
# ----------------------------------------------------------------------------

$smbFirewallSetting = Get-ConfigValue $Config @('firewall', 'smb')
$smbRuleName = 'Bootstrap-AllowSmbIn'
$smbFirewallSkip = if ($firewallDisabled) {
    "'firewall.disabled' is set to true"
} elseif (-not $smbFirewallSetting) {
    "no 'firewall.smb' configured"
} else { $null }

Invoke-Step -Name 'Configure SMB firewall rule' -SkipReason $smbFirewallSkip -Tag @('smb', 'firewall') -Verify {
    if ($smbFirewallSetting -notin $script:ValidFirewallRuleModes) {
        throw "Invalid firewall.smb '$smbFirewallSetting' - must be 'block', 'allow_lan', or 'allow_all'."
    }
    $existingRule = Get-NetFirewallRule -Name $smbRuleName -ErrorAction SilentlyContinue
    if ($smbFirewallSetting -eq 'block') {
        [pscustomobject]@{ Ok = (-not $existingRule); Detail = "'$smbRuleName' $(if ($existingRule) { 'still exists' } else { 'is absent' }) (expected: absent)" }
    }
    else {
        $desiredProfile = if ($smbFirewallSetting -eq 'allow_all') { 'Any' } else { 'Private,Domain' }
        $ok = $existingRule -and $existingRule.Profile -eq $desiredProfile -and $existingRule.Enabled -eq 'True'
        [pscustomobject]@{ Ok = [bool]$ok; Detail = if (-not $existingRule) { "'$smbRuleName' does not exist (expected profile: $desiredProfile)" } else { "'$smbRuleName' profile='$($existingRule.Profile)' enabled='$($existingRule.Enabled)' (expected profile: $desiredProfile, enabled: True)" } }
    }
} -Action {
    if ($smbFirewallSetting -notin $script:ValidFirewallRuleModes) {
        throw "Invalid firewall.smb '$smbFirewallSetting' - must be 'block', 'allow_lan', or 'allow_all'."
    }

    $existingRule = Get-NetFirewallRule -Name $smbRuleName -ErrorAction SilentlyContinue
    if ($smbFirewallSetting -eq 'block') {
        if ($existingRule) {
            $existingRule | Remove-NetFirewallRule
            Write-Host "Removed '$smbRuleName' - SMB inbound is blocked (Windows default)."
        }
        else {
            Write-Host "'$smbRuleName' does not exist - SMB inbound is already blocked (Windows default)."
        }
        return
    }

    # Same reasoning as the ICMP ping rule above: the built-in SMB-In rules
    # have a mismatched Domain-vs-Private+Public grouping, so this owns a
    # dedicated rule instead.
    $desiredProfile = if ($smbFirewallSetting -eq 'allow_all') { 'Any' } else { 'Private,Domain' }
    if (-not $existingRule) {
        New-NetFirewallRule -Name $smbRuleName -DisplayName 'Bootstrap: Allow SMB (File Sharing) In' `
            -Direction Inbound -Protocol TCP -LocalPort 445 -Action Allow -Profile $desiredProfile -Enabled True | Out-Null
        Write-Host "Created '$smbRuleName', scope: $desiredProfile."
    }
    elseif ($existingRule.Profile -ne $desiredProfile -or $existingRule.Enabled -ne 'True') {
        $existingRule | Set-NetFirewallRule -Profile $desiredProfile -Enabled True
        Write-Host "Updated '$smbRuleName', scope: $desiredProfile."
    }
    else {
        Write-Host "'$smbRuleName' already configured for scope $desiredProfile, skipping."
    }

    $liveCategory = (Get-NetConnectionProfile | Select-Object -First 1).NetworkCategory
    Write-Host "Current live network category: $liveCategory (rule applies when the active category matches $desiredProfile)."
}

# ----------------------------------------------------------------------------
# 25. Configure SSH keys for local user accounts
# ----------------------------------------------------------------------------
# Deliberately separate from (and much later than) account creation/profile
# initialization above (step 4) - the admin branch below writes into
# C:\ProgramData\ssh, which only exists once "Enable OpenSSH Server" has
# installed OpenSSH, so this sub-step has to stay after that regardless of
# how early the accounts themselves get created. Reuses $localUsers /
# $localUsersDisabled resolved back in step 4 (plain script-scoped
# variables, same as $script:LastCreatedUserPassword).

if ($localUsers.Count -eq 0) {
    Invoke-Step -Name 'Configure SSH keys for local user accounts' -SkipReason 'no local_users entries configured' -Tag 'local_users' -Action {}
}
else {
    foreach ($entry in $localUsers) {
        $userName = Get-ConfigValue $entry @('name')
        $isAdmin = Get-ConfigValue $entry @('admin') $false
        $userDisabled = Get-ConfigValue $entry @('disabled') $false
        $sshKeysConfig = Get-ConfigValue $entry @('ssh_keys')
        $sshKeysSkip = if ($localUsersDisabled) {
            "'local_users.disabled' is set to true"
        } elseif ($userDisabled) {
            "'disabled: true' for user '$userName'"
        } elseif (-not $sshKeysConfig) {
            "no 'ssh_keys' configured for user '$userName'"
        } else { $null }

        Invoke-Step -Name "Configure SSH key(s) for local user '$userName'" -SkipReason $sshKeysSkip -Tag 'local_users', 'ssh' -Verify {
            # [array] on the LHS is required here, not just @() inside each
            # branch: PowerShell unwraps a single-element array back into a
            # bare scalar when an if/else-as-expression's branch produces
            # exactly one pipeline output, even if that branch already wraps
            # it with @() - confirmed live (a 1-key explicit ssh_keys list
            # crashed with "property 'Count' cannot be found" without this).
            [array]$keys = Resolve-SshKeyList -Keys $(if ($sshKeysConfig -eq 'default') { @(Get-ConfigValue $Config @('ssh_server', 'authorized_keys') @()) } else { @($sshKeysConfig) })
            if ($keys.Count -eq 0) {
                [pscustomobject]@{ Ok = $false; Detail = "'ssh_keys: default' resolved to zero keys - no 'ssh_server.authorized_keys' configured" }
            }
            else {
                $isMember = [bool](Get-LocalGroupMember -Group 'Administrators' -ErrorAction SilentlyContinue |
                    Where-Object { $_.Name -eq $userName -or $_.Name -like "*\$userName" })
                $keysPath = if ($isMember) {
                    Join-Path $env:ProgramData 'ssh\administrators_authorized_keys'
                } else {
                    $homeDir = Resolve-RealUserProfilePath -UserName $userName
                    if ($homeDir) { Join-Path $homeDir '.ssh\authorized_keys' } else { $null }
                }
                if (-not $keysPath) {
                    [pscustomobject]@{ Ok = $false; Detail = "user '$userName' has never logged on yet - its real profile directory isn't known, so a non-admin account's ssh_keys can't be applied until after first logon" }
                }
                else {
                    $existing = if (Test-Path $keysPath) { Get-Content -Path $keysPath -Raw -ErrorAction SilentlyContinue } else { '' }
                    $missing = @($keys | Where-Object { $existing -notmatch [regex]::Escape($_) })
                    [pscustomobject]@{ Ok = ($missing.Count -eq 0); Detail = if ($missing.Count -eq 0) { "all $($keys.Count) key(s) already present in '$keysPath'" } else { "$($missing.Count) of $($keys.Count) key(s) missing from '$keysPath'" } }
                }
            }
        } -Action {
            # 'default' reuses ssh_server.authorized_keys instead of duplicating
            # key material per-user in the config - anything else is treated as
            # an explicit list of raw public key lines, same format as that
            # section's own authorized_keys.
            # [array] on the LHS is required here, not just @() inside each
            # branch: PowerShell unwraps a single-element array back into a
            # bare scalar when an if/else-as-expression's branch produces
            # exactly one pipeline output, even if that branch already wraps
            # it with @() - confirmed live (a 1-key explicit ssh_keys list
            # crashed with "property 'Count' cannot be found" without this).
            [array]$keys = Resolve-SshKeyList -Keys $(if ($sshKeysConfig -eq 'default') { @(Get-ConfigValue $Config @('ssh_server', 'authorized_keys') @()) } else { @($sshKeysConfig) })
            if ($keys.Count -eq 0) {
                Write-Warning "local_users '$userName': 'ssh_keys: default' requested but no 'ssh_server.authorized_keys' are configured - skipping."
                return
            }

            function Add-AuthorizedKeyIfMissing {
                param(
                    [Parameter(Mandatory)] [string]$Path,
                    [Parameter(Mandatory)] [string]$Key
                )
                $existing = if (Test-Path $Path) { Get-Content -Path $Path -Raw -ErrorAction SilentlyContinue } else { '' }
                if ($existing -notmatch [regex]::Escape($Key)) {
                    Add-Content -Path $Path -Value $Key
                }
            }

            # Get-LocalGroupMember returns names as "COMPUTERNAME\username" for
            # local accounts, so match on the suffix rather than an exact string
            # - same check used above when reconciling Administrators membership.
            $isMember = [bool](Get-LocalGroupMember -Group 'Administrators' -ErrorAction SilentlyContinue |
                Where-Object { $_.Name -eq $userName -or $_.Name -like "*\$userName" })

            if ($isMember) {
                # Windows OpenSSH ignores the per-user authorized_keys file
                # entirely for accounts in Administrators - only
                # administrators_authorized_keys is honored, shared by every
                # admin account on the machine (the same file
                # ssh_server.authorized_keys populates in its own step above).
                $keysPath = Join-Path $env:ProgramData 'ssh\administrators_authorized_keys'
                foreach ($key in $keys) { Add-AuthorizedKeyIfMissing -Path $keysPath -Key $key }
                icacls.exe $keysPath /inheritance:r | Out-Null
                if ($LASTEXITCODE -ne 0) { throw "icacls /inheritance:r failed (exit $LASTEXITCODE) for $keysPath" }
                icacls.exe $keysPath /grant 'SYSTEM:F' | Out-Null
                if ($LASTEXITCODE -ne 0) { throw "icacls /grant SYSTEM:F failed (exit $LASTEXITCODE) for $keysPath" }
                icacls.exe $keysPath /grant 'Administrators:F' | Out-Null
                if ($LASTEXITCODE -ne 0) { throw "icacls /grant Administrators:F failed (exit $LASTEXITCODE) for $keysPath" }
            }
            else {
                # Non-admin accounts use their own per-user authorized_keys
                # file, under their REAL profile directory - confirmed live
                # that guessing "C:\Users\<name>" and pre-creating a folder
                # there for an account that had never logged on actively
                # corrupts things: Windows then assigns a different,
                # computer-name-suffixed profile path on that account's
                # first real logon instead of a clean one, since it finds
                # the guessed folder already "taken". Not a concern for
                # admin accounts, which use the shared file above instead.
                $homeDir = Resolve-RealUserProfilePath -UserName $userName
                if (-not $homeDir) {
                    Write-Warning "local_users '$userName': cannot configure ssh_keys yet - this account has never logged on, so Windows hasn't created its real profile directory. Log on once (e.g. with its configured password) and re-run bootstrap to apply the key."
                    return
                }
                $sshDir = Join-Path $homeDir '.ssh'
                if (-not (Test-Path $sshDir)) { New-Item -Path $sshDir -ItemType Directory -Force | Out-Null }
                $keysPath = Join-Path $sshDir 'authorized_keys'
                foreach ($key in $keys) { Add-AuthorizedKeyIfMissing -Path $keysPath -Key $key }
                icacls.exe $keysPath /inheritance:r | Out-Null
                if ($LASTEXITCODE -ne 0) { throw "icacls /inheritance:r failed (exit $LASTEXITCODE) for $keysPath" }
                icacls.exe $keysPath /grant "${userName}:F" | Out-Null
                if ($LASTEXITCODE -ne 0) { throw "icacls /grant ${userName}:F failed (exit $LASTEXITCODE) for $keysPath" }
                icacls.exe $keysPath /grant 'SYSTEM:F' | Out-Null
                if ($LASTEXITCODE -ne 0) { throw "icacls /grant SYSTEM:F failed (exit $LASTEXITCODE) for $keysPath" }
                icacls.exe $keysPath /grant 'Administrators:F' | Out-Null
                if ($LASTEXITCODE -ne 0) { throw "icacls /grant Administrators:F failed (exit $LASTEXITCODE) for $keysPath" }
            }
            Write-Host "Configured $($keys.Count) SSH key(s) for local user '$userName' in '$keysPath'."
        }
    }
}

# ----------------------------------------------------------------------------
# 26. Schedule first-login setup for local user accounts
# ----------------------------------------------------------------------------
# 'apps' entries with scope: user can only ever be installed correctly in
# the target account's own real interactive session (see
# Register-FirstLoginTask above, and the 'local_users' step for why a
# batch-logon-forced profile isn't enough) - this schedules that to
# happen automatically the next time each opted-in local_users account
# actually logs on, instead of requiring a second manual bootstrap run
# (which has its own problem: the script/config typically lives under
# the ORIGINAL bootstrap account's profile, which a different,
# non-admin account may not even be able to read).

if ($localUsers.Count -eq 0) {
    Invoke-Step -Name 'Schedule first-login setup for local user accounts' -SkipReason 'no local_users entries configured' -Tag 'first_login' -Action {}
}
else {
    foreach ($entry in $localUsers) {
        $userName = Get-ConfigValue $entry @('name')
        $userDisabled = Get-ConfigValue $entry @('disabled') $false
        $completeSetupOnFirstLogin = Get-ConfigValue $entry @('complete_setup_on_first_login') $true
        $userScopeAppsForLogin = if ($appsDisabled) {
            @()
        }
        else {
            @($apps | Where-Object {
                (Get-ConfigValue $_ @('scope') 'machine') -eq 'user' -and -not (Get-ConfigValue $_ @('disabled') $false)
            } | ForEach-Object {
                [pscustomobject]@{
                    Id              = Get-ConfigValue $_ @('id')
                    DesktopShortcut = Get-ConfigValue $_ @('desktop_shortcut') $false
                }
            })
        }

        $firstLoginSkip = if ($localUsersDisabled) {
            "'local_users.disabled' is set to true"
        } elseif ($userDisabled) {
            "'disabled: true' for user '$userName'"
        } elseif (-not $completeSetupOnFirstLogin) {
            "'complete_setup_on_first_login: false' for user '$userName'"
        } elseif ($appsDisabled) {
            "'apps.disabled' is set to true"
        } elseif ($userScopeAppsForLogin.Count -eq 0) {
            "no 'scope: user' apps configured"
        } else { $null }

        Invoke-Step -Name "Schedule first-login setup for local user '$userName'" -SkipReason $firstLoginSkip -Tag 'first_login' -Verify {
            $taskName = "win-bootstrap-first-login-$userName"
            $exists = [bool](Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue)
            [pscustomobject]@{ Ok = $exists; Detail = if ($exists) { "task '$taskName' is already scheduled" } else { "task '$taskName' does not exist yet" } }
        } -Action {
            Register-FirstLoginTask -UserName $userName -Apps $userScopeAppsForLogin
        }
    }
}

# ----------------------------------------------------------------------------
# 27. Configure sudo for Windows
# ----------------------------------------------------------------------------

$sudoMode = Get-ConfigValue $Config @('sudo', 'mode')
$sudoSkip = if (-not $sudoMode) { "no 'sudo.mode' configured" } else { $null }

Invoke-Step -Name 'Configure sudo for Windows' -SkipReason $sudoSkip -Tag 'sudo' -Verify {
    $sudoModeMap = @{ disabled = 0; force_new_window = 1; disable_input = 2; normal = 3 }
    if ($sudoMode -notin $script:ValidSudoModes) {
        throw "Invalid sudo.mode '$sudoMode' - must be 'disabled', 'force_new_window', 'disable_input', or 'normal'."
    }
    $desiredValue = $sudoModeMap[$sudoMode]
    $existing = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Sudo' -ErrorAction SilentlyContinue
    $currentValue = if ($existing -and $existing.PSObject.Properties['Enabled']) { $existing.Enabled } else { $null }
    [pscustomobject]@{ Ok = ($currentValue -eq $desiredValue); Detail = "sudo registry Enabled is currently '$currentValue', expected '$desiredValue' (mode '$sudoMode')" }
} -Action {
    $sudoModeMap = @{ disabled = 0; force_new_window = 1; disable_input = 2; normal = 3 }
    if ($sudoMode -notin $script:ValidSudoModes) {
        throw "Invalid sudo.mode '$sudoMode' - must be 'disabled', 'force_new_window', 'disable_input', or 'normal'."
    }
    if ([Environment]::OSVersion.Version.Build -lt 26100) {
        Write-Warning "This Windows build predates Sudo for Windows (requires 11 24H2 / build 26100+) - the registry value will be set but will have no effect until upgraded."
    }

    $desiredValue = $sudoModeMap[$sudoMode]
    $keyPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Sudo'
    if (-not (Test-Path $keyPath)) {
        New-Item -Path $keyPath -Force | Out-Null
    }
    $existing = Get-ItemProperty -Path $keyPath -ErrorAction SilentlyContinue
    $currentValue = if ($existing -and $existing.PSObject.Properties['Enabled']) { $existing.Enabled } else { $null }
    if ($currentValue -eq $desiredValue) {
        Write-Host "sudo is already configured for mode '$sudoMode', skipping."
        return
    }
    New-ItemProperty -Path $keyPath -Name 'Enabled' -Value $desiredValue -PropertyType DWord -Force | Out-Null
    Write-Host "sudo configured for mode '$sudoMode' (registry Enabled=$desiredValue)."
}

# ----------------------------------------------------------------------------
# 28. Configure crash dump settings
# ----------------------------------------------------------------------------

$crashDumpType = Get-ConfigValue $Config @('crash_dump', 'type')
$crashDumpSkip = if (-not $crashDumpType) { "no 'crash_dump.type' configured" } else { $null }
$crashDumpTypeMap = @{ none = 0; complete = 1; kernel = 2; small = 3; active = 4; automatic = 7 }
$crashDumpKeyPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl'

Invoke-Step -Name 'Configure crash dump settings' -SkipReason $crashDumpSkip -Tag 'crash_dump' -Verify {
    if ($crashDumpType -notin $script:ValidCrashDumpTypes) {
        [pscustomobject]@{ Ok = $false; Detail = "invalid crash_dump.type '$crashDumpType'" }
    }
    else {
        $existing = Get-ItemProperty -Path $crashDumpKeyPath -ErrorAction SilentlyContinue
        $desired = @{ CrashDumpEnabled = $crashDumpTypeMap[$crashDumpType] }
        $dumpFile = Get-ConfigValue $Config @('crash_dump', 'dump_file')
        if ($dumpFile) { $desired['DumpFile'] = $dumpFile }
        $overwrite = Get-ConfigValue $Config @('crash_dump', 'overwrite')
        if ($null -ne $overwrite) { $desired['Overwrite'] = [int][bool]$overwrite }
        $mismatches = [System.Collections.Generic.List[string]]::new()
        foreach ($name in $desired.Keys) {
            $current = if ($existing -and $existing.PSObject.Properties[$name]) { $existing.$name } else { $null }
            if ("$current" -ne "$($desired[$name])") { $mismatches.Add("$name=$current (expected $($desired[$name]))") }
        }
        [pscustomobject]@{ Ok = ($mismatches.Count -eq 0); Detail = if ($mismatches.Count -eq 0) { "already matches ($($desired.Keys -join ', '))" } else { "mismatched: $($mismatches -join '; ')" } }
    }
} -Action {
    if ($crashDumpType -notin $script:ValidCrashDumpTypes) {
        throw "Invalid crash_dump.type '$crashDumpType' - must be 'none', 'complete', 'kernel', 'small', 'automatic', or 'active'."
    }
    if (-not (Test-Path $crashDumpKeyPath)) { New-Item -Path $crashDumpKeyPath -Force | Out-Null }
    New-ItemProperty -Path $crashDumpKeyPath -Name 'CrashDumpEnabled' -Value $crashDumpTypeMap[$crashDumpType] -PropertyType DWord -Force | Out-Null
    $dumpFile = Get-ConfigValue $Config @('crash_dump', 'dump_file')
    if ($dumpFile) { New-ItemProperty -Path $crashDumpKeyPath -Name 'DumpFile' -Value $dumpFile -PropertyType ExpandString -Force | Out-Null }
    $overwrite = Get-ConfigValue $Config @('crash_dump', 'overwrite')
    if ($null -ne $overwrite) { New-ItemProperty -Path $crashDumpKeyPath -Name 'Overwrite' -Value ([int][bool]$overwrite) -PropertyType DWord -Force | Out-Null }
    Write-Host "Crash dump configured: type=$crashDumpType."
}

# ----------------------------------------------------------------------------
# 29. Configure kernel debugging
# ----------------------------------------------------------------------------

$kernelDebugEnabled = Get-ConfigValue $Config @('kernel_debugging', 'enable') $false
$kernelDebugTarget = Get-ConfigValue $Config @('kernel_debugging', 'target') 'current'
$kernelDebugDefaultProfile = Get-ConfigValue $Config @('kernel_debugging', 'default_profile') 'current'
$kernelDebugSkip = if (-not $kernelDebugEnabled) { "'kernel_debugging.enable' is not set to true" } else { $null }

Invoke-Step -Name 'Configure kernel debugging boot entry' -SkipReason $kernelDebugSkip -Tag 'kernel_debugging' -Verify {
    if ($kernelDebugTarget -notin $script:ValidKernelDebugTargets) {
        [pscustomobject]@{ Ok = $false; Detail = "invalid kernel_debugging.target '$kernelDebugTarget'" }
    }
    elseif ($kernelDebugDefaultProfile -notin $script:ValidKernelDebugTargets) {
        [pscustomobject]@{ Ok = $false; Detail = "invalid kernel_debugging.default_profile '$kernelDebugDefaultProfile'" }
    }
    else {
        $targetId = if ($kernelDebugTarget -eq 'current') { '{current}' } else { Get-BcdEntryIdByDescription -Description $KernelDebugEntryDescription }
        if (-not $targetId) {
            [pscustomobject]@{ Ok = $false; Detail = "target boot entry '$KernelDebugEntryDescription' does not exist yet" }
        }
        else {
            $enumOutput = & bcdedit.exe /enum $targetId
            $debugOn = ($enumOutput -join "`n") -match '(?m)^debug\s+Yes'
            # default_profile only matters for target: dedicated - with
            # target: current there's only one entry, nothing to compare.
            # {bootmgr}'s own "default" field is checked here rather than
            # {current}'s "identifier" - bcdedit displays {current} (the
            # alias) as the identifier of whichever entry is presently
            # booted/default, never its real GUID, so comparing against
            # that would never match a real dedicated-entry GUID (confirmed
            # live). {bootmgr}'s "default" field shows the real GUID once
            # /default has actually been pointed at a specific entry.
            $defaultOk = if ($kernelDebugTarget -eq 'dedicated' -and $kernelDebugDefaultProfile -eq 'dedicated') {
                ((& bcdedit.exe /enum '{bootmgr}') -join "`n") -match "(?m)^default\s+$([regex]::Escape($targetId))"
            }
            else { $true }
            [pscustomobject]@{ Ok = ($debugOn -and $defaultOk); Detail = "debug=$debugOn for $targetId, default_profile requirement met=$defaultOk" }
        }
    }
} -Action {
    if ($kernelDebugTarget -notin $script:ValidKernelDebugTargets) {
        throw "Invalid kernel_debugging.target '$kernelDebugTarget' - must be 'current' or 'dedicated'."
    }
    if ($kernelDebugDefaultProfile -notin $script:ValidKernelDebugTargets) {
        throw "Invalid kernel_debugging.default_profile '$kernelDebugDefaultProfile' - must be 'current' or 'dedicated'."
    }
    if ($kernelDebugTarget -eq 'current') {
        $targetId = '{current}'
    }
    else {
        $targetId = Get-BcdEntryIdByDescription -Description $KernelDebugEntryDescription
        if (-not $targetId) {
            $copyOutput = & bcdedit.exe /copy '{current}' /d $KernelDebugEntryDescription
            if ($LASTEXITCODE -ne 0) { throw "bcdedit /copy failed (exit $LASTEXITCODE): $copyOutput" }
            if (($copyOutput -join ' ') -match '(\{[^}]+\})') { $targetId = $Matches[1] } else { throw "Could not parse new boot entry identifier from: $copyOutput" }
            Write-Host "Created boot entry '$KernelDebugEntryDescription' ($targetId)."
        }
        if ($kernelDebugDefaultProfile -eq 'dedicated') {
            & bcdedit.exe /default $targetId | Out-Null
            if ($LASTEXITCODE -ne 0) { throw "bcdedit /default failed (exit $LASTEXITCODE)" }
        }
        # default_profile: current (the default) deliberately does NOT
        # touch /default at all - /copy never changes the boot default on
        # its own, so the original entry stays default automatically.
    }
    $debugOnOutput = & bcdedit.exe /set $targetId debug on
    if ($LASTEXITCODE -ne 0) { throw "bcdedit /set $targetId debug on failed (exit $LASTEXITCODE): $debugOnOutput" }
    $defaultNote = if ($kernelDebugTarget -eq 'dedicated') {
        if ($kernelDebugDefaultProfile -eq 'dedicated') { ' and set as the boot default' } else { ' (boot default left unchanged - pick it from the boot menu to use it)' }
    }
    else { '' }
    Write-Host "Kernel debugging enabled on boot entry $targetId$defaultNote. Takes effect on next reboot."
}

$legacyBootMenu = Get-ConfigValue $Config @('kernel_debugging', 'legacy_boot_menu') $false
$legacyBootMenuSkip = if (-not $legacyBootMenu) { "'kernel_debugging.legacy_boot_menu' is not set to true in config" } else { $null }

Invoke-Step -Name 'Configure boot menu policy (legacy vs modern)' -SkipReason $legacyBootMenuSkip -Tag 'kernel_debugging' -Verify {
    $entries = Get-BcdOsLoaderEntries
    $notLegacy = @($entries | Where-Object { $_.BootMenuPolicy -ne 'Legacy' })
    [pscustomobject]@{ Ok = ($notLegacy.Count -eq 0); Detail = "$($entries.Count - $notLegacy.Count)/$($entries.Count) boot loader entry/entries already set to Legacy bootmenupolicy" }
} -Action {
    $entries = Get-BcdOsLoaderEntries
    $changed = 0
    foreach ($entry in $entries) {
        if ($entry.BootMenuPolicy -ne 'Legacy') {
            & bcdedit.exe /set $entry.Guid bootmenupolicy Legacy | Out-Null
            if ($LASTEXITCODE -ne 0) { throw "bcdedit /set $($entry.Guid) bootmenupolicy Legacy failed (exit $LASTEXITCODE)" }
            $changed++
        }
    }
    Write-Host "Set bootmenupolicy to Legacy on $changed of $($entries.Count) boot loader entry/entries (all-or-nothing: applies to every entry, not just the one used for kernel debugging)."
}

# The debugger transport (/dbgsettings) is a GLOBAL BCD object shared by
# ANY boot entry with debug on - not per-entry - so this applies
# regardless of whether kernel_debugging.target is current or dedicated.
$kernelDebugTransport = Get-ConfigValue $Config @('kernel_debugging', 'transport')
$kernelDebugTransportSkip = if (-not $kernelDebugEnabled) {
    "'kernel_debugging.enable' is not set to true"
}
elseif (-not $kernelDebugTransport) {
    "no 'kernel_debugging.transport' configured"
}
else { $null }

Invoke-Step -Name 'Configure kernel debugger transport' -SkipReason $kernelDebugTransportSkip -Tag 'kernel_debugging' -Verify {
    $current = (& bcdedit.exe /dbgsettings) -join "`n"
    if ($kernelDebugTransport -eq 'serial') {
        $port = (Get-ConfigValue $Config @('kernel_debugging', 'serial', 'port') 'COM1') -replace '[^0-9]', ''
        $baud = Get-ConfigValue $Config @('kernel_debugging', 'serial', 'baud_rate') 115200
        $ok = ($current -match '(?im)^debugtype\s+Serial') -and ($current -match "(?im)^debugport\s+$port\b") -and ($current -match "(?im)^baudrate\s+$baud\b")
        [pscustomobject]@{ Ok = $ok; Detail = "current dbgsettings:`n$current" }
    }
    elseif ($kernelDebugTransport -eq 'network') {
        $hostIp = Get-ConfigValue $Config @('kernel_debugging', 'network', 'host_ip')
        $port = Get-ConfigValue $Config @('kernel_debugging', 'network', 'port')
        $busParams = Get-ConfigValue $Config @('kernel_debugging', 'network', 'bus_params')
        $ok = ($current -match '(?im)^debugtype\s+Net') -and ($current -match "(?im)^hostip\s+$([regex]::Escape("$hostIp"))\b") -and ($current -match "(?im)^port\s+$port\b")
        if ($busParams) { $ok = $ok -and ($current -match "(?im)^busparams\s+$([regex]::Escape($busParams))\b") }
        [pscustomobject]@{ Ok = $ok; Detail = "current dbgsettings:`n$current" }
    }
    else {
        [pscustomobject]@{ Ok = $false; Detail = "invalid kernel_debugging.transport '$kernelDebugTransport'" }
    }
} -Action {
    if ($kernelDebugTransport -eq 'serial') {
        $port = (Get-ConfigValue $Config @('kernel_debugging', 'serial', 'port') 'COM1') -replace '[^0-9]', ''
        $baud = Get-ConfigValue $Config @('kernel_debugging', 'serial', 'baud_rate') 115200
        & bcdedit.exe /dbgsettings SERIAL DEBUGPORT:$port BAUDRATE:$baud | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "bcdedit /dbgsettings SERIAL failed (exit $LASTEXITCODE)" }
        Write-Host "Kernel debugger transport set to serial (port COM$port, $baud baud)."
    }
    elseif ($kernelDebugTransport -eq 'network') {
        $hostIp = Get-ConfigValue $Config @('kernel_debugging', 'network', 'host_ip')
        $port = Get-ConfigValue $Config @('kernel_debugging', 'network', 'port')
        $inlineKey = Get-ConfigValue $Config @('kernel_debugging', 'network', 'key')
        $keyPath = Get-ConfigValue $Config @('kernel_debugging', 'network', 'key_path')
        $keyUrl = Get-ConfigValue $Config @('kernel_debugging', 'network', 'key_url')
        $keySecretId = Get-ConfigValue $Config @('kernel_debugging', 'network', 'key_secret_id')
        $generate = Get-ConfigValue $Config @('kernel_debugging', 'network', 'generate') $false
        $busParams = Get-ConfigValue $Config @('kernel_debugging', 'network', 'bus_params')
        if (-not $hostIp -or -not $port) {
            throw "kernel_debugging.network requires 'host_ip' and 'port'."
        }
        $keySourceCount = @($inlineKey, $keyPath, $keyUrl, $keySecretId | Where-Object { $_ }).Count + [int]$generate
        if ($keySourceCount -ne 1) {
            throw "kernel_debugging.network: specify exactly one of 'key', 'key_path', 'key_url', 'key_secret_id', or 'generate: true'."
        }

        $current = (& bcdedit.exe /dbgsettings) -join "`n"

        # busparams pins the debug transport to a specific PCI
        # bus.device.function - independent of the host/port/key, and
        # carries no secret, so it's always safe to (re)apply on every
        # run regardless of the "don't touch an existing key" guard below.
        if ($busParams) {
            $busParamsOk = $current -match "(?im)^busparams\s+$([regex]::Escape($busParams))\b"
            if (-not $busParamsOk) {
                & bcdedit.exe /set '{dbgsettings}' busparams $busParams | Out-Null
                if ($LASTEXITCODE -ne 0) { throw "bcdedit /set '{dbgsettings}' busparams $busParams failed (exit $LASTEXITCODE)" }
                Write-Host "Kernel debugger busparams set to $busParams."
                $current = (& bcdedit.exe /dbgsettings) -join "`n"
            }
        }

        $alreadySet = ($current -match '(?im)^debugtype\s+Net') -and ($current -match "(?im)^hostip\s+$([regex]::Escape("$hostIp"))\b") -and ($current -match "(?im)^port\s+$port\b")
        if ($alreadySet) {
            # Never touch an already-configured network key, generated or
            # not - same "don't clobber existing state" philosophy as
            # local_users' password handling; regenerating would silently
            # break trust with whatever debug host already has the old key.
            Write-Host "Kernel debugger transport already set to network ($hostIp`:$port), leaving key untouched."
            return
        }

        if ($generate) {
            $genOutput = & bcdedit.exe /dbgsettings NET "HOSTIP:$hostIp" "PORT:$port" 'KEY:GENERATE'
            if ($LASTEXITCODE -ne 0) { throw "bcdedit /dbgsettings NET (generate) failed (exit $LASTEXITCODE): $genOutput" }
            $keyMatch = ($genOutput -join ' ') | Select-String -Pattern '([0-9A-Za-z]{4}[.\-][0-9A-Za-z]{4}[.\-][0-9A-Za-z]{4}[.\-][0-9A-Za-z]{4})'
            if (-not $keyMatch) { throw "Could not parse generated debug key from bcdedit output: $genOutput" }
            $revealKey = $keyMatch.Matches[0].Groups[1].Value
        }
        else {
            $resolvedKey = Resolve-ConfigResource -InlineValue $inlineKey -PathValue $keyPath -UrlValue $keyUrl `
                -SecretIdValue $keySecretId -Description 'kernel_debugging.network.key'
            & bcdedit.exe /dbgsettings NET "HOSTIP:$hostIp" "PORT:$port" "KEY:$resolvedKey" | Out-Null
            if ($LASTEXITCODE -ne 0) { throw "bcdedit /dbgsettings NET failed (exit $LASTEXITCODE)" }
        }
        Write-Host "Kernel debugger transport set to network ($hostIp`:$port)."

        if ($generate) {
            # Same reveal-once convention as local_users' generated
            # passwords - console if interactive, locked-down file next to
            # the script under -Quiet.
            if ($Quiet) {
                Invoke-WithoutBootstrapTranscript {
                    $dumpPath = Join-Path $PSScriptRoot 'kernel-debug-key.generated.txt'
                    Set-Content -Path $dumpPath -Value $revealKey -NoNewline -Encoding ascii
                    icacls.exe $dumpPath /inheritance:r | Out-Null
                    if ($LASTEXITCODE -ne 0) { throw "icacls /inheritance:r failed (exit $LASTEXITCODE) for $dumpPath" }
                    icacls.exe $dumpPath /grant 'SYSTEM:F' | Out-Null
                    if ($LASTEXITCODE -ne 0) { throw "icacls /grant SYSTEM:F failed (exit $LASTEXITCODE) for $dumpPath" }
                    icacls.exe $dumpPath /grant 'Administrators:F' | Out-Null
                    if ($LASTEXITCODE -ne 0) { throw "icacls /grant Administrators:F failed (exit $LASTEXITCODE) for $dumpPath" }
                    Write-Warning "Generated kernel debug key written to '$dumpPath' - read it, then delete this file."
                }
            }
            else {
                Invoke-WithoutBootstrapTranscript {
                    Write-Host '================================================================'
                    Write-Host "GENERATED KERNEL DEBUG KEY (save now - shown only once): $revealKey"
                    Write-Host '================================================================'
                }
            }
        }
    }
    else {
        throw "Invalid kernel_debugging.transport '$kernelDebugTransport' - must be 'serial' or 'network'."
    }
}

# ----------------------------------------------------------------------------
# 30. Install and activate a Windows product key
# ----------------------------------------------------------------------------

$winKeyInline = Get-ConfigValue $Config @('windows_product_key')
$winKeyPath = Get-ConfigValue $Config @('windows_product_key_path')
$winKeyUrl = Get-ConfigValue $Config @('windows_product_key_url')
$winKeySecretId = Get-ConfigValue $Config @('windows_product_key_secret_id')
$winKeySkip = if (-not ($winKeyInline -or $winKeyPath -or $winKeyUrl -or $winKeySecretId)) {
    "no 'windows_product_key' configured"
} else { $null }

# Well-known Application ID for the Windows OS licensing product itself
# (used internally by slmgr.vbs; stable across Windows versions).
$windowsAppId = '55c92734-d682-4d71-983e-d6ec3f16059f'

Invoke-Step -Name 'Install and activate Windows product key' -SkipReason $winKeySkip -Tag 'product_key' -Verify {
    $desiredKey = (Resolve-ConfigResource -InlineValue $winKeyInline -PathValue $winKeyPath -UrlValue $winKeyUrl -SecretIdValue $winKeySecretId -Description 'windows_product_key').Trim()
    $desiredSuffix = $desiredKey.Substring($desiredKey.Length - 5)

    $product = Get-CimInstance -ClassName SoftwareLicensingProduct -Filter "ApplicationID = '$windowsAppId' AND PartialProductKey IS NOT NULL" -ErrorAction SilentlyContinue
    $currentSuffix = if ($product) { $product.PartialProductKey } else { $null }
    $licensed = [bool]($product -and $product.LicenseStatus -eq 1)

    # Windows never exposes a fully-installed product key back out (only
    # the last 5 characters), so this can only ever be a suffix
    # comparison, not a full-key comparison.
    if ($currentSuffix -ne $desiredSuffix) {
        [pscustomobject]@{ Ok = $false; Detail = "installed key ends '...$currentSuffix' (or none), expected '...$desiredSuffix'" }
    } elseif (-not $licensed) {
        [pscustomobject]@{ Ok = $false; Detail = "key '...$desiredSuffix' installed but not activated (LicenseStatus=$($product.LicenseStatus))" }
    } else {
        [pscustomobject]@{ Ok = $true; Detail = "already activated with key ending '...$desiredSuffix'" }
    }
} -Action {
    $desiredKey = (Resolve-ConfigResource -InlineValue $winKeyInline -PathValue $winKeyPath -UrlValue $winKeyUrl -SecretIdValue $winKeySecretId -Description 'windows_product_key').Trim()
    $desiredSuffix = $desiredKey.Substring($desiredKey.Length - 5)

    $product = Get-CimInstance -ClassName SoftwareLicensingProduct -Filter "ApplicationID = '$windowsAppId' AND PartialProductKey IS NOT NULL" -ErrorAction SilentlyContinue
    if ($product.PartialProductKey -ne $desiredSuffix) {
        $service = Get-CimInstance -ClassName SoftwareLicensingService
        Invoke-CimMethod -InputObject $service -MethodName InstallProductKey -Arguments @{ ProductKey = $desiredKey } | Out-Null
        Invoke-CimMethod -InputObject $service -MethodName RefreshLicenseStatus | Out-Null
        $product = Get-CimInstance -ClassName SoftwareLicensingProduct -Filter "ApplicationID = '$windowsAppId' AND PartialProductKey IS NOT NULL" -ErrorAction SilentlyContinue
        Write-Host "Installed product key ending '...$desiredSuffix'."
    }
    if ($product.LicenseStatus -ne 1) {
        try {
            Invoke-CimMethod -InputObject $product -MethodName Activate | Out-Null
            Write-Host 'Activation requested.'
        } catch {
            Write-Warning "Activation call failed (often means no network/KMS reachability): $($_.Exception.Message). The key is installed; re-run bootstrap once network is available to retry activation."
        }
    }
}

# ----------------------------------------------------------------------------
# 31. Configure power settings (sleep / display timeouts)
# ----------------------------------------------------------------------------
# 'powercfg /change' just writes a value into the active power scheme -
# confirmed live (2026-08-05) it succeeds (exit 0) even on a VM where
# powercfg /a reports every sleep state as unavailable (no S1/S2/S3, no
# S0 Low Power Idle, hibernation not enabled - common for QEMU/KVM guests
# whose virtual firmware doesn't expose ACPI sleep support at all). The
# value is simply never acted on in that case, same as it already sits
# unused in the scheme today (Windows just hides the "Sleep after"
# slider from Settings' UI when no sleep state is available - the
# underlying setting is still there). So this never needs to detect or
# special-case an unsupported machine; it's a no-op that can't fail.

function Resolve-PowerTimeoutMinutes {
    # 'never' -> 0 (powercfg's own convention for "don't do this at all");
    # otherwise a plain whole number of minutes, already validated by
    # Test-PowerTimeoutValue above during config validation. $null (not
    # configured) is passed through so callers can tell "leave alone"
    # apart from "set to 0".
    param([string]$Value)
    if (-not $Value) { return $null }
    if ($Value.Trim().ToLowerInvariant() -eq 'never') { return 0 }
    return [int]$Value.Trim()
}

function Get-PowerSettingMinutes {
    # powercfg /query reports the active scheme's current value in
    # seconds (hex); /change (used to set it) takes whole minutes instead
    # - converting both to minutes here so Verify/Action compare like for
    # like without needing a separate seconds-vs-minutes code path.
    param(
        [Parameter(Mandatory)] [string]$SubGroup,
        [Parameter(Mandatory)] [string]$Setting
    )
    $output = powercfg /query SCHEME_CURRENT $SubGroup $Setting 2>&1 | Out-String
    $acMatch = [regex]::Match($output, 'Current AC Power Setting Index:\s*0x([0-9a-fA-F]+)')
    $dcMatch = [regex]::Match($output, 'Current DC Power Setting Index:\s*0x([0-9a-fA-F]+)')
    [pscustomobject]@{
        AcMinutes = if ($acMatch.Success) { [math]::Round([Convert]::ToInt64($acMatch.Groups[1].Value, 16) / 60) } else { $null }
        DcMinutes = if ($dcMatch.Success) { [math]::Round([Convert]::ToInt64($dcMatch.Groups[1].Value, 16) / 60) } else { $null }
    }
}

$sleepAfterOnPower = Resolve-PowerTimeoutMinutes (Get-ConfigValue $Config @('power', 'sleep_after', 'on_power'))
$sleepAfterOnBattery = Resolve-PowerTimeoutMinutes (Get-ConfigValue $Config @('power', 'sleep_after', 'on_battery'))
$displayOffAfterOnPower = Resolve-PowerTimeoutMinutes (Get-ConfigValue $Config @('power', 'display_off_after', 'on_power'))
$displayOffAfterOnBattery = Resolve-PowerTimeoutMinutes (Get-ConfigValue $Config @('power', 'display_off_after', 'on_battery'))
$powerDisabled = Get-ConfigValue $Config @('power', 'disabled') $false

$sleepSkip = if ($powerDisabled) {
    "'power.disabled' is set to true"
} elseif ($null -eq $sleepAfterOnPower -and $null -eq $sleepAfterOnBattery) {
    "no 'power.sleep_after.on_power'/'power.sleep_after.on_battery' configured"
} else { $null }

Invoke-Step -Name 'Configure power sleep timeout' -SkipReason $sleepSkip -Tag 'power' -Verify {
    $current = Get-PowerSettingMinutes -SubGroup 'SUB_SLEEP' -Setting 'STANDBYIDLE'
    $mismatches = [System.Collections.Generic.List[string]]::new()
    if ($null -ne $sleepAfterOnPower -and $current.AcMinutes -ne $sleepAfterOnPower) { $mismatches.Add("on power is $($current.AcMinutes) min, expected $sleepAfterOnPower") }
    if ($null -ne $sleepAfterOnBattery -and $current.DcMinutes -ne $sleepAfterOnBattery) { $mismatches.Add("on battery is $($current.DcMinutes) min, expected $sleepAfterOnBattery") }
    [pscustomobject]@{ Ok = ($mismatches.Count -eq 0); Detail = if ($mismatches.Count -eq 0) { 'sleep timeout already matches configured value(s)' } else { "mismatched: $($mismatches -join '; ')" } }
} -Action {
    if ($null -ne $sleepAfterOnPower) {
        powercfg /change standby-timeout-ac $sleepAfterOnPower
        if ($LASTEXITCODE -ne 0) { throw "powercfg /change standby-timeout-ac $sleepAfterOnPower failed (exit $LASTEXITCODE)" }
    }
    if ($null -ne $sleepAfterOnBattery) {
        powercfg /change standby-timeout-dc $sleepAfterOnBattery
        if ($LASTEXITCODE -ne 0) { throw "powercfg /change standby-timeout-dc $sleepAfterOnBattery failed (exit $LASTEXITCODE)" }
    }
    $powerDetail = if ($null -ne $sleepAfterOnPower) { "$sleepAfterOnPower min" } else { 'unchanged' }
    $batteryDetail = if ($null -ne $sleepAfterOnBattery) { "$sleepAfterOnBattery min" } else { 'unchanged' }
    Write-Host "Sleep timeout set (on power: $powerDetail, on battery: $batteryDetail)."
}

$displaySkip = if ($powerDisabled) {
    "'power.disabled' is set to true"
} elseif ($null -eq $displayOffAfterOnPower -and $null -eq $displayOffAfterOnBattery) {
    "no 'power.display_off_after.on_power'/'power.display_off_after.on_battery' configured"
} else { $null }

Invoke-Step -Name 'Configure power display timeout' -SkipReason $displaySkip -Tag 'power' -Verify {
    $current = Get-PowerSettingMinutes -SubGroup 'SUB_VIDEO' -Setting 'VIDEOIDLE'
    $mismatches = [System.Collections.Generic.List[string]]::new()
    if ($null -ne $displayOffAfterOnPower -and $current.AcMinutes -ne $displayOffAfterOnPower) { $mismatches.Add("on power is $($current.AcMinutes) min, expected $displayOffAfterOnPower") }
    if ($null -ne $displayOffAfterOnBattery -and $current.DcMinutes -ne $displayOffAfterOnBattery) { $mismatches.Add("on battery is $($current.DcMinutes) min, expected $displayOffAfterOnBattery") }
    [pscustomobject]@{ Ok = ($mismatches.Count -eq 0); Detail = if ($mismatches.Count -eq 0) { 'display timeout already matches configured value(s)' } else { "mismatched: $($mismatches -join '; ')" } }
} -Action {
    if ($null -ne $displayOffAfterOnPower) {
        powercfg /change monitor-timeout-ac $displayOffAfterOnPower
        if ($LASTEXITCODE -ne 0) { throw "powercfg /change monitor-timeout-ac $displayOffAfterOnPower failed (exit $LASTEXITCODE)" }
    }
    if ($null -ne $displayOffAfterOnBattery) {
        powercfg /change monitor-timeout-dc $displayOffAfterOnBattery
        if ($LASTEXITCODE -ne 0) { throw "powercfg /change monitor-timeout-dc $displayOffAfterOnBattery failed (exit $LASTEXITCODE)" }
    }
    $powerDetail = if ($null -ne $displayOffAfterOnPower) { "$displayOffAfterOnPower min" } else { 'unchanged' }
    $batteryDetail = if ($null -ne $displayOffAfterOnBattery) { "$displayOffAfterOnBattery min" } else { 'unchanged' }
    Write-Host "Display timeout set (on power: $powerDetail, on battery: $batteryDetail)."
}

# ----------------------------------------------------------------------------
# 32. Delete bootstrap user account (destructive, confirmation-gated)
# ----------------------------------------------------------------------------

# Placed last, deliberately after local_users account creation above - so
# if this config also provisions a replacement admin, the safety check
# below sees it as already created before deciding whether it's safe to
# remove the account that ran bootstrap.
$deleteBootstrapUser = Get-ConfigValue $Config @('delete_bootstrap_user') $false
$deleteBootstrapUserSkip = if (-not $deleteBootstrapUser) {
    "'delete_bootstrap_user' is not set to true in config"
} else { $null }

Invoke-Step -Name 'Delete bootstrap user account' -SkipReason $deleteBootstrapUserSkip -Tag 'cleanup' -Verify {
    $bootstrapUser = $env:USERNAME
    $exists = [bool](Get-LocalUser -Name $bootstrapUser -ErrorAction SilentlyContinue)
    [pscustomobject]@{
        Ok     = (-not $exists)
        Detail = if ($exists) { "user account '$bootstrapUser' (that ran bootstrap) still exists" }
                 else { "user account '$bootstrapUser' no longer exists" }
    }
} -Action {
    $bootstrapUser = $env:USERNAME
    if (-not (Get-LocalUser -Name $bootstrapUser -ErrorAction SilentlyContinue)) {
        Write-Host "User account '$bootstrapUser' already doesn't exist, skipping."
        return
    }

    # Hard safety gate - this setting means "delete whoever is running
    # bootstrap right now", which is only correct for the original,
    # disposable provisioning account. If a 'local_users' account from
    # this same config (i.e. one of the accounts meant to persist) is
    # the one running bootstrap - e.g. delete_bootstrap_user: true was
    # left in the config and someone re-runs bootstrap while already
    # logged in as the real target user - refuse outright rather than
    # deleting that account.
    $configuredUserNames = @($localUsers | ForEach-Object { Get-ConfigValue $_ @('name') } | Where-Object { $_ })
    if ($configuredUserNames -contains $bootstrapUser) {
        throw "Refusing to delete '$bootstrapUser': it is defined as a 'local_users' account in this config, not the disposable account the original bootstrap ran under. If 'delete_bootstrap_user: true' is left over from an earlier run, remove it from the config now."
    }

    # Hard safety gate - never leave the machine with zero enabled
    # Administrators. Checks LIVE machine state (not just "did the
    # local_users step above report OK"), so this still correctly
    # refuses even if an intended replacement admin failed to get
    # created earlier in this same run.
    $otherEnabledAdmins = @(
        Get-LocalGroupMember -Group 'Administrators' -ErrorAction SilentlyContinue |
        Where-Object { $_.ObjectClass -eq 'User' -and $_.Name -notlike "*\$bootstrapUser" } |
        ForEach-Object { Get-LocalUser -Name ($_.Name -split '\\')[-1] -ErrorAction SilentlyContinue } |
        Where-Object { $_ -and $_.Enabled }
    )
    if ($otherEnabledAdmins.Count -eq 0) {
        throw "Refusing to delete '$bootstrapUser': it is the only enabled Administrator account left on this machine. Configure at least one other admin (e.g. via local_users) before enabling delete_bootstrap_user."
    }

    $proceed = Confirm-RiskyAction -Message "This will permanently delete the local user account '$bootstrapUser' - the account currently running this bootstrap script. This cannot be undone."
    if (-not $proceed) {
        Write-Host 'Skipped by user.'
        return
    }

    # 'apps' entries with scope: user install into whichever account is
    # running this script - i.e. $bootstrapUser, which is about to be
    # deleted - so the "Install apps" step already skips them outright
    # (see its own SkipReason logic above) rather than installing then
    # losing them. Mention it again here too, at the point of deletion,
    # since it's easy to miss earlier in a long run's output.
    $userScopeAppIds = @($apps | Where-Object {
        (Get-ConfigValue $_ @('scope') 'machine') -eq 'user' -and -not (Get-ConfigValue $_ @('disabled') $false)
    } | ForEach-Object { Get-ConfigValue $_ @('id') })
    if ($userScopeAppIds.Count -gt 0) {
        Write-Warning "$($userScopeAppIds.Count) app(s) with scope: user ($($userScopeAppIds -join ', ')) were skipped during 'Install apps' because this account was going to be deleted - install them after logging in as the real target user, or switch to scope: machine if that package supports it."
    }

    # The actual deletion is deferred to the very end of this run (see
    # Summary below) - deleting the account currently running this
    # script, often over an active SSH session as that account, can end
    # the session/process before the rest of this run (including the
    # final summary) has a chance to finish, the same class of problem
    # solved for sshd restarts via Request-SshdRestart/Invoke-SshdRestart
    # above. Unlike that case, a plain try/catch is enough here (no
    # scheduled task) - Remove-LocalUser on an in-use account fails with
    # a normal catchable error rather than hanging, so on failure this
    # just recommends a reboot instead.
    $script:BootstrapUserToDelete = $bootstrapUser
    Write-Host "User account '$bootstrapUser' will be deleted at the very end of this run, after the summary below."
}

# ----------------------------------------------------------------------------
# 33. Configure network settings (static IP / gateway / DNS / MAC)
# ----------------------------------------------------------------------------
# Placed last (even after 'Delete bootstrap user account' above) since
# applying ip/gateway/dns immediately (network.apply_after_reboot: false)
# can drop the very session bootstrap is running over (typically SSH) -
# every other step, including the account deletion above, should already
# be done and visible in the summary before that risk is taken.
#
# mac_address never applies live at all (see
# Set-NetworkAdapterMacRegistryValue) - it's written straight to the
# adapter driver's registry key and only takes effect the next time the
# driver loads (a real reboot), same reasoning as - and independent of -
# network.apply_after_reboot, which only governs ip/gateway/dns.

function Resolve-NetworkAdapterAlias {
    # No 'interface' configured -> auto-detect via the current default
    # IPv4 route, which is reliable on the single-NIC VMs/servers this is
    # meant for. Re-run both now and inside the scheduled task at boot time
    # (see Register-NetworkConfigTask) rather than resolving once and
    # freezing the result, since the adapter's state can differ after a
    # reboot.
    param([string]$Configured)
    if ($Configured) {
        $adapter = Get-NetAdapter -Name $Configured -ErrorAction SilentlyContinue
        if (-not $adapter) { throw "network.interface '$Configured' does not match any network adapter on this machine." }
        return $adapter.Name
    }
    $route = Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue | Sort-Object -Property RouteMetric | Select-Object -First 1
    if (-not $route) { throw 'Could not auto-detect a network adapter (no default IPv4 route found) - set network.interface explicitly.' }
    $adapter = Get-NetAdapter -InterfaceIndex $route.InterfaceIndex -ErrorAction SilentlyContinue
    if (-not $adapter) { throw 'Could not resolve the network adapter for the default route.' }
    return $adapter.Name
}

function Test-NetworkConfigurationApplied {
    param(
        [Parameter(Mandatory)] [string]$InterfaceAlias,
        [string]$Ip,
        [string]$Gateway,
        [string[]]$Dns,
        [string]$Mac
    )
    $mismatches = [System.Collections.Generic.List[string]]::new()
    if ($Ip) {
        $addr, $prefix = $Ip -split '/'
        $current = Get-NetIPAddress -InterfaceAlias $InterfaceAlias -AddressFamily IPv4 -ErrorAction SilentlyContinue | Select-Object -First 1
        if (-not $current -or $current.IPAddress -ne $addr -or $current.PrefixLength -ne [int]$prefix) {
            $currentDetail = if ($current) { "$($current.IPAddress)/$($current.PrefixLength)" } else { 'not set' }
            $mismatches.Add("IP is $currentDetail, expected $Ip")
        }
    }
    if ($Gateway) {
        $currentGateway = (Get-NetIPConfiguration -InterfaceAlias $InterfaceAlias -ErrorAction SilentlyContinue).IPv4DefaultGateway.NextHop
        if ($currentGateway -ne $Gateway) {
            $mismatches.Add("gateway is $(if ($currentGateway) { $currentGateway } else { 'not set' }), expected $Gateway")
        }
    }
    if ($Dns -and $Dns.Count -gt 0) {
        $currentDns = @((Get-DnsClientServerAddress -InterfaceAlias $InterfaceAlias -AddressFamily IPv4 -ErrorAction SilentlyContinue).ServerAddresses)
        if (@(Compare-Object -ReferenceObject $Dns -DifferenceObject $currentDns).Count -gt 0) {
            $mismatches.Add("DNS servers are $($currentDns -join ', '), expected $($Dns -join ', ')")
        }
    }
    if ($Mac) {
        $currentMac = (Get-NetAdapter -Name $InterfaceAlias -ErrorAction SilentlyContinue).MacAddress
        $normalizedCurrent = ($currentMac -replace '[:-]', '').ToUpperInvariant()
        $normalizedExpected = ($Mac -replace '[:-]', '').ToUpperInvariant()
        if ($normalizedCurrent -ne $normalizedExpected) {
            $mismatches.Add("MAC address is $currentMac, expected $Mac")
        }
    }
    [pscustomobject]@{
        Ok     = ($mismatches.Count -eq 0)
        Detail = if ($mismatches.Count -eq 0) { 'network configuration matches config' } else { "mismatched: $($mismatches -join '; ')" }
    }
}

function Set-NetworkAdapterMacRegistryValue {
    # Writes the MAC override straight to the adapter driver's own registry
    # key (same key Set-NetAdapterAdvancedProperty itself ultimately writes
    # to) WITHOUT calling Set-NetAdapterAdvancedProperty - that cmdlet also
    # forces the driver to re-initialize immediately to pick up the change.
    # A plain registry write has no live effect at all; the driver only
    # reads NetworkAddress the next time it loads (a real reboot), so the
    # caller is responsible for setting $script:RebootRequired. Confirmed
    # live (2026-08-06, after fixing the unrelated reagentc/recovery_partition
    # bug that was the real cause of earlier boot failures blamed on this)
    # that a plain reboot after this write applies the new MAC cleanly,
    # with no adapter-reset risk, on the same QEMU/VirtIO host that
    # previously appeared to crash from MAC changes.
    param(
        [Parameter(Mandatory)] [string]$InterfaceAlias,
        [Parameter(Mandatory)] [string]$Mac
    )
    $adapter = Get-NetAdapter -Name $InterfaceAlias -ErrorAction Stop
    $classKey = 'HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}'
    $subkey = Get-ChildItem -Path $classKey -ErrorAction SilentlyContinue | Where-Object {
        (Get-ItemProperty -Path $_.PSPath -Name 'NetCfgInstanceId' -ErrorAction SilentlyContinue).NetCfgInstanceId -eq $adapter.InterfaceGuid
    } | Select-Object -First 1
    if (-not $subkey) { throw "Could not find the registry driver key for adapter '$InterfaceAlias' (network adapter class GUID {4d36e972-e325-11ce-bfc1-08002be10318})." }
    $macValue = $Mac -replace '[:-]', ''
    Set-ItemProperty -Path $subkey.PSPath -Name 'NetworkAddress' -Value $macValue
}

function Set-NetworkConfiguration {
    # Shared sequence used both for the immediate-apply path below and
    # (duplicated, since a scheduled task's script runs standalone - same
    # reasoning as Resolve-DesktopShortcutSource being duplicated inside
    # Register-FirstLoginTask's template) inside Register-NetworkConfigTask's
    # at-boot script. New-NetIPAddress (not Set-NetIPAddress, which cannot
    # set a gateway) is the confirmed-correct way to set IP+gateway together;
    # existing addresses/routes are removed first so this is safe to re-run
    # (e.g. every boot) without "object already exists" errors.
    param(
        [Parameter(Mandatory)] [string]$InterfaceAlias,
        [string]$Ip,
        [string]$Gateway,
        [string[]]$Dns
    )
    if ($Ip) {
        $addr, $prefix = $Ip -split '/'
        Get-NetIPAddress -InterfaceAlias $InterfaceAlias -AddressFamily IPv4 -ErrorAction SilentlyContinue | Remove-NetIPAddress -Confirm:$false -ErrorAction SilentlyContinue
        Get-NetRoute -InterfaceAlias $InterfaceAlias -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue | Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue
        Set-NetIPInterface -InterfaceAlias $InterfaceAlias -Dhcp Disabled -ErrorAction SilentlyContinue
        if ($Gateway) {
            New-NetIPAddress -InterfaceAlias $InterfaceAlias -IPAddress $addr -PrefixLength ([int]$prefix) -DefaultGateway $Gateway | Out-Null
        } else {
            New-NetIPAddress -InterfaceAlias $InterfaceAlias -IPAddress $addr -PrefixLength ([int]$prefix) | Out-Null
        }
        Write-Host "IP address set to $Ip on '$InterfaceAlias'$(if ($Gateway) { " with gateway $Gateway" })."
    }
    if ($Dns -and $Dns.Count -gt 0) {
        Set-DnsClientServerAddress -InterfaceAlias $InterfaceAlias -ServerAddresses $Dns
        Write-Host "DNS servers set to $($Dns -join ', ') on '$InterfaceAlias'."
    }
}

function Register-NetworkConfigTask {
    # Unlike Register-ProfileCleanupTask, this task is deliberately
    # re-registered (script content overwritten, task Force-registered)
    # on every bootstrap run rather than left alone once scheduled - if
    # the config's network settings change between two runs (before a
    # reboot actually applies them), a stale task would otherwise apply
    # outdated values. It also isn't self-deleting: it re-applies the
    # configured settings on every subsequent boot too, which is harmless
    # (idempotent - old addresses/routes are removed first) and corrects
    # any manual drift.
    param(
        [string]$InterfaceAlias,
        [string]$Ip,
        [string]$Gateway,
        [string[]]$Dns
    )
    $taskName = 'win-bootstrap-network-config'
    $baseDir = 'C:\ProgramData\win-bootstrap'
    if (-not (Test-Path $baseDir)) { New-Item -ItemType Directory -Path $baseDir -Force | Out-Null }
    $scriptPath = Join-Path $baseDir 'network-config.ps1'
    $logPath = Join-Path $baseDir 'network-config.log'
    $dnsLiteral = if ($Dns -and $Dns.Count -gt 0) { $Dns -join ',' } else { '' }

    # Single-quoted (non-interpolating) template, same reasoning as
    # Register-ProfileCleanupTask/Register-FirstLoginTask above - the
    # placeholders are substituted via .Replace() below, not PowerShell
    # string interpolation.
    $template = @'
$logPath = '__LOG_PATH__'
$interfaceAlias = '__INTERFACE__'
$ip = '__IP__'
$gateway = '__GATEWAY__'
$dnsCsv = '__DNS__'

function Write-Log { param([string]$Message) "$(Get-Date -Format o) - $Message" | Out-File -FilePath $logPath -Append }

Start-Sleep -Seconds 30

try {
    if ($interfaceAlias) {
        $adapter = Get-NetAdapter -Name $interfaceAlias -ErrorAction SilentlyContinue
    } else {
        $route = Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue | Sort-Object -Property RouteMetric | Select-Object -First 1
        if (-not $route) { Write-Log 'No default route found, cannot auto-detect network adapter.'; exit }
        $adapter = Get-NetAdapter -InterfaceIndex $route.InterfaceIndex -ErrorAction SilentlyContinue
    }
    if (-not $adapter) { Write-Log "Adapter '$interfaceAlias' not found."; exit }
    $alias = $adapter.Name

    if ($ip) {
        $addr, $prefix = $ip -split '/'
        Get-NetIPAddress -InterfaceAlias $alias -AddressFamily IPv4 -ErrorAction SilentlyContinue | Remove-NetIPAddress -Confirm:$false -ErrorAction SilentlyContinue
        Get-NetRoute -InterfaceAlias $alias -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue | Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue
        Set-NetIPInterface -InterfaceAlias $alias -Dhcp Disabled -ErrorAction SilentlyContinue
        if ($gateway) {
            New-NetIPAddress -InterfaceAlias $alias -IPAddress $addr -PrefixLength ([int]$prefix) -DefaultGateway $gateway | Out-Null
        } else {
            New-NetIPAddress -InterfaceAlias $alias -IPAddress $addr -PrefixLength ([int]$prefix) | Out-Null
        }
        Write-Log "IP address set to $ip on '$alias'$(if ($gateway) { " with gateway $gateway" })."
    }

    if ($dnsCsv) {
        $dnsList = $dnsCsv -split ','
        Set-DnsClientServerAddress -InterfaceAlias $alias -ServerAddresses $dnsList
        Write-Log "DNS servers set to $($dnsList -join ', ') on '$alias'."
    }

    Write-Log 'Network configuration applied successfully.'
} catch {
    Write-Log "Error applying network configuration: $($_.Exception.Message)"
}
'@
    $interfaceLiteral = if ($InterfaceAlias) { $InterfaceAlias } else { '' }
    $ipLiteral = if ($Ip) { $Ip } else { '' }
    $gatewayLiteral = if ($Gateway) { $Gateway } else { '' }
    $scriptContent = $template.Replace('__LOG_PATH__', $logPath).Replace('__INTERFACE__', $interfaceLiteral).Replace('__IP__', $ipLiteral).Replace('__GATEWAY__', $gatewayLiteral).Replace('__DNS__', $dnsLiteral)
    Set-Content -Path $scriptPath -Value $scriptContent

    $action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$scriptPath`""
    $trigger = New-ScheduledTaskTrigger -AtStartup
    $trigger.Delay = 'PT30S'
    $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
    Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Principal $principal -Force | Out-Null
    Write-Host "Scheduled network configuration to apply at next reboot (log: $logPath)."
}

$networkInterface = Get-ConfigValue $Config @('network', 'interface')
$networkIp = Get-ConfigValue $Config @('network', 'ip')
$networkGateway = Get-ConfigValue $Config @('network', 'gateway')
$networkDns = Get-ConfigValue $Config @('network', 'dns') @()
$networkMac = Get-ConfigValue $Config @('network', 'mac_address')
$networkApplyAfterReboot = Get-ConfigValue $Config @('network', 'apply_after_reboot') $true
$networkDisabled = Get-ConfigValue $Config @('network', 'disabled') $false

$networkSkip = if ($networkDisabled) {
    "'network.disabled' is set to true"
} elseif (-not $networkIp -and -not $networkGateway -and $networkDns.Count -eq 0 -and -not $networkMac) {
    "no 'network.ip'/'network.dns'/'network.mac_address' configured"
} else { $null }

Invoke-Step -Name 'Configure network settings' -SkipReason $networkSkip -Tag 'network' -Verify {
    $alias = Resolve-NetworkAdapterAlias -Configured $networkInterface
    Test-NetworkConfigurationApplied -InterfaceAlias $alias -Ip $networkIp -Gateway $networkGateway -Dns $networkDns -Mac $networkMac
} -Action {
    $alias = Resolve-NetworkAdapterAlias -Configured $networkInterface

    # MAC is handled independently of apply_after_reboot - it never
    # applies live (see Set-NetworkAdapterMacRegistryValue), so it always
    # just needs a reboot, same as recovery_partition/kernel_debugging/
    # computer_name (see the general Reboot handling mechanism below).
    if ($networkMac) {
        $macStatus = Test-NetworkConfigurationApplied -InterfaceAlias $alias -Mac $networkMac
        if ($macStatus.Ok) {
            Write-Host "MAC address already set to $networkMac on '$alias'."
        } else {
            $supportsMac = Get-NetAdapterAdvancedProperty -Name $alias -RegistryKeyword 'NetworkAddress' -ErrorAction SilentlyContinue
            if ($supportsMac) {
                Set-NetworkAdapterMacRegistryValue -InterfaceAlias $alias -Mac $networkMac
                Write-Host "MAC address for '$alias' written to the registry - takes effect on the next reboot."
                $script:RebootRequired = $true
            } else {
                Write-Warning "Adapter '$alias' does not support overriding its MAC address (no 'NetworkAddress' advanced property) - skipping network.mac_address."
            }
        }
    }

    if ($networkIp -or $networkGateway -or ($networkDns -and $networkDns.Count -gt 0)) {
        $ipDnsStatus = Test-NetworkConfigurationApplied -InterfaceAlias $alias -Ip $networkIp -Gateway $networkGateway -Dns $networkDns
        if ($ipDnsStatus.Ok) {
            Write-Host 'IP/gateway/DNS configuration already matches - nothing to do.'
        } elseif ($networkApplyAfterReboot) {
            Register-NetworkConfigTask -InterfaceAlias $networkInterface -Ip $networkIp -Gateway $networkGateway -Dns $networkDns
        } else {
            $interfaceDetail = if ($networkInterface) { $networkInterface } else { '(auto-detected)' }
            $proceed = Confirm-RiskyAction -Message "This will immediately reconfigure networking on interface '$interfaceDetail' - if this session is connected over that network (e.g. SSH/RDP), the connection may drop immediately and not come back if the new settings are wrong. This cannot be undone remotely."
            if (-not $proceed) {
                Write-Host 'Skipped by user.'
            } else {
                $script:NetworkConfigToApplyNow = [pscustomobject]@{
                    InterfaceAlias = $alias
                    Ip             = $networkIp
                    Gateway        = $networkGateway
                    Dns            = $networkDns
                }
                Write-Host 'Network settings will be applied immediately at the very end of this run, after the summary below.'
            }
        }
    }
}

# ----------------------------------------------------------------------------
# Summary
# ----------------------------------------------------------------------------

if ($script:VerifyMode) {
    Write-Host "`n=== Verification summary ===" -ForegroundColor Cyan
    $script:StepResults | Format-Table -AutoSize

    $notApplied = @($script:StepResults | Where-Object { $_.Status -eq 'NOT APPLIED' })
    $errors = @($script:StepResults | Where-Object { $_.Status -eq 'ERROR' })
    if ($notApplied.Count -gt 0) {
        Write-Warning "$($notApplied.Count) step(s) are not yet applied per the config - run without -Verify to apply them."
    }
    if ($errors.Count -gt 0) {
        Write-Warning "$($errors.Count) step(s) could not be verified due to an error. Review the summary above."
    }
    $script:BootstrapExitCode = if ($notApplied.Count -gt 0 -or $errors.Count -gt 0) { 1 } else { 0 }
    if ($script:BootstrapExitCode -eq 0) {
        Write-Host 'Verification complete. No changes were made to this machine.' -ForegroundColor Green
    }
    else {
        Write-Warning 'Verification completed with mismatches or errors. No changes were made to this machine; the process will return a nonzero exit code.'
    }
}
else {
    Write-Host "`n=== Bootstrap summary ===" -ForegroundColor Cyan
    $script:StepResults | Format-Table -AutoSize

    $failures = @($script:StepResults | Where-Object { $_.Status -in @('FAILED', 'ERROR', 'NOT APPLIED') })
    if ($failures.Count -gt 0) {
        Write-Warning "$($failures.Count) step(s) failed, errored, or were not applied. Review the summary above."
    }
    $script:BootstrapExitCode = if ($failures.Count -gt 0) { 1 } else { 0 }

    if ($script:RebootRequired) {
        Write-Warning 'A reboot is required for some of the changes above to fully take effect.'
    }

    # Deferred to here (once, after every other step has already run) rather
    # than immediately inside each sshd-affecting step - see
    # Request-SshdRestart/Invoke-SshdRestart above for why restarting sshd
    # any earlier can abort the rest of this very run.
    if ($script:SshdRestartNeeded) {
        try {
            Invoke-SshdRestart
        }
        catch {
            $script:BootstrapExitCode = 1
            Write-Warning "Deferred sshd restart failed: $($_.Exception.Message)"
        }
    }

    # Truly the last action in the script - see "Delete bootstrap user
    # account" above for why (the account/session running this script may
    # not survive it).
    if ($script:BootstrapUserToDelete) {
        # Captured before deletion - Get-LocalUser can't find the SID
        # once the account is gone, and Win32_UserProfile matches by SID.
        $bootstrapUserSid = (Get-LocalUser -Name $script:BootstrapUserToDelete -ErrorAction SilentlyContinue).SID.Value

        # Registered BEFORE Remove-LocalUser, not after - confirmed live:
        # doing this afterward fails every time with "No mapping between
        # account names and security IDs was done." - the ScheduledTasks
        # module needs to resolve the CALLING process's own account (this
        # script is still running as the account being deleted), which
        # breaks the instant that account no longer exists in the SAM
        # database, even though the process/session itself lives on.
        if ($bootstrapUserSid) {
            try {
                Register-ProfileCleanupTask -UserName $script:BootstrapUserToDelete -Sid $bootstrapUserSid
            }
            catch {
                $script:BootstrapExitCode = 1
                Write-Warning "Could not schedule profile cleanup for '$script:BootstrapUserToDelete': $($_.Exception.Message)"
            }
        }

        try {
            Remove-LocalUser -Name $script:BootstrapUserToDelete -ErrorAction Stop
            Write-Host "Deleted user account '$script:BootstrapUserToDelete'."
        }
        catch {
            $script:BootstrapExitCode = 1
            Write-Warning "Could not delete user account '$script:BootstrapUserToDelete' (it may have an active logon session): $($_.Exception.Message). Reboot and re-run this script (it's idempotent) to complete the cleanup."
        }
    }

    # Also truly-last (after even the bootstrap user deletion above) - see
    # "Configure network settings" for why network.apply_after_reboot: false
    # is deferred this far: it can drop the very session running this
    # script, so everything else should already be done and visible first.
    if ($script:NetworkConfigToApplyNow) {
        Write-Host "`nApplying network configuration now - this may disconnect this session." -ForegroundColor Yellow
        try {
            Set-NetworkConfiguration -InterfaceAlias $script:NetworkConfigToApplyNow.InterfaceAlias -Ip $script:NetworkConfigToApplyNow.Ip -Gateway $script:NetworkConfigToApplyNow.Gateway -Dns $script:NetworkConfigToApplyNow.Dns
        }
        catch {
            $script:BootstrapExitCode = 1
            Write-Warning "Failed to apply network configuration: $($_.Exception.Message)"
        }
    }

    # Truly the last action in the script (after even the bootstrap user
    # deletion above) - a reboot ends this session/process outright, so
    # every other step - including the summary and the account deletion -
    # must already be done first. Reuses Confirm-RiskyAction, so -Quiet
    # reboots automatically (no unattended run should be left half-applied
    # waiting on a manual reboot) while an interactive run asks first,
    # since this can end the current session just like recovery_partition's
    # delete or delete_bootstrap_user's deletion above.
    if ($script:RebootRequired) {
        $rebootNow = Confirm-RiskyAction -Message 'One or more changes above need a reboot to fully take effect. Reboot now? This will end this session if connected remotely (e.g. SSH/RDP).'
        if ($rebootNow) {
            Write-Host 'Rebooting now...' -ForegroundColor Yellow
            Restart-Computer -Force
        } else {
            Write-Host 'Reboot skipped - remember to reboot manually later to apply the pending change(s).'
        }
    }

    if ($script:BootstrapExitCode -eq 0) {
        Write-Host 'Bootstrap complete. Run this script again at any time to verify everything is still correctly applied (already-satisfied steps report OK without making changes), or use -Verify for a read-only check that never makes changes.' -ForegroundColor Green
    }
    else {
        Write-Warning 'Bootstrap completed with one or more failures. Review the summary and warnings above; the process will return a nonzero exit code.'
    }
}

# Keep the process status meaningful to win-bootstrap.cmd, scheduled callers,
# and other automation even though every independent step was allowed to run.
exit $script:BootstrapExitCode
