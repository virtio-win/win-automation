<#
.SYNOPSIS
    Focused regression checks for win-bootstrap.ps1.

.DESCRIPTION
    This is a self-contained Windows PowerShell 5.1 harness. It loads only
    selected function definitions from the production script's AST; it never
    dot-sources the provisioning script and therefore cannot run provisioning
    steps. Scheduled-task cmdlets are stubbed; HTTP checks use both mocks
    and temporary loopback servers with a dummy token. Transcript ACL checks
    use temporary directories on Windows.

.PARAMETER ScriptPath
    Path to the production win-bootstrap.ps1. Defaults to the sibling file.
#>

[CmdletBinding()]
param(
    [string]$ScriptPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:Passed = 0
$script:Failed = 0
$script:BootstrapRegressionRequests = @()
$script:MissingProductionFunctions = @()

if ([string]::IsNullOrWhiteSpace($ScriptPath)) {
    $ScriptPath = Join-Path $PSScriptRoot '..\win-bootstrap\win-bootstrap.ps1'
}

function Assert-True {
    param([Parameter(Mandatory)] [bool]$Condition, [Parameter(Mandatory)] [string]$Message)
    if (-not $Condition) { throw $Message }
}

function Assert-Throws {
    param([Parameter(Mandatory)] [scriptblock]$ScriptBlock, [Parameter(Mandatory)] [string]$Message)
    $thrown = $false
    try { & $ScriptBlock } catch { $thrown = $true }
    Assert-True -Condition $thrown -Message $Message
}

function Assert-ProductionFunctionAvailable {
    param([Parameter(Mandatory)] [string]$Name)
    Assert-True ($script:MissingProductionFunctions -notcontains $Name) "Production function '$Name' is missing; this regression cannot exercise it."
}

function Invoke-RegressionTest {
    param([Parameter(Mandatory)] [string]$Name, [Parameter(Mandatory)] [scriptblock]$ScriptBlock)
    try {
        & $ScriptBlock
        $script:Passed++
        Write-Host "PASS: $Name" -ForegroundColor Green
    }
    catch {
        $script:Failed++
        Write-Host "FAIL: $Name - $($_.Exception.Message)" -ForegroundColor Red
        if ($Name -like 'loopback*') {
            Write-Host $_.ScriptStackTrace -ForegroundColor DarkYellow
        }
    }
}

if (-not (Test-Path -LiteralPath $ScriptPath)) { throw "ScriptPath not found: $ScriptPath" }
$tokens = $null
$parseErrors = $null
$sourceAst = [System.Management.Automation.Language.Parser]::ParseFile($ScriptPath, [ref]$tokens, [ref]$parseErrors)
if ($parseErrors.Count -gt 0) { throw "Production script has parse errors: $($parseErrors -join '; ')" }

function Import-ProductionFunctions {
    param([Parameter(Mandatory)] [string[]]$Name)
    foreach ($wanted in $Name) {
        $functionAst = $sourceAst.Find({
            param($node)
            $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
                $node.Name -eq $wanted
        }, $true) | Select-Object -First 1
        if (-not $functionAst) {
            $script:MissingProductionFunctions += $wanted
            continue
        }
        # Return the production function body verbatim. The caller evaluates
        # it in script scope below; evaluating it here would create local
        # functions that disappear when this importer returns in PS 5.1.
        $functionAst.Extent.Text
    }
}

$productionFunctionDefinitions = @(Import-ProductionFunctions -Name @(
    'Assert-NotReparsePoint',
    'Set-BootstrapTranscriptAcl',
    'Start-BootstrapTranscript',
    'Stop-BootstrapTranscript',
    'Invoke-WithoutBootstrapTranscript',
    'ConvertTo-WebResponseText',
    'Get-UrlOrigin',
    'Get-RedirectLocation',
    'Test-ConfigTokenAllowedForUrl',
    'Get-ConfigText',
    'Register-FirstLoginTask'
))
foreach ($definition in $productionFunctionDefinitions) {
    # The production function body is evaluated verbatim from its AST
    # extent. This deliberately avoids running the script's param block,
    # startup code, elevation gate, or provisioning steps.
    Invoke-Expression $definition
}

if ($script:MissingProductionFunctions.Count -gt 0) {
    Write-Host "Production functions expected by these regressions are absent: $($script:MissingProductionFunctions -join ', ')" -ForegroundColor Yellow
}

function Get-FreeLoopbackPort {
    $listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, 0)
    $listener.Start()
    try { return $listener.LocalEndpoint.Port }
    finally { $listener.Stop() }
}

function Start-LoopbackHttpServer {
    param(
        [Parameter(Mandatory)] [int]$Port,
        [Parameter(Mandatory)] [hashtable]$Routes
    )
    $job = Start-Job -ScriptBlock {
        param([int]$Port, [hashtable]$Routes)
        $listener = New-Object System.Net.HttpListener
        $listener.Prefixes.Add("http://127.0.0.1:$Port/")
        try { $listener.Start() }
        catch {
            Write-Output "SERVER_ERROR|$($_.Exception.Message)"
            return
        }
        Write-Output 'READY'
        $logs = New-Object 'System.Collections.Generic.List[string]'
        try {
            $stop = $false
            while (-not $stop) {
                $context = $listener.GetContext()
                try {
                    $path = $context.Request.Url.AbsolutePath
                    $authorization = $context.Request.Headers['Authorization']
                    $logs.Add("REQUEST|$path|$authorization")
                    if ($path -eq '/shutdown') {
                        $statusCode = 200
                        $body = 'shutdown'
                        $location = $null
                        $stop = $true
                    }
                    else {
                        $route = $Routes[$path]
                        if ($null -eq $route) {
                            $statusCode = 404
                            $body = 'not found'
                            $location = $null
                        }
                        else {
                            $statusCode = [int]$route.Status
                            $body = [string]$route.Body
                            $location = if ($route.Location) { [string]$route.Location } else { $null }
                        }
                    }
                    $bodyBytes = [System.Text.Encoding]::UTF8.GetBytes($body)
                    $context.Response.StatusCode = $statusCode
                    $context.Response.ContentType = 'text/plain'
                    $context.Response.ContentLength64 = $bodyBytes.Length
                    if ($location) { $context.Response.RedirectLocation = $location }
                    $context.Response.OutputStream.Write($bodyBytes, 0, $bodyBytes.Length)
                    $context.Response.Close()
                }
                finally { if ($context) { $context.Response.Close() } }
            }
        }
        catch {
            $logs.Add("SERVER_ERROR|$($_.Exception.Message)")
        }
        finally { $listener.Stop() }
        foreach ($entry in $logs) { Write-Output $entry }
    } -ArgumentList $Port, $Routes

    $deadline = (Get-Date).AddSeconds(10)
    $ready = $false
    while ((Get-Date) -lt $deadline) {
        $output = @(Receive-Job -Job $job -Keep -ErrorAction SilentlyContinue)
        if ($output -contains 'READY') { $ready = $true; break }
        if (@($output | Where-Object { $_ -like 'SERVER_ERROR|*' }).Count -gt 0) { break }
        Start-Sleep -Milliseconds 100
    }
    if (-not $ready) {
        Stop-Job -Job $job -ErrorAction SilentlyContinue
        Remove-Job -Job $job -Force -ErrorAction SilentlyContinue
        throw "Loopback HTTP server failed to start on port $Port."
    }
    [pscustomobject]@{ Job = $job; Port = $Port; BaseUrl = "http://127.0.0.1:$Port" }
}

function Stop-LoopbackHttpServer {
    param([Parameter(Mandatory)] $Server)
    try {
        $client = New-Object System.Net.WebClient
        $client.Proxy = $null
        $null = $client.DownloadString("$($Server.BaseUrl)/shutdown")
    }
    catch { }
    $completed = Wait-Job -Job $Server.Job -Timeout 10
    if (-not $completed) { Stop-Job -Job $Server.Job -ErrorAction SilentlyContinue }
    $output = @(Receive-Job -Job $Server.Job -ErrorAction SilentlyContinue)
    Remove-Job -Job $Server.Job -Force -ErrorAction SilentlyContinue
    return $output
}

Invoke-RegressionTest -Name 'origin comparison includes scheme, host, and port' -ScriptBlock {
    Assert-ProductionFunctionAvailable -Name 'Get-UrlOrigin'
    Assert-True ((Get-UrlOrigin 'HTTPS://Example.test:443/path') -eq 'https://example.test:443') 'Origin was not normalized.'
    Assert-True ((Get-UrlOrigin 'http://example.test:8080/a') -ne (Get-UrlOrigin 'http://example.test:8081/a')) 'Ports were ignored.'
}

Invoke-RegressionTest -Name 'token is sent only to selected config origin' -ScriptBlock {
    Assert-ProductionFunctionAvailable -Name 'Get-UrlOrigin'
    Assert-ProductionFunctionAvailable -Name 'Test-ConfigTokenAllowedForUrl'
    $oldToken = $env:BOOTSTRAP_CONFIG_TOKEN
    try {
        $env:BOOTSTRAP_CONFIG_TOKEN = 'regression-token'
        $script:ConfigAuthOrigin = Get-UrlOrigin 'https://private.example.test:443/config.yaml'
        Assert-True (Test-ConfigTokenAllowedForUrl 'https://private.example.test/config.yaml') 'Same-origin token was denied.'
        Assert-True (-not (Test-ConfigTokenAllowedForUrl 'https://cdn.example.test/config.yaml')) 'Cross-origin token was allowed.'
    }
    finally { $env:BOOTSTRAP_CONFIG_TOKEN = $oldToken }
}

Invoke-RegressionTest -Name 'normal fetch preserves same-origin auth and strips it for resources' -ScriptBlock {
    Assert-ProductionFunctionAvailable -Name 'Get-ConfigText'
    Assert-ProductionFunctionAvailable -Name 'Test-ConfigTokenAllowedForUrl'
    $oldToken = $env:BOOTSTRAP_CONFIG_TOKEN
    $oldRequests = $script:BootstrapRegressionRequests
    try {
        $env:BOOTSTRAP_CONFIG_TOKEN = 'regression-token'
        $script:ConfigAuthOrigin = Get-UrlOrigin 'https://private.example.test:443/config.yaml'
        $script:BootstrapRegressionRequests = @()
        function global:Invoke-WebRequest {
            [CmdletBinding()]
            param($Uri, $Headers, [switch]$UseBasicParsing, [int]$MaximumRedirection)
            $script:BootstrapRegressionRequests += [pscustomobject]@{ Uri = $Uri; Headers = $Headers }
            [pscustomobject]@{ StatusCode = 200; Content = 'ok'; Headers = @{} }
        }
        $null = Get-ConfigText -Source ([pscustomobject]@{ Kind = 'Url'; Value = 'https://private.example.test/config.yaml' })
        $null = Get-ConfigText -Source ([pscustomobject]@{ Kind = 'Url'; Value = 'https://cdn.example.test/ca.pem' })
        Assert-True ($script:BootstrapRegressionRequests.Count -eq 2) 'Unexpected request count.'
        Assert-True ($script:BootstrapRegressionRequests[0].Headers['Authorization'] -eq 'Bearer regression-token') 'Config token was not sent to selected origin.'
        Assert-True (-not $script:BootstrapRegressionRequests[1].Headers.ContainsKey('Authorization')) 'Resource-origin request received config token.'
    }
    finally {
        Remove-Item Function:\Invoke-WebRequest -ErrorAction SilentlyContinue
        $env:BOOTSTRAP_CONFIG_TOKEN = $oldToken
        $script:BootstrapRegressionRequests = $oldRequests
    }
}

Invoke-RegressionTest -Name 'cross-origin authenticated redirect is rejected' -ScriptBlock {
    Assert-ProductionFunctionAvailable -Name 'Get-ConfigText'
    Assert-ProductionFunctionAvailable -Name 'Test-ConfigTokenAllowedForUrl'
    $oldToken = $env:BOOTSTRAP_CONFIG_TOKEN
    try {
        $env:BOOTSTRAP_CONFIG_TOKEN = 'regression-token'
        $script:ConfigAuthOrigin = Get-UrlOrigin 'https://private.example.test/config.yaml'
        function global:Invoke-WebRequest {
            [CmdletBinding()]
            param($Uri, $Headers, [switch]$UseBasicParsing, [int]$MaximumRedirection)
            [pscustomobject]@{
                StatusCode = 302
                Content = ''
                Headers = @{ Location = 'https://other.example.test/config.yaml' }
            }
        }
        Assert-Throws {
            Get-ConfigText -Source ([pscustomobject]@{ Kind = 'Url'; Value = 'https://private.example.test/config.yaml' })
        } 'Cross-origin redirect was accepted.'
    }
    finally {
        Remove-Item Function:\Invoke-WebRequest -ErrorAction SilentlyContinue
        $env:BOOTSTRAP_CONFIG_TOKEN = $oldToken
    }
}

Invoke-RegressionTest -Name 'HTTP error is not treated as a successful config fetch' -ScriptBlock {
    Assert-ProductionFunctionAvailable -Name 'Get-ConfigText'
    Assert-ProductionFunctionAvailable -Name 'Test-ConfigTokenAllowedForUrl'
    try {
        $script:ConfigAuthOrigin = Get-UrlOrigin 'https://private.example.test/config.yaml'
        function global:Invoke-WebRequest {
            [CmdletBinding()]
            param($Uri, $Headers, [switch]$UseBasicParsing, [int]$MaximumRedirection)
            [pscustomobject]@{ StatusCode = 503; Content = 'unavailable'; Headers = @{} }
        }
        Assert-Throws {
            Get-ConfigText -Source ([pscustomobject]@{ Kind = 'Url'; Value = 'https://private.example.test/config.yaml' })
        } 'HTTP 503 did not fail.'
    }
    finally { Remove-Item Function:\Invoke-WebRequest -ErrorAction SilentlyContinue }
}

Invoke-RegressionTest -Name 'insecure curl fetch returns the downloaded body' -ScriptBlock {
    Assert-ProductionFunctionAvailable -Name 'Get-ConfigText'
    Assert-ProductionFunctionAvailable -Name 'Invoke-WithoutBootstrapTranscript'
    Assert-ProductionFunctionAvailable -Name 'Set-BootstrapTranscriptAcl'
    $script:TranscriptActive = $false
    $oldToken = $env:BOOTSTRAP_CONFIG_TOKEN
    $env:BOOTSTRAP_CONFIG_TOKEN = 'curl-regression-token'
    $script:ConfigAuthOrigin = Get-UrlOrigin 'https://private.example.test/config.yaml'
    $script:CapturedCurlArguments = @()
    function global:curl.exe {
        $curlArgs = @($args)
        $script:CapturedCurlArguments = $curlArgs
        $bodyPath = $curlArgs[$curlArgs.IndexOf('-o') + 1]
        $headersPath = $curlArgs[$curlArgs.IndexOf('-D') + 1]
        Set-Content -LiteralPath $bodyPath -Value 'curl-regression-body' -NoNewline
        Set-Content -LiteralPath $headersPath -Value 'HTTP/1.1 200 OK' -NoNewline
        $global:LASTEXITCODE = 0
        return '200'
    }
    try {
        $body = Get-ConfigText -Source ([pscustomobject]@{ Kind = 'Url'; Value = 'https://private.example.test/config.yaml' }) -SkipCertCheck
        Assert-True ($body -eq 'curl-regression-body') 'Insecure fetch returned null or the wrong body.'
        Assert-True ($script:CapturedCurlArguments[0] -eq '-q') 'Insecure curl fetch does not disable default curl configuration first.'
        Assert-True (-not (($script:CapturedCurlArguments -join ' ').Contains('curl-regression-token'))) 'Bearer token was exposed in curl process arguments.'
    }
    finally {
        Remove-Item Function:\curl.exe -ErrorAction SilentlyContinue
        $env:BOOTSTRAP_CONFIG_TOKEN = $oldToken
    }
}

Invoke-RegressionTest -Name 'loopback HTTP exercises auth, redirects, resources, errors, and curl' -ScriptBlock {
    Assert-ProductionFunctionAvailable -Name 'Get-ConfigText'
    Assert-ProductionFunctionAvailable -Name 'Get-UrlOrigin'
    $oldToken = $env:BOOTSTRAP_CONFIG_TOKEN
    $serverOne = $null
    $serverTwo = $null
    try {
        $portOne = Get-FreeLoopbackPort
        $portTwo = Get-FreeLoopbackPort
        $routesOne = @{
            '/config.yaml' = @{ Status = 200; Body = 'loopback-config' }
            '/redirect-same' = @{ Status = 302; Body = ''; Location = '/config.yaml' }
            '/redirect-cross' = @{ Status = 302; Body = ''; Location = "http://127.0.0.1:$portTwo/config.yaml" }
            '/missing' = @{ Status = 404; Body = 'missing' }
        }
        $routesTwo = @{
            '/config.yaml' = @{ Status = 200; Body = 'external-config' }
            '/resource' = @{ Status = 200; Body = 'external-resource' }
        }
        $serverOne = Start-LoopbackHttpServer -Port $portOne -Routes $routesOne
        $serverTwo = Start-LoopbackHttpServer -Port $portTwo -Routes $routesTwo
        $env:BOOTSTRAP_CONFIG_TOKEN = 'loopback-token'
        $script:ConfigAuthOrigin = Get-UrlOrigin "$($serverOne.BaseUrl)/config.yaml"

        $directBody = Get-ConfigText -Source ([pscustomobject]@{ Kind = 'Url'; Value = "$($serverOne.BaseUrl)/config.yaml" })
        Assert-True ($directBody -eq 'loopback-config') 'Direct loopback IWR fetch returned the wrong body.'
        $sameOriginBody = Get-ConfigText -Source ([pscustomobject]@{ Kind = 'Url'; Value = "$($serverOne.BaseUrl)/redirect-same" })
        Assert-True ($sameOriginBody -eq 'loopback-config') 'Same-origin redirect returned the wrong body.'

        $externalBody = Get-ConfigText -Source ([pscustomobject]@{ Kind = 'Url'; Value = "$($serverTwo.BaseUrl)/resource" })
        Assert-True ($externalBody -eq 'external-resource') 'External resource returned the wrong body.'

        Assert-Throws {
            Get-ConfigText -Source ([pscustomobject]@{ Kind = 'Url'; Value = "$($serverOne.BaseUrl)/redirect-cross" })
        } 'Cross-origin redirect was not rejected.'
        Assert-Throws {
            Get-ConfigText -Source ([pscustomobject]@{ Kind = 'Url'; Value = "$($serverOne.BaseUrl)/missing" })
        } 'HTTP 404 did not fail.'

        $curlBody = Get-ConfigText -Source ([pscustomobject]@{ Kind = 'Url'; Value = "$($serverOne.BaseUrl)/config.yaml" }) -SkipCertCheck
        Assert-True ($curlBody -eq 'loopback-config') 'Curl fetch returned the wrong body.'
        $curlRedirectBody = Get-ConfigText -Source ([pscustomobject]@{ Kind = 'Url'; Value = "$($serverOne.BaseUrl)/redirect-same" }) -SkipCertCheck
        Assert-True ($curlRedirectBody -eq 'loopback-config') 'Curl same-origin redirect returned the wrong body.'
        $curlResourceBody = Get-ConfigText -Source ([pscustomobject]@{ Kind = 'Url'; Value = "$($serverTwo.BaseUrl)/resource" }) -SkipCertCheck
        Assert-True ($curlResourceBody -eq 'external-resource') 'Curl external resource returned the wrong body.'
        Assert-Throws {
            Get-ConfigText -Source ([pscustomobject]@{ Kind = 'Url'; Value = "$($serverOne.BaseUrl)/redirect-cross" }) -SkipCertCheck
        } 'Curl cross-origin redirect was not rejected.'
        Assert-Throws {
            Get-ConfigText -Source ([pscustomobject]@{ Kind = 'Url'; Value = "$($serverOne.BaseUrl)/missing" }) -SkipCertCheck
        } 'Curl HTTP 404 did not fail.'
    }
    finally {
        $serverTwoOutput = if ($serverTwo) { @(Stop-LoopbackHttpServer -Server $serverTwo) } else { @() }
        $serverOneOutput = if ($serverOne) { @(Stop-LoopbackHttpServer -Server $serverOne) } else { @() }
        $env:BOOTSTRAP_CONFIG_TOKEN = $oldToken
    }

    $sameAuth = @($serverOneOutput | Where-Object { $_ -eq 'REQUEST|/redirect-same|Bearer loopback-token' })
    Assert-True ($sameAuth.Count -eq 2) 'Both HTTP clients must send Authorization to the same-origin redirect.'
    $sameFinalAuth = @($serverOneOutput | Where-Object { $_ -eq 'REQUEST|/config.yaml|Bearer loopback-token' })
    Assert-True ($sameFinalAuth.Count -ge 1) 'Same-origin redirected request did not preserve Authorization.'
    $resourceAuth = @($serverTwoOutput | Where-Object { $_ -like 'REQUEST|/resource|*' })
    Assert-True ($resourceAuth.Count -eq 2 -and @($resourceAuth | Where-Object { $_ -ne 'REQUEST|/resource|' }).Count -eq 0) 'External resource received Authorization.'
    $crossFollowed = @($serverTwoOutput | Where-Object { $_ -like 'REQUEST|/config.yaml|*' })
    Assert-True ($crossFollowed.Count -eq 0) 'Cross-origin redirect reached the other origin.'
}

Invoke-RegressionTest -Name 'first-login template keeps retryable state on install failure' -ScriptBlock {
    Assert-ProductionFunctionAvailable -Name 'Register-FirstLoginTask'
    $script:CapturedFirstLoginTemplate = $null
    function global:Get-ScheduledTask { [CmdletBinding()] param([string]$TaskName) return $null }
    function global:New-Item { [CmdletBinding()] param([string]$Path, [string]$ItemType, [switch]$Force) return [pscustomobject]@{} }
    function global:Set-Content {
        [CmdletBinding()] param($Path, $Value, [switch]$NoNewline, [string]$Encoding)
        if ($Path -like '*first-login-*.ps1') { $script:CapturedFirstLoginTemplate = [string]$Value }
    }
    function global:New-ScheduledTaskAction { [CmdletBinding()] param([string]$Execute, [string]$Argument) return [pscustomobject]@{} }
    function global:New-ScheduledTaskTrigger { [CmdletBinding()] param([switch]$AtLogOn, [string]$User) return [pscustomobject]@{ Delay = $null } }
    function global:New-ScheduledTaskPrincipal { [CmdletBinding()] param([string]$UserId, [string]$LogonType, [string]$RunLevel) return [pscustomobject]@{} }
    function global:Register-ScheduledTask { [CmdletBinding()] param([string]$TaskName, $Action, $Trigger, $Principal, [switch]$Force) }
    try {
        Register-FirstLoginTask -UserName 'regression-user' -Apps @([pscustomobject]@{ Id = 'Contoso.App'; DesktopShortcut = $false })
        Assert-True (-not [string]::IsNullOrEmpty([string]$script:CapturedFirstLoginTemplate)) 'First-login template was not captured.'
        Assert-True ($script:CapturedFirstLoginTemplate.Contains('$allSucceeded = $true')) 'Template lacks aggregate install status.'
        Assert-True ($script:CapturedFirstLoginTemplate.Contains('if (-not $allSucceeded)')) 'Template lacks retryable failure branch.'
        Assert-True ($script:CapturedFirstLoginTemplate.Contains('Test-WingetInstallSuccess')) 'Template does not accept already-installed winget statuses.'
        $markerIndex = $script:CapturedFirstLoginTemplate.IndexOf('New-Item -ItemType File -Path $markerPath')
        $failureIndex = $script:CapturedFirstLoginTemplate.IndexOf('if (-not $allSucceeded)')
        Assert-True ($markerIndex -gt $failureIndex) 'Completion marker is created before failure handling.'
        Assert-True ($script:CapturedFirstLoginTemplate.Contains('exit 1')) 'Template does not return nonzero on failure.'
    }
    finally {
        foreach ($name in @('Get-ScheduledTask', 'New-Item', 'Set-Content', 'New-ScheduledTaskAction', 'New-ScheduledTaskTrigger', 'New-ScheduledTaskPrincipal', 'Register-ScheduledTask')) {
            Remove-Item "Function:\$name" -ErrorAction SilentlyContinue
        }
    }
}

Invoke-RegressionTest -Name 'transcript is disabled for validation and verification and ACL uses well-known SIDs' -ScriptBlock {
    $text = Get-Content -LiteralPath $ScriptPath -Raw
    $transcriptGuardIndex = $text.LastIndexOf('if (-not $ValidateConfig -and -not $Verify)')
    $elevationGateIndex = $text.IndexOf('if (-not (Test-IsAdmin))')
    Assert-True ($transcriptGuardIndex -gt $elevationGateIndex) 'Transcript must start only after the elevation gate.'
    Assert-True ($text.Contains('S-1-5-18')) 'SYSTEM well-known SID is missing from transcript ACL.'
    Assert-True ($text.Contains('S-1-5-32-544')) 'Administrators well-known SID is missing from transcript ACL.'
    Assert-True ($text.Contains("[Environment]::GetFolderPath([Environment+SpecialFolder]::Windows)) 'Logs\win-bootstrap'")) 'Transcript path is not rooted below the protected Windows log directory.'
    Assert-True ($text.Contains('Assert-NotReparsePoint')) 'Transcript paths are not checked for reparse points.'
    Assert-True ($text.Contains('AllowCurrentUser')) 'Ephemeral curl header ACL lacks current-user support.'
    Assert-True ($text.Contains('Invoke-WithoutBootstrapTranscript')) 'Secret handoff does not suspend transcript.'
    Assert-True ($text.Contains('exit $script:BootstrapExitCode')) 'Bootstrap does not return an explicit aggregate process status.'
}

Invoke-RegressionTest -Name 'whole-list apps.disabled also skips first-login scheduling' -ScriptBlock {
    $text = Get-Content -LiteralPath $ScriptPath -Raw
    Assert-True ($text.Contains('$userScopeAppsForLogin = if ($appsDisabled)')) 'First-login app selection does not honor whole-list apps.disabled.'
    Assert-True ($text.Contains('elseif ($appsDisabled)') -and $text.Contains("'apps.disabled' is set to true")) 'First-login scheduling has no explicit apps.disabled skip reason.'
}

Invoke-RegressionTest -Name 'protected transcript can start and stop in a temporary directory' -ScriptBlock {
    if ($env:OS -ne 'Windows_NT') {
        Write-Host 'SKIP: protected transcript runtime check requires Windows ACL support.' -ForegroundColor Yellow
        return
    }
    Assert-ProductionFunctionAvailable -Name 'Start-BootstrapTranscript'
    Assert-ProductionFunctionAvailable -Name 'Stop-BootstrapTranscript'
    Assert-ProductionFunctionAvailable -Name 'Assert-NotReparsePoint'
    $temporaryTranscriptDir = Join-Path ([IO.Path]::GetTempPath()) "bootstrap-regression-$([guid]::NewGuid().ToString('N'))"
    New-Item -ItemType Directory -Path $temporaryTranscriptDir -Force | Out-Null
    try {
        $everyoneSid = New-Object System.Security.Principal.SecurityIdentifier -ArgumentList 'S-1-1-0'
        $everyoneRule = New-Object System.Security.AccessControl.FileSystemAccessRule -ArgumentList @(
            $everyoneSid,
            [System.Security.AccessControl.FileSystemRights]::Read,
            [System.Security.AccessControl.InheritanceFlags]::None,
            [System.Security.AccessControl.PropagationFlags]::None,
            [System.Security.AccessControl.AccessControlType]::Allow
        )
        $directoryAcl = Get-Acl -LiteralPath $temporaryTranscriptDir
        [void]$directoryAcl.AddAccessRule($everyoneRule)
        Set-Acl -LiteralPath $temporaryTranscriptDir -AclObject $directoryAcl
        $oldLogPath = Join-Path $temporaryTranscriptDir 'bootstrap-run-old.log'
        New-Item -ItemType File -Path $oldLogPath -Force | Out-Null
        $oldLogAcl = Get-Acl -LiteralPath $oldLogPath
        [void]$oldLogAcl.AddAccessRule($everyoneRule)
        Set-Acl -LiteralPath $oldLogPath -AclObject $oldLogAcl
        $script:TranscriptBaseDir = $temporaryTranscriptDir
        $script:TranscriptPath = $null
        $script:TranscriptActive = $false
        Start-BootstrapTranscript
        Assert-True $script:TranscriptActive 'Protected transcript did not start.'
        $firstTranscriptPath = $script:TranscriptPath
        Add-Content -Path (Join-Path $temporaryTranscriptDir 'bootstrap-runtime-marker.txt') -Value 'not part of transcript'
        $directorySids = @(Get-Acl $temporaryTranscriptDir).Access | ForEach-Object {
            $_.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value
        }
        $fileSids = @(Get-Acl $script:TranscriptPath).Access | ForEach-Object {
            $_.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value
        }
        $oldLogSids = @(Get-Acl $oldLogPath).Access | ForEach-Object {
            $_.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value
        }
        Assert-True ($directorySids -contains 'S-1-5-18') 'Transcript directory lacks SYSTEM SID ACL.'
        Assert-True ($fileSids -contains 'S-1-5-18') 'Transcript file lacks SYSTEM SID ACL.'
        Assert-True ($directorySids -notcontains 'S-1-1-0') 'Transcript directory retained an explicit Everyone ACE.'
        Assert-True ($fileSids -notcontains 'S-1-1-0') 'Transcript file retained an explicit Everyone ACE.'
        Assert-True ($oldLogSids -notcontains 'S-1-1-0') 'Existing transcript retained an explicit Everyone ACE.'
        Stop-BootstrapTranscript
        Assert-True (-not $script:TranscriptActive) 'Protected transcript did not stop.'
        Start-BootstrapTranscript
        Assert-True ($script:TranscriptPath -eq $firstTranscriptPath) 'Transcript resume created a different log path.'
        Stop-BootstrapTranscript
    }
    finally {
        if ($script:TranscriptActive) { Stop-BootstrapTranscript }
        Remove-Item -LiteralPath $temporaryTranscriptDir -Recurse -Force -ErrorAction SilentlyContinue
    }
}

Invoke-RegressionTest -Name 'insecure curl path avoids token argv and checks HTTP status' -ScriptBlock {
    $text = Get-Content -LiteralPath $ScriptPath -Raw
    Assert-True ($text.Contains("`$curlArgs = @('-q', '-k'")) 'Insecure fetch does not disable default curl configuration first.'
    Assert-True (-not $text.Contains('$curlArgs = @(''-k'', ''-sS'', ''-L''')) 'Insecure fetch still uses curl automatic redirects.'
    Assert-True ($text.Contains('$curlArgs += @(''-H'', "@$headerFile")')) 'Insecure fetch does not use a temporary header file.'
    Assert-True ($text.Contains('if ($statusCode -ge 400)')) 'Insecure fetch does not reject HTTP errors.'
}

Write-Host "`n$script:Passed passed, $script:Failed failed." -ForegroundColor Cyan
if ($script:Failed -gt 0) { exit 1 }
exit 0
