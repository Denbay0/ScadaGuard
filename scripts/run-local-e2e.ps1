[CmdletBinding()]
param(
    [switch]$TestOfflineRecovery
)

$ErrorActionPreference = 'Stop'
$repositoryRoot = Split-Path -Parent $PSScriptRoot
$dockerCommand = Get-Command docker.exe -ErrorAction SilentlyContinue
if (-not $dockerCommand) {
    $dockerBin = Join-Path $env:LOCALAPPDATA 'Programs\DockerDesktop\resources\bin'
    $dockerPath = Join-Path $dockerBin 'docker.exe'
    if (-not (Test-Path -LiteralPath $dockerPath -PathType Leaf)) {
        throw 'Docker CLI was not found.'
    }
    $env:PATH = "$dockerBin;$env:PATH"
} else {
    $dockerPath = $dockerCommand.Source
}

$compose = @(
    'compose',
    '-f', (Join-Path $repositoryRoot 'deploy\docker-compose.yml'),
    '-f', (Join-Path $repositoryRoot 'deploy\docker-compose.dev.yml'),
    '--env-file', (Join-Path $repositoryRoot 'deploy\.env')
)
$agentExecutable = Join-Path $repositoryRoot 'build\windows-msvc\RelWithDebInfo\scadaguard.exe'
$agentConfiguration = Join-Path $repositoryRoot 'config\config.local-masterscada.json'
if (-not (Test-Path -LiteralPath $agentExecutable -PathType Leaf)) {
    throw 'Build the Windows Agent before running E2E.'
}

$randomBytes = New-Object byte[] 24
$randomGenerator = [Security.Cryptography.RandomNumberGenerator]::Create()
$randomGenerator.GetBytes($randomBytes)
$randomGenerator.Dispose()
$adminPassword = [Convert]::ToBase64String($randomBytes)
$adminUsername = 'e2e-' + [Guid]::NewGuid().ToString('N').Substring(0, 12)
$bootstrapOutput = $null
$agentProcess = $null
$session = New-Object Microsoft.PowerShell.Commands.WebRequestSession

function Invoke-Compose {
    & $dockerPath @compose @args
    if ($LASTEXITCODE -ne 0) {
        throw "Docker Compose command failed: $($args -join ' ')"
    }
}

function Start-IntegrationAgent {
    $existing = Get-CimInstance Win32_Process -Filter "Name='scadaguard.exe'" |
        Where-Object { $_.CommandLine -like '*config.local-masterscada.json*' }
    if ($existing) {
        throw 'A local MasterSCADA integration Agent is already running.'
    }
    $stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
    $outputLog = Join-Path $repositoryRoot "build\e2e-agent-$stamp.out.log"
    $errorLog = Join-Path $repositoryRoot "build\e2e-agent-$stamp.err.log"
    Start-Process -FilePath $agentExecutable `
        -ArgumentList '--console', '--config', $agentConfiguration `
        -PassThru -WindowStyle Hidden `
        -RedirectStandardOutput $outputLog -RedirectStandardError $errorLog
}

function Get-AgentView {
    $agents = Invoke-RestMethod -Uri 'http://localhost:8080/api/v1/agents' -WebSession $session
    $agents | Where-Object { $_.agent_id -eq 'local-masterscada' } | Select-Object -First 1
}

try {
    Invoke-Compose up -d --build
    $env:SCADAGUARD_BOOTSTRAP_PASSWORD = $adminPassword
    Invoke-Compose exec -T -e "SCADAGUARD_BOOTSTRAP_PASSWORD=$adminPassword" server `
        python -m app.cli create-admin --username $adminUsername | Out-Null
    $bootstrapOutput = Invoke-Compose exec -T server python -m app.cli bootstrap-demo `
        --host-id local-windows
    $tokenLine = $bootstrapOutput | Where-Object { $_ -like 'SCADAGUARD_API_TOKEN=*' } |
        Select-Object -Last 1
    if (-not $tokenLine) {
        throw 'Bootstrap did not return an Agent token.'
    }
    $env:SCADAGUARD_API_TOKEN = $tokenLine.Substring('SCADAGUARD_API_TOKEN='.Length)

    $loginBody = @{ username = $adminUsername; password = $adminPassword } | ConvertTo-Json
    $login = Invoke-RestMethod -Uri 'http://localhost:8080/api/v1/auth/login' -Method Post `
        -ContentType 'application/json' -Body $loginBody -WebSession $session

    $agentProcess = Start-IntegrationAgent
    Start-Sleep -Seconds 22
    if ($agentProcess.HasExited) {
        throw "Agent exited unexpectedly with code $($agentProcess.ExitCode)."
    }
    $agent = Get-AgentView
    if (-not $agent) {
        throw 'Agent is not visible through the Web API.'
    }
    $discovery = Invoke-RestMethod `
        -Uri "http://localhost:8080/api/v1/agents/$($agent.id)/discovery" -WebSession $session
    $databaseCheck = Invoke-Compose exec -T postgres psql -U scadaguard -d scadaguard -Atc `
        "SELECT (last_seen_at IS NOT NULL)::int || ',' || (SELECT count(*) FROM agent_discovery_reports WHERE agent_id=agents.id) FROM agents WHERE agent_id='local-masterscada';"

    $offlineIncident = 0
    $recoveredIncident = 0
    if ($TestOfflineRecovery) {
        Stop-Process -Id $agentProcess.Id -ErrorAction Stop
        $agentProcess.WaitForExit()
        Start-Sleep -Seconds 48
        $offlineIncident = [int](Invoke-Compose exec -T postgres psql -U scadaguard -d scadaguard -Atc `
            "SELECT count(*) FROM incidents WHERE agent_id=(SELECT id FROM agents WHERE agent_id='local-masterscada') AND status='open' AND details->>'problem_type'='agent_offline';")
        if ($offlineIncident -lt 1) {
            throw 'agent_offline incident was not opened.'
        }
        $agentProcess = Start-IntegrationAgent
        Start-Sleep -Seconds 32
        $recoveredIncident = [int](Invoke-Compose exec -T postgres psql -U scadaguard -d scadaguard -Atc `
            "SELECT count(*) FROM incidents WHERE agent_id=(SELECT id FROM agents WHERE agent_id='local-masterscada') AND status='closed' AND details->>'problem_type'='agent_offline';")
        if ($recoveredIncident -lt 1) {
            throw 'agent_offline incident was not recovered.'
        }
    }

    [pscustomobject]@{
        containers = 'healthy'
        web_role = $login.role
        agent_pid = $agentProcess.Id
        agent_last_seen = $agent.last_seen_at
        heartbeat_and_discovery_rows = $databaseCheck
        discovery_scan = $discovery.scan_id
        masterscada_detected = $discovery.masterscada.detected
        masterscada_version = $discovery.masterscada.version
        archive_candidates = $discovery.archive_candidates.Count
        log_candidates = $discovery.log_candidates.Count
        offline_incident = $offlineIncident
        recovered_incident = $recoveredIncident
    } | ConvertTo-Json
} catch {
    if ($agentProcess -and -not $agentProcess.HasExited) {
        Stop-Process -Id $agentProcess.Id -ErrorAction SilentlyContinue
    }
    throw
} finally {
    if ($adminUsername) {
        & $dockerPath @compose exec -T postgres psql -U scadaguard -d scadaguard -Atc `
            "DELETE FROM users WHERE username='$adminUsername';" | Out-Null
    }
    Remove-Item Env:\SCADAGUARD_API_TOKEN -ErrorAction SilentlyContinue
    Remove-Item Env:\SCADAGUARD_BOOTSTRAP_PASSWORD -ErrorAction SilentlyContinue
    $adminPassword = $null
    $bootstrapOutput = $null
}
