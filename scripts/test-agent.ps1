[CmdletBinding()]
param(
    [ValidateSet('Debug', 'Release', 'RelWithDebInfo')]
    [string]$Configuration = 'RelWithDebInfo'
)

$ErrorActionPreference = 'Stop'
$repositoryRoot = Split-Path -Parent $PSScriptRoot

& "$PSScriptRoot\build-agent.ps1" -Configuration $Configuration
if ($LASTEXITCODE -ne 0) {
    exit $LASTEXITCODE
}

Push-Location $repositoryRoot
try {
    ctest --preset windows-msvc --build-config $Configuration --output-on-failure
    if ($LASTEXITCODE -ne 0) { throw 'Agent tests failed.' }
} finally {
    Pop-Location
}
