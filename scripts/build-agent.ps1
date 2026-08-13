[CmdletBinding()]
param(
    [ValidateSet('Debug', 'Release', 'RelWithDebInfo')]
    [string]$Configuration = 'RelWithDebInfo',
    [switch]$InstallMissing
)

$ErrorActionPreference = 'Stop'
$repositoryRoot = Split-Path -Parent $PSScriptRoot

& "$PSScriptRoot\bootstrap-windows.ps1" -InstallMissing:$InstallMissing
if ($LASTEXITCODE -ne 0) {
    exit $LASTEXITCODE
}

Push-Location $repositoryRoot
try {
    cmake --preset windows-msvc
    if ($LASTEXITCODE -ne 0) { throw 'CMake configuration failed.' }

    cmake --build --preset windows-msvc --config $Configuration
    if ($LASTEXITCODE -ne 0) { throw 'Agent build failed.' }
} finally {
    Pop-Location
}
