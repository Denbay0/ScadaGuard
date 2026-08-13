[CmdletBinding()]
param(
    [switch]$InstallMissing
)

$ErrorActionPreference = 'Stop'
$requestedVcpkgRoot = $env:VCPKG_ROOT

function Find-VisualStudio {
    $vswhereCandidates = @(
        "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe",
        "$env:ProgramFiles\Microsoft Visual Studio\Installer\vswhere.exe"
    )

    foreach ($candidate in $vswhereCandidates) {
        if ($candidate -and (Test-Path -LiteralPath $candidate)) {
            $installation = & $candidate -prerelease -latest -products * `
                -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 `
                -property installationPath
            if ($installation) {
                return $installation
            }
        }
    }
    return $null
}

function Install-WithWinget {
    param(
        [Parameter(Mandatory)]
        [string]$Id,
        [string]$Override = ''
    )

    if (-not (Get-Command winget -ErrorAction SilentlyContinue)) {
        throw "winget is not available. Install the missing component manually."
    }

    $arguments = @(
        'install', '--id', $Id, '--exact', '--silent',
        '--accept-package-agreements', '--accept-source-agreements'
    )
    if ($Override) {
        $arguments += @('--override', $Override)
    }
    & winget @arguments
    if ($LASTEXITCODE -ne 0) {
        throw "winget failed to install $Id (exit code $LASTEXITCODE)."
    }
}

$missing = [System.Collections.Generic.List[string]]::new()
$visualStudio = Find-VisualStudio
if (-not $visualStudio) {
    $missing.Add('Visual Studio 2022 Build Tools with Desktop development with C++')
}

$bundledCMake = if ($visualStudio) {
    Join-Path $visualStudio 'Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin'
} else {
    $null
}
if (-not (Get-Command cmake -ErrorAction SilentlyContinue) -and $bundledCMake -and
    (Test-Path -LiteralPath (Join-Path $bundledCMake 'cmake.exe'))) {
    $env:PATH = "$bundledCMake;$env:PATH"
}

if (-not (Get-Command cmake -ErrorAction SilentlyContinue)) {
    $missing.Add('CMake 3.25 or newer')
}

if (-not $env:VCPKG_ROOT) {
    $missing.Add('VCPKG_ROOT environment variable')
} elseif (-not (Test-Path -LiteralPath "$env:VCPKG_ROOT\scripts\buildsystems\vcpkg.cmake")) {
    $missing.Add("valid vcpkg checkout at VCPKG_ROOT ($env:VCPKG_ROOT)")
}

if ($missing.Count -gt 0 -and $InstallMissing) {
    Write-Host 'Explicit installation was requested. System packages may require elevation.'
    if (-not $visualStudio) {
        Install-WithWinget -Id 'Microsoft.VisualStudio.2022.BuildTools' -Override (
            '--wait --quiet --norestart ' +
            '--add Microsoft.VisualStudio.Workload.VCTools ' +
            '--includeRecommended'
        )
    }
    if (-not (Get-Command cmake -ErrorAction SilentlyContinue)) {
        Install-WithWinget -Id 'Kitware.CMake'
    }
    Write-Host 'Refresh the terminal PATH, configure VCPKG_ROOT, and run this script again.'
    exit 0
}

if ($missing.Count -gt 0) {
    Write-Error (@"
ScadaGuard build prerequisites are missing:
  - $($missing -join "`n  - ")

No software was installed and the system was not modified.

Install Visual Studio Build Tools 2022 with the C++ workload and CMake, then prepare vcpkg:
  winget install --id Microsoft.VisualStudio.2022.BuildTools --exact
  winget install --id Kitware.CMake --exact
  git clone https://github.com/microsoft/vcpkg C:\Tools\vcpkg
  C:\Tools\vcpkg\bootstrap-vcpkg.bat
  `$env:VCPKG_ROOT = 'C:\Tools\vcpkg'

Alternatively, rerun with -InstallMissing to explicitly authorize winget installation of
Visual Studio Build Tools and CMake. vcpkg remains an explicit checkout managed by you.
"@)
}

$vcvars = Join-Path $visualStudio 'VC\Auxiliary\Build\vcvars64.bat'
if (-not (Test-Path -LiteralPath $vcvars)) {
    throw "MSVC x64 environment script was not found: $vcvars"
}

$devShell = Join-Path $visualStudio 'Common7\Tools\Microsoft.VisualStudio.DevShell.dll'
if (Test-Path -LiteralPath $devShell) {
    Import-Module $devShell
    Enter-VsDevShell -VsInstallPath $visualStudio -SkipAutomaticLocation -DevCmdArguments '-arch=amd64 -host_arch=amd64'
} else {
    $environment = & cmd.exe /s /c "`"$vcvars`" >nul && set"
    if ($LASTEXITCODE -ne 0) {
        throw 'Failed to activate the Visual Studio x64 developer environment.'
    }
    foreach ($line in $environment) {
        $name, $value = $line -split '=', 2
        if ($name -and $null -ne $value) {
            Set-Item -Path "Env:$name" -Value $value
        }
    }
}

if ($requestedVcpkgRoot) {
    $env:VCPKG_ROOT = $requestedVcpkgRoot
}
$env:VSLANG = '1033'

Write-Host "Visual Studio: $visualStudio"
Write-Host "CMake: $((Get-Command cmake).Source)"
Write-Host "vcpkg: $env:VCPKG_ROOT"
Write-Host 'ScadaGuard Windows build prerequisites are available.'
