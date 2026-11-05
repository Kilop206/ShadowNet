param(
    [string]$BuildDir = 'build/mingw',
    [string]$MingwRoot = 'C:/mingw64'
)
$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $PSScriptRoot
$buildPath = (Resolve-Path -LiteralPath $BuildDir).Path
$compiler = Join-Path $MingwRoot 'bin/g++.exe'
$gccVersion = (& $compiler -dumpversion).Trim()
if ($LASTEXITCODE -ne 0) { throw 'Cannot determine MinGW version' }
$arguments = @(
    '-p', $buildPath,
    '--extra-arg=--target=x86_64-w64-windows-gnu',
    "--extra-arg=-isystem$MingwRoot/include/c++/$gccVersion",
    "--extra-arg=-isystem$MingwRoot/include/c++/$gccVersion/x86_64-w64-mingw32",
    "--extra-arg=-isystem$MingwRoot/x86_64-w64-mingw32/include",
    "--extra-arg=-isystem$MingwRoot/include"
)
$sources = @(rg --files (Join-Path $repoRoot 'libs') (Join-Path $repoRoot 'apps') -g '*.cpp')
if ($LASTEXITCODE -ne 0 -or $sources.Count -eq 0) { throw 'Cannot discover C++ sources (requires rg)' }
# Windows PowerShell 5 wraps native stderr as ErrorRecord, even on exit 0.
# Preserve diagnostics as text and use clang-tidy's exit status as the result.
$ErrorActionPreference = 'Continue'
& clang-tidy @arguments @sources 2>&1 | ForEach-Object { $_.ToString() }
exit $LASTEXITCODE
