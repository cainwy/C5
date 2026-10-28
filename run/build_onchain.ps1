# Cross-compile the on-chain driver for the Linux container host (WSL).
param([string]$Out = "")
$ErrorActionPreference = 'Stop'
. "$PSScriptRoot\_env.ps1"
if (-not $Out) { $Out = Join-Path $Root 'bin\onchain_linux' }
New-Item -ItemType Directory -Force -Path (Split-Path -Parent $Out) | Out-Null

Push-Location (Join-Path $Root 'blockchain')
$env:GOOS = 'linux'
$env:GOARCH = 'amd64'
$env:CGO_ENABLED = '0'
go build -trimpath -o $Out ./experiments/cmd/onchain
$code = $LASTEXITCODE
Pop-Location
if ($code -ne 0) { exit $code }
Get-Item $Out | Select-Object FullName, Length
