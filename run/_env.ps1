# Execution environment for the Windows experiment scripts.
# Do not ship workstation-specific absolute paths. The installed Go toolchain
# must be accessible on PATH, or THESIS_GOROOT must point to its installation.
$Root = Split-Path -Parent $PSScriptRoot
Set-Location $Root

if ($env:THESIS_GOROOT) {
  $env:GOROOT = $env:THESIS_GOROOT
  $env:PATH = "$env:GOROOT\bin;$env:PATH"
}
if ($env:THESIS_GOPATH) { $env:GOPATH = $env:THESIS_GOPATH }
if (-not (Get-Command go -ErrorAction SilentlyContinue)) {
  throw 'Go is not available. Install Go 1.25.7 or set THESIS_GOROOT to its root.'
}
$env:GO111MODULE = 'on'
$env:GOTOOLCHAIN = 'local'
$env:GOMAXPROCS = '4'

$DataRoot = Join-Path $Root 'data'
$FigRoot = Join-Path $Root 'figures'
$LogRoot = Join-Path $Root 'data\logs'
New-Item -ItemType Directory -Force -Path $DataRoot, $FigRoot, $LogRoot | Out-Null
