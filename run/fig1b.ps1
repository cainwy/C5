param(
  [int]$Reps = 10,
  [int]$Warmups = 1,
  [string]$Profiles = "1024,3072",
  [string]$WslRoot = "",
  [switch]$DryRun
)
# Fig. 1(b): chaincode verification on the real Fabric network.
# The network and the driver run inside WSL, so this script only forwards the
# parameters to run/fabric_onchain.sh.
$ErrorActionPreference = 'Stop'
. "$PSScriptRoot\_env.ps1"
if (-not $WslRoot) {
  $WslRoot = "/mnt/" + ($Root.Substring(0, 1).ToLower()) + ($Root.Substring(2) -replace '\\', '/')
}
$bits = ($Profiles -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ }) -join ' '
$inner = "REPS=$Reps WARMUPS=$Warmups GAI_PROFILES='$bits' bash '$WslRoot/run/fabric_onchain.sh' fig1b"

if ($DryRun) {
  Write-Host "wsl -e bash -c `"$inner`""
  exit 0
}
& "$PSScriptRoot\build_onchain.ps1" | Out-Null
wsl -e bash -c $inner
exit $LASTEXITCODE
