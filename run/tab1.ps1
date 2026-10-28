param(
  [int]$Reps = 10,
  [int]$Warmups = 1,
  [int]$GaiProfile = 3072,
  [string]$WslRoot = "",
  [switch]$DryRun
)
# Table 1: cumulative Fabric transaction times for (3,1), (5,2) and (9,4).
# The network and the driver run inside WSL, so this script only forwards the
# parameters to run/fabric_onchain.sh.
$ErrorActionPreference = 'Stop'
. "$PSScriptRoot\_env.ps1"
if (-not $WslRoot) {
  $WslRoot = "/mnt/" + ($Root.Substring(0, 1).ToLower()) + ($Root.Substring(2) -replace '\\', '/')
}
$inner = "REPS=$Reps WARMUPS=$Warmups GAI_BITS=$GaiProfile bash '$WslRoot/run/fabric_onchain.sh' tab1"

if ($DryRun) {
  Write-Host "wsl -e bash -c `"$inner`""
  exit 0
}
& "$PSScriptRoot\build_onchain.ps1" | Out-Null
wsl -e bash -c $inner
exit $LASTEXITCODE
