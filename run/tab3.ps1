param(
  [string]$Ls = "1,2,4",
  [int]$Reps = 1
)
# Table 3: relation-specific Groth16 setup, proving time and peak memory for each
# output dimension. Setup and proving are reported separately.
. "$PSScriptRoot\_env.ps1"
Push-Location (Join-Path $Root 'blockchain')
go run ./experiments/cmd/tab3 -ls $Ls -reps $Reps -out "$DataRoot\tab3"
$code = $LASTEXITCODE
Pop-Location
exit $code
