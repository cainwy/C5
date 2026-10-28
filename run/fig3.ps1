param(
  [string]$Ls = "1,2,4",
  [int]$ProofBytes = 292
)
# Fig. 3: constraint counts and serialized proof sizes for per-coordinate (B1)
# and single-proof (B2, our scheme) organisation.
. "$PSScriptRoot\_env.ps1"
Push-Location (Join-Path $Root 'blockchain')
go run ./experiments/cmd/fig3 -ls $Ls -proof-bytes $ProofBytes -out "$DataRoot\fig3"
$code = $LASTEXITCODE
Pop-Location
exit $code
