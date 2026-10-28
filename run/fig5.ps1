# Fig. 5: authenticated recovery-delivery volume for (n,f) in {(3,1),(5,2),(9,4)}
# and L in {1,2,4,8,16,32,64}, derived from the delivery message format.
. "$PSScriptRoot\_env.ps1"
Push-Location (Join-Path $Root 'blockchain')
go run ./experiments/cmd/fig5 -out "$DataRoot\fig5"
$code = $LASTEXITCODE
Pop-Location
exit $code
