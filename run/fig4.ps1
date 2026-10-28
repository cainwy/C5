param([int]$Reps = 30)
# Fig. 4: local receiver-recovery time for (n,f) in {(3,1),(5,2),(9,4)} and
# L in {1,2,4,8,16,32,64}, with exactly t=f+1 deliveries supplied.
. "$PSScriptRoot\_env.ps1"
Push-Location (Join-Path $Root 'blockchain')
go run ./experiments/cmd/fig4 -reps $Reps -out "$DataRoot\fig4"
$code = $LASTEXITCODE
Pop-Location
exit $code
