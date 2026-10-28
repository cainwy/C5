param([int]$Reps = 5)
# Functional validation: tampered deliveries, garbage proofs, flipped signatures,
# unregistered indices and duplicate indices are rejected; recovery fails with
# fewer than t=f+1 valid shares; every valid threshold subset reconstructs the
# same output.
. "$PSScriptRoot\_env.ps1"
Push-Location (Join-Path $Root 'blockchain')
go run ./experiments/cmd/selftest -reps $Reps -out "$DataRoot\selftest"
$code = $LASTEXITCODE
Pop-Location
exit $code
