# Table 2: dynamic communication volumes for n in {3,5,9}, derived from the
# message format of both schemes.
. "$PSScriptRoot\_env.ps1"
Push-Location (Join-Path $Root 'blockchain')
go run ./experiments/cmd/tab2 -raw "$DataRoot\fig2\fig2_recovery.json" -out "$DataRoot\tab2\tab2_communication.json"
$code = $LASTEXITCODE
Pop-Location
exit $code
