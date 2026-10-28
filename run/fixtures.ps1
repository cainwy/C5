# Regenerate the deterministic fixtures under blockchain/fixtures/.
# Requires blockchain/artifacts/c5_l1_507/{ccs,pk,vk}.bin.
param([int]$Servers = 3)
. "$PSScriptRoot\_env.ps1"
Push-Location (Join-Path $Root 'blockchain')
go run ./experiments/cmd/verifyctl fixture-c5 -out "$Root\blockchain\fixtures\c5_l1_507.json"
if ($LASTEXITCODE -ne 0) { Pop-Location; exit $LASTEXITCODE }
go run ./experiments/cmd/verifyctl fixture-schemea -servers $Servers -profile P-SA-128 `
  -out "$Root\blockchain\fixtures\schemea_3072.json"
if ($LASTEXITCODE -ne 0) { Pop-Location; exit $LASTEXITCODE }
Pop-Location
