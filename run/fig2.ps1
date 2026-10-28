param(
  [int]$Reps = 5,
  [string]$Profiles = "M,N"
)
# Fig. 2: receiver-recovery computation for n in {3,5,9}. M is Gai et al.'s
# 1024-bit configuration, N is its 3072-bit configuration with a 256-bit subgroup.
. "$PSScriptRoot\_env.ps1"
Push-Location (Join-Path $Root 'blockchain')
go run ./experiments/cmd/fig2 -reps $Reps -profiles $Profiles -out "$DataRoot\fig2"
$code = $LASTEXITCODE
Pop-Location
exit $code
