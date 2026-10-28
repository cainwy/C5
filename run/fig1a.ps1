param(
  [int]$Reps = 30,
  [int]$Warmup = 3,
  [string]$Profiles = "1024,3072"
)
# Fig. 1(a): proof verification of our scheme and of Gai et al.'s 1024-bit and
# 3072-bit configurations, measured in-process with the Windows QPC timer.
. "$PSScriptRoot\_env.ps1"
Push-Location (Join-Path $Root 'blockchain')
go run ./experiments/cmd/fig1a -reps $Reps -warmup $Warmup -profiles $Profiles -out "$DataRoot\fig1a"
$code = $LASTEXITCODE
Pop-Location
exit $code
