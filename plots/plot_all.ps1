param(
  [string]$Lang = "both",
  [switch]$SkipOnchain
)
$ErrorActionPreference = 'Stop'
. "$PSScriptRoot\..\run\_env.ps1"
$plots = Join-Path $Root 'plots'
$langs = if ($Lang -eq 'both') { @('en', 'zh') } else { @($Lang) }

if (-not $SkipOnchain) {
  python "$plots\merge_onchain.py" --raw-root "$DataRoot\fig1b" --logs "$DataRoot\logs" `
    --out "$DataRoot\fig1b" --out-tab1 "$DataRoot\tab1"
  python "$plots\merge_onchain.py" --raw-root "$DataRoot\tab1" --logs "$DataRoot\logs" `
    --out "$DataRoot\tab1" --out-tab1 "$DataRoot\tab1"
}

foreach ($l in $langs) {
  python "$plots\fig1.py" --lang $l --out "$FigRoot"
  python "$plots\fig2.py" --lang $l --out "$FigRoot"
  python "$plots\fig3.py" --lang $l --out "$FigRoot"
  python "$plots\fig4.py" --lang $l --out "$FigRoot"
  python "$plots\fig5.py" --lang $l --out "$FigRoot"
}
Write-Host "PLOTS_DONE" -ForegroundColor Green
