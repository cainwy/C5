param([string]$Lang = "en")
$ErrorActionPreference = 'Stop'
. "$PSScriptRoot\..\run\_env.ps1"
python "$PSScriptRoot\fig3.py" --lang $Lang --out "$FigRoot"
