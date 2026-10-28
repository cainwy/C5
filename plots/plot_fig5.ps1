param([string]$Lang = "en")
$ErrorActionPreference = 'Stop'
. "$PSScriptRoot\..\run\_env.ps1"
python "$PSScriptRoot\fig5.py" --lang $Lang --out "$FigRoot"
