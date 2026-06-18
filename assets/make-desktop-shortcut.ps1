# Creates (or refreshes) a "fwforge" shortcut on the Desktop that launches the
# web GUI with the branded icon. Re-run any time. Safe to run repeatedly.
$ErrorActionPreference = "Stop"
$assets = $PSScriptRoot
$repo   = Split-Path -Parent $assets
$ico    = Join-Path $assets "fwforge.ico"

# Resolve a REAL python.exe, skipping the Windows Store execution-alias stub
# under WindowsApps (which often won't actually launch the app).
$py = (Get-Command python -All -ErrorAction SilentlyContinue |
       Where-Object { $_.Source -notlike "*\WindowsApps\*" } |
       Select-Object -First 1 -ExpandProperty Source)
if (-not $py) {
  $g = Get-ChildItem "$env:LOCALAPPDATA\Python\pythoncore-*\python.exe" -ErrorAction SilentlyContinue | Select-Object -First 1
  if ($g) { $py = $g.FullName }
}
if (-not $py) { $py = (Get-Command py -ErrorAction SilentlyContinue).Source }
if (-not $py) { $py = (Get-Command python -ErrorAction SilentlyContinue).Source }
if (-not $py) { throw "python not found - install Python or add it to PATH" }

$desktop = [Environment]::GetFolderPath("Desktop")
$lnk     = Join-Path $desktop "fwforge.lnk"

$ws = New-Object -ComObject WScript.Shell
$sc = $ws.CreateShortcut($lnk)
$sc.TargetPath       = $py
$sc.Arguments        = "-m fwforge gui"
$sc.WorkingDirectory = $repo
$sc.IconLocation     = "$ico,0"
$sc.Description       = "fwforge - firewall config converter (web GUI)"
$sc.WindowStyle      = 1
$sc.Save()

Write-Output "Created desktop shortcut: $lnk"
Write-Output "  launches : $py -m fwforge gui"
Write-Output "  workdir  : $repo"
Write-Output "  icon     : $ico"
