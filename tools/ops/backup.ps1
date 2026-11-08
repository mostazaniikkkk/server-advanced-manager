# Respaldo del servidor: el mundo y config/sam (cuentas, identidad, permisos, .env) más las listas del
# servidor, en un .zip con fecha. Si el servidor está corriendo, pausa el guardado por RCON mientras copia.
# Conserva los últimos $Keep respaldos. El .zip lleva secretos cifrados y el .env: guárdalo como el .env.
param(
    [string]$ServerDir = "D:\Proyectos\Minecraft\QA Server SAM",
    [string]$Dest = "D:\Proyectos\Minecraft\Backups\QA Server SAM",
    [int]$Keep = 14,
    [string]$Tools = (Join-Path $PSScriptRoot "..\qa")
)
$ErrorActionPreference = "Stop"

$props = Get-Content (Join-Path $ServerDir "server.properties")
$level = (($props | Where-Object { $_ -match '^level-name=' }) -replace '^level-name=', '').Trim()
if (-not $level) { $level = "world" }
$port = [int]((($props | Where-Object { $_ -match '^server-port=' }) -replace '^server-port=', '').Trim())
$running = [bool](Get-NetTCPConnection -LocalPort $port -State Listen -ErrorAction SilentlyContinue)

New-Item -ItemType Directory -Force $Dest | Out-Null
$stamp = Get-Date -Format "yyyyMMdd-HHmmss"
$staging = Join-Path $env:TEMP "sam-backup-$stamp"
$zip = Join-Path $Dest "sam-backup-$stamp.zip"

if ($running) {
    & (Join-Path $Tools "rcon.ps1") -ServerDir $ServerDir -Command "save-off" | Out-Null
    & (Join-Path $Tools "rcon.ps1") -ServerDir $ServerDir -Command "save-all flush" | Out-Null
}
try {
    New-Item -ItemType Directory -Force $staging | Out-Null
    Copy-Item -Recurse (Join-Path $ServerDir $level) (Join-Path $staging $level)
    New-Item -ItemType Directory -Force (Join-Path $staging "config") | Out-Null
    Copy-Item -Recurse (Join-Path $ServerDir "config\sam") (Join-Path $staging "config\sam")
    foreach ($f in "server.properties", "ops.json", "whitelist.json", "banned-players.json", "banned-ips.json") {
        $p = Join-Path $ServerDir $f
        if (Test-Path $p) { Copy-Item $p $staging }
    }
} finally {
    if ($running) { & (Join-Path $Tools "rcon.ps1") -ServerDir $ServerDir -Command "save-on" | Out-Null }
}
# La sesión del mundo está bloqueada mientras corre: no hace falta en el respaldo
Remove-Item -Force (Join-Path $staging "$level\session.lock") -ErrorAction SilentlyContinue
Compress-Archive -Path (Join-Path $staging "*") -DestinationPath $zip -CompressionLevel Optimal
Remove-Item -Recurse -Force $staging

# Solo el dueño puede leerlo (lleva el .env)
icacls $zip /inheritance:r /grant:r "$($env:USERNAME):(F)" | Out-Null

$old = Get-ChildItem $Dest -Filter "sam-backup-*.zip" | Sort-Object Name -Descending | Select-Object -Skip $Keep
$old | Remove-Item -Force
"Respaldo: $zip ($([math]::Round((Get-Item $zip).Length / 1MB, 1)) MB, servidor $(if ($running) { 'corriendo' } else { 'detenido' })); se conservan $Keep, se borraron $(@($old).Count)"
