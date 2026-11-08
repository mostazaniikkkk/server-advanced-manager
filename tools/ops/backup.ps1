# Respaldo cifrado del servidor (RF-CFG-11, H-16 de docs/HARDENING.md): el mundo, config/sam (cuentas, identidad,
# permisos, auditoría, .env) y las listas del servidor. Se arma en una carpeta temporal solo del dueño, se comprime y
# se cifra con sam-signer backup-seal usando SAM_BACKUP_KEY (variable de entorno; genera una con
# "sam-signer backup-key"). En el destino solo quedan el .sambk y su .sha256: nunca el zip en claro.
# Si el servidor está corriendo, pausa el guardado por RCON mientras copia. Conserva los últimos $Keep respaldos.
# Para restaurar: tools/ops/restore.ps1.
param(
    [string]$ServerDir = "D:\Proyectos\Minecraft\QA Server SAM",
    [string]$Dest = "D:\Proyectos\Minecraft\Backups\QA Server SAM",
    [int]$Keep = 14,
    [string]$Tools = (Join-Path $PSScriptRoot "..\qa"),
    [string]$Signer = "",
    [string]$Java = "java"
)
$ErrorActionPreference = "Stop"

if (-not $env:SAM_BACKUP_KEY) {
    throw "Falta SAM_BACKUP_KEY en el entorno. Genera una con: java -jar sam-signer.jar backup-key (y guárdala aparte del respaldo)."
}
if (-not $Signer) {
    $Signer = (Get-ChildItem (Join-Path $PSScriptRoot "..\..\sam-signer\build\libs") -Filter "sam-signer-*.jar" |
        Sort-Object LastWriteTime -Descending | Select-Object -First 1).FullName
}
if (-not $Signer -or -not (Test-Path $Signer)) { throw "No se encontró sam-signer.jar (usa -Signer <ruta>)" }

$props = Get-Content (Join-Path $ServerDir "server.properties")
$level = (($props | Where-Object { $_ -match '^level-name=' }) -replace '^level-name=', '').Trim()
if (-not $level) { $level = "world" }
$port = [int]((($props | Where-Object { $_ -match '^server-port=' }) -replace '^server-port=', '').Trim())
$running = [bool](Get-NetTCPConnection -LocalPort $port -State Listen -ErrorAction SilentlyContinue)

New-Item -ItemType Directory -Force $Dest | Out-Null
$stamp = Get-Date -Format "yyyyMMdd-HHmmss"
$staging = Join-Path $env:TEMP "sam-backup-$stamp"
$sealed = Join-Path $Dest "sam-backup-$stamp.sambk"

# La carpeta temporal nace solo del dueño: lo que se copia adentro hereda ese permiso
New-Item -ItemType Directory -Force $staging | Out-Null
icacls $staging /inheritance:r /grant:r "$($env:USERNAME):(OI)(CI)F" | Out-Null
try {
    if ($running) {
        & (Join-Path $Tools "rcon.ps1") -ServerDir $ServerDir -Command "save-off" | Out-Null
        & (Join-Path $Tools "rcon.ps1") -ServerDir $ServerDir -Command "save-all flush" | Out-Null
    }
    try {
        $content = Join-Path $staging "contenido"
        New-Item -ItemType Directory -Force $content | Out-Null
        Copy-Item -Recurse (Join-Path $ServerDir $level) (Join-Path $content $level)
        New-Item -ItemType Directory -Force (Join-Path $content "config") | Out-Null
        Copy-Item -Recurse (Join-Path $ServerDir "config\sam") (Join-Path $content "config\sam")
        foreach ($f in "server.properties", "ops.json", "whitelist.json", "banned-players.json", "banned-ips.json") {
            $p = Join-Path $ServerDir $f
            if (Test-Path $p) { Copy-Item $p $content }
        }
    } finally {
        if ($running) { & (Join-Path $Tools "rcon.ps1") -ServerDir $ServerDir -Command "save-on" | Out-Null }
    }
    # La sesión del mundo está bloqueada mientras corre: no hace falta en el respaldo
    Remove-Item -Force (Join-Path $content "$level\session.lock") -ErrorAction SilentlyContinue
    $zip = Join-Path $staging "respaldo.zip"
    Compress-Archive -Path (Join-Path $content "*") -DestinationPath $zip -CompressionLevel Optimal
    & $Java -jar $Signer backup-seal $zip $sealed | Out-Null
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path $sealed)) { throw "sam-signer no pudo cifrar el respaldo (código $LASTEXITCODE)" }
} finally {
    Remove-Item -Recurse -Force $staging -ErrorAction SilentlyContinue
}

$old = Get-ChildItem $Dest -Filter "sam-backup-*.sambk" | Sort-Object Name -Descending | Select-Object -Skip $Keep
foreach ($o in $old) { Remove-Item -Force $o.FullName, "$($o.FullName).sha256" -ErrorAction SilentlyContinue }
"Respaldo cifrado: $sealed ($([math]::Round((Get-Item $sealed).Length / 1MB, 1)) MB, servidor $(if ($running) { 'corriendo' } else { 'detenido' })); se conservan $Keep, se borraron $(@($old).Count)"
