# Restaura un respaldo cifrado (RF-CFG-11, H-16 de docs/HARDENING.md): verifica su .sha256, lo descifra con
# sam-signer backup-open (SAM_BACKUP_KEY en el entorno) y lo extrae en una carpeta NUEVA. Nunca escribe encima del
# servidor: revisa lo restaurado y copia tú lo que haga falta, con el servidor detenido.
param(
    [Parameter(Mandatory = $true)][string]$Backup,
    [Parameter(Mandatory = $true)][string]$Dest,
    [string]$Signer = "",
    [string]$Java = "java"
)
$ErrorActionPreference = "Stop"

if (-not $env:SAM_BACKUP_KEY) { throw "Falta SAM_BACKUP_KEY en el entorno (la misma con la que se respaldó)." }
if (Test-Path $Dest) { throw "$Dest ya existe: restaura en una carpeta nueva." }
if (-not $Signer) {
    $Signer = (Get-ChildItem (Join-Path $PSScriptRoot "..\..\sam-signer\build\libs") -Filter "sam-signer-*.jar" |
        Sort-Object LastWriteTime -Descending | Select-Object -First 1).FullName
}
if (-not $Signer -or -not (Test-Path $Signer)) { throw "No se encontró sam-signer.jar (usa -Signer <ruta>)" }

$work = Join-Path $env:TEMP "sam-restore-$(Get-Date -Format 'yyyyMMdd-HHmmss')"
New-Item -ItemType Directory -Force $work | Out-Null
icacls $work /inheritance:r /grant:r "$($env:USERNAME):(OI)(CI)F" | Out-Null
try {
    $zip = Join-Path $work "respaldo.zip"
    $output = & $Java -jar $Signer backup-open (Resolve-Path $Backup).Path $zip
    if ($LASTEXITCODE -ne 0) { throw "No se pudo descifrar: $output" }
    New-Item -ItemType Directory -Force $Dest | Out-Null
    icacls $Dest /inheritance:r /grant:r "$($env:USERNAME):(OI)(CI)F" | Out-Null
    Expand-Archive -Path $zip -DestinationPath $Dest
} finally {
    Remove-Item -Recurse -Force $work -ErrorAction SilentlyContinue
}
"Restaurado en $Dest (solo lo puede leer $($env:USERNAME)). Revisa y copia lo que necesites con el servidor detenido."
