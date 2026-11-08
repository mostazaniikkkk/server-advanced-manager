# Arranca el servidor con SAM en una consola visible (para escribir comandos como "sam auth reset").
# SAM_IDENTITY_PASSPHRASE y SAM_DATA_KEY tienen que ser variables de entorno del proceso (RF-CFG-08): se leen
# de los archivos que están junto al servidor, que solo el dueño debería poder leer.
param(
    [string]$ServerDir = "D:\Proyectos\Minecraft\QA Server SAM",
    [string]$Java = "C:\Program Files\Java\jdk-25.0.2\bin\java.exe"
)
$ErrorActionPreference = "Stop"
$port = [int](((Get-Content (Join-Path $ServerDir "server.properties")) | Where-Object { $_ -match '^server-port=' }) -replace '^server-port=', '')
if (Get-NetTCPConnection -LocalPort $port -State Listen -ErrorAction SilentlyContinue) { "El servidor ya está corriendo en el puerto $port."; exit 1 }
$identity = Join-Path $ServerDir ".sam-qa-identity-passphrase"
$dataKey = Join-Path $ServerDir ".sam-qa-data-key"
if (-not (Test-Path $identity)) { "Falta $identity (la passphrase de la identidad del servidor)."; exit 1 }
$env:SAM_IDENTITY_PASSPHRASE = ([IO.File]::ReadAllText($identity)).Trim()
if (Test-Path $dataKey) { $env:SAM_DATA_KEY = ([IO.File]::ReadAllText($dataKey)).Trim() } else { "Aviso: sin $dataKey el 2FA queda desactivado." }
# Una ventana de consola propia: lo que se escribe ahí es la consola real del servidor
Start-Process -FilePath "cmd.exe" -WorkingDirectory $ServerDir -ArgumentList "/k", "title Servidor SAM && `"$Java`" -Xmx2G -jar fabric-server-launch.jar nogui"
"Servidor arrancando en una ventana nueva (puerto $port)."
