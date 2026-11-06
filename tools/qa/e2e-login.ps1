# Prueba de punta a punta del login con el cliente real (runClient de Loom) contra QA Server SAM.
# Instala sam-server, arranca el servidor, abre el juego en el entorno de desarrollo (autocompleta la
# AuthScreen y se cierra solo tras entrar al mundo) y detiene el servidor. Solo a pedido.
param(
    [string]$ProjectDir = "D:\Proyectos\Minecraft\Server Advanced Manager mod",
    [string]$ServerDir = "D:\Proyectos\Minecraft\QA Server SAM",
    [string]$Tools = $PSScriptRoot,
    [string]$Out = (Join-Path $PSScriptRoot "..\..\build\qa"),
    [string]$User = "SamDev",
    [switch]$SkipInstall
)

New-Item -ItemType Directory -Force $Out | Out-Null
$java = "C:\Program Files\Java\jdk-25.0.2\bin\java.exe"
if (-not $SkipInstall) {
    & "$Tools\gradle-watch.ps1" -ProjectDir $ProjectDir -GradleArgs ":sam-server:installQaServer --console=plain" -Log "$Out\install.log" -StallSeconds 120 -MaxMinutes 8 | Out-Null
    if ((Get-Content "$Out\install.log" -Raw) -notmatch "BUILD SUCCESSFUL") { Write-Output "E2E: falló la instalación"; exit 1 }
}
if (Get-NetTCPConnection -LocalPort 25567 -State Listen -ErrorAction SilentlyContinue) { Write-Output "E2E: el puerto 25567 está en uso"; exit 1 }

# Secretos solo de QA, fuera del repositorio
function Secreto($nombre) {
    $f = Join-Path $ServerDir $nombre
    if (-not (Test-Path $f)) {
        $bytes = New-Object byte[] 24; [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
        [System.IO.File]::WriteAllText($f, [Convert]::ToBase64String($bytes))
    }
    return ([System.IO.File]::ReadAllText($f)).Trim()
}
$env:SAM_IDENTITY_PASSPHRASE = ([System.IO.File]::ReadAllText((Join-Path $ServerDir ".sam-qa-identity-passphrase"))).Trim()
$password = Secreto ".sam-qa-dev-password"
$env:SAM_TCP_ENABLED = "true"; $env:SAM_WS_ENABLED = "true"; $env:SAM_WS_PATH = "/qa-ws"

$log = Join-Path $ServerDir "server-run.log"
$server = Start-Process -FilePath $java -ArgumentList "-Xmx2G", "-jar", "fabric-server-launch.jar", "nogui" -WorkingDirectory $ServerDir `
    -RedirectStandardOutput $log -RedirectStandardError "$log.err" -NoNewWindow -PassThru
$null = $server.Handle
$start = Get-Date; $ready = $false
while (((Get-Date) - $start).TotalSeconds -lt 180) {
    Start-Sleep -Seconds 2
    if ($server.HasExited) { break }
    if ((Get-Content $log -Raw -ErrorAction SilentlyContinue) -match "Done \(") { $ready = $true; break }
}
Write-Output ("E2E: servidor listo: {0}" -f $ready)

if ($ready) {
    # El entorno de desarrollo del cliente (sam-client/run, fuera del repositorio): sin la pantalla de
    # accesibilidad del primer arranque, que impide el quick play
    $options = Join-Path $ProjectDir "sam-client\run\options.txt"
    $lines = @(); if (Test-Path $options) { $lines = Get-Content $options | Where-Object { $_ -notmatch "^(onboardAccessibility|skipMultiplayerWarning|joinedFirstServer):" } }
    $lines += "onboardAccessibility:false", "skipMultiplayerWarning:true", "joinedFirstServer:true"
    New-Item -ItemType Directory -Force (Split-Path $options) | Out-Null
    Set-Content -Path $options -Value $lines -Encoding ASCII
    & "$Tools\gradle-watch.ps1" -ProjectDir $ProjectDir -GradleArgs ":sam-client:runClient --console=plain -PsamDevServer=127.0.0.1:25567 -PsamDevUser=$User -PsamDevPassword=$password -PsamDevQuitAfterJoin=6" -Log "$Out\client.log" -StallSeconds 240 -MaxMinutes 10 | Out-Null
    Get-Content "$Out\client.log" -Encoding UTF8 | Where-Object { $_ -match "\[SAM\]|SAM Client|\[dev\]|Primera conexión|SAM-C|TLS de SAM|Exception|ERROR|Connecting to|Disconnect|BUILD" -and $_ -notmatch "sam.dev.password" } | Select-Object -First 30 | ForEach-Object { "CLIENTE: $_" }
}
Get-Content $log -Encoding UTF8 | Where-Object { $_ -match "auditoría|joined the game|lost connection|left the game|Login de SAM|Exception|ERROR" } | Select-Object -First 20 | ForEach-Object { "SERVIDOR: $_" }

if (-not $server.HasExited) {
    try { & "$Tools\rcon.ps1" -ServerDir $ServerDir -Command "stop" | Out-Null } catch { Write-Output "E2E: RCON falló: $($_.Exception.Message)" }
    if (-not $server.WaitForExit(60000)) { Write-Output "E2E: ATENCIÓN: el servidor sigue vivo (PID $($server.Id))" }
}
Write-Output ("E2E: servidor detenido: {0}" -f $server.HasExited)
