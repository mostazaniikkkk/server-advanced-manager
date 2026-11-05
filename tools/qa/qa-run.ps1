# QA de punta a punta: instala sam-server, arranca QA Server SAM, corre :sam-server:qaTest y lo detiene por RCON.
# Detección: espera "Done (" con tope de tiempo, corta ante crash o log trabado, y siempre intenta detener el servidor.
param(
    [string]$ProjectDir = "D:\Proyectos\Minecraft\Server Advanced Manager mod",
    [string]$ServerDir = "D:\Proyectos\Minecraft\QA Server SAM",
    [string]$Tools = $PSScriptRoot,
    [string]$Out = (Join-Path $PSScriptRoot "..\..\build\qa"),
    [switch]$SkipInstall
)

New-Item -ItemType Directory -Force $Out | Out-Null
$java = "C:\Program Files\Java\jdk-25.0.2\bin\java.exe"

if (-not $SkipInstall) {
    & "$Tools\gradle-watch.ps1" -ProjectDir $ProjectDir -GradleArgs ":sam-server:installQaServer --console=plain" -Log "$Out\install.log" -StallSeconds 120 -MaxMinutes 8 | Out-Null
    if ((Get-Content "$Out\install.log" -Raw) -notmatch "BUILD SUCCESSFUL") { Write-Output "QA: falló la instalación (ver $Out\install.log)"; exit 1 }
}

if (Get-NetTCPConnection -LocalPort 25567 -State Listen -ErrorAction SilentlyContinue) {
    Write-Output "QA: el puerto 25567 ya está en uso: hay un servidor corriendo. No se arranca otro."; exit 1
}

$log = Join-Path $ServerDir "server-run.log"
$server = Start-Process -FilePath $java -ArgumentList "-Xmx2G", "-jar", "fabric-server-launch.jar", "nogui" -WorkingDirectory $ServerDir `
    -RedirectStandardOutput $log -RedirectStandardError "$log.err" -NoNewWindow -PassThru
$null = $server.Handle

$start = Get-Date; $lastSize = -1; $lastChange = Get-Date; $state = "timeout"
while (((Get-Date) - $start).TotalSeconds -lt 180) {
    Start-Sleep -Seconds 2
    if ($server.HasExited) { $state = "el proceso terminó solo (código $($server.ExitCode))"; break }
    $size = (Get-Item $log -ErrorAction SilentlyContinue).Length
    if ($size -ne $lastSize) { $lastSize = $size; $lastChange = Get-Date }
    $text = Get-Content $log -Raw -ErrorAction SilentlyContinue
    if ($text -match "Done \(") { $state = "listo"; break }
    if ($text -match "crashed|FAILED TO BIND|Failed to start|Exception in server tick") { $state = "falla al arrancar"; break }
    if (((Get-Date) - $lastChange).TotalSeconds -ge 60) { $state = "log trabado 60 s"; break }
}
Write-Output ("QA: servidor {0} en {1} s" -f $state, [int]((Get-Date) - $start).TotalSeconds)
Get-Content $log | Where-Object { $_ -match "SAM Server|Loading \d+ mods|Starting Minecraft server on|ERROR" } | Select-Object -First 6

$exit = 1
if ($state -eq "listo") {
    & "$Tools\gradle-watch.ps1" -ProjectDir $ProjectDir -GradleArgs ":sam-server:qaTest --console=plain" -Log "$Out\qatest.log" -StallSeconds 120 -MaxMinutes 6 | Out-Null
    Get-Content "$Out\qatest.log" | Where-Object { $_ -match "QaTest > .* (PASSED|FAILED)|BUILD (SUCCESSFUL|FAILED)|Expecting|but was|expected|as \[" } | Select-Object -First 20
    if ((Get-Content "$Out\qatest.log" -Raw) -match "BUILD SUCCESSFUL") { $exit = 0 }
}

# Siempre: detener el servidor por RCON y esperar a que termine
if (-not $server.HasExited) {
    try { & "$Tools\rcon.ps1" -ServerDir $ServerDir -Command "stop" | Out-Null } catch { Write-Output "QA: RCON falló: $($_.Exception.Message)" }
    if (-not $server.WaitForExit(60000)) { Write-Output "QA: ATENCIÓN: el servidor sigue vivo tras 60 s (PID $($server.Id))" }
}
Write-Output ("QA: servidor detenido: {0}; puerto 25567 libre: {1}" -f $server.HasExited, -not [bool](Get-NetTCPConnection -LocalPort 25567 -State Listen -ErrorAction SilentlyContinue))
exit $exit
