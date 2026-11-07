# RN-04 de punta a punta: con un jugador real en el mundo (el cliente de desarrollo como SamDev), otra
# conexión con su nick no debe expulsarlo. Arranca QA Server SAM, mete al cliente, corre la prueba
# unaConexionConElNickDeUnJugadorConectadoNoLoExpulsa mientras está dentro y detiene todo.
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
$env:JAVA_HOME = "C:\Program Files\Java\jdk-25.0.2"
if (-not $SkipInstall) {
    & "$Tools\gradle-watch.ps1" -ProjectDir $ProjectDir -GradleArgs ":sam-server:installQaServer --console=plain" -Log "$Out\install.log" -StallSeconds 120 -MaxMinutes 8 | Out-Null
    if ((Get-Content "$Out\install.log" -Raw) -notmatch "BUILD SUCCESSFUL") { Write-Output "RN04: falló la instalación"; exit 1 }
}
# Compilar antes lo que usan los dos builds que corren a la vez (cliente y prueba)
& "$Tools\gradle-watch.ps1" -ProjectDir $ProjectDir -GradleArgs ":sam-server:qaTestClasses :sam-client:classes --console=plain" -Log "$Out\rn04-build.log" -StallSeconds 120 -MaxMinutes 8 | Out-Null
if ((Get-Content "$Out\rn04-build.log" -Raw) -notmatch "BUILD SUCCESSFUL") { Write-Output "RN04: falló la compilación"; exit 1 }
if (Get-NetTCPConnection -LocalPort 25567 -State Listen -ErrorAction SilentlyContinue) { Write-Output "RN04: el puerto 25567 está en uso"; exit 1 }

$env:SAM_IDENTITY_PASSPHRASE = ([System.IO.File]::ReadAllText((Join-Path $ServerDir ".sam-qa-identity-passphrase"))).Trim()
# Clave de datos del 2FA (RS-AUTH-03), solo de QA y fuera del repositorio; como variable de entorno real
$env:SAM_DATA_KEY = ([System.IO.File]::ReadAllText((Join-Path $ServerDir ".sam-qa-data-key"))).Trim()
$password = ([System.IO.File]::ReadAllText((Join-Path $ServerDir ".sam-qa-dev-password"))).Trim()
$env:SAM_TCP_ENABLED = "true"; $env:SAM_WS_ENABLED = "true"; $env:SAM_WS_PATH = "/qa-ws"
$env:SAM_WS_TRUSTED_PROXIES = "192.0.2.1/32"

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
Write-Output ("RN04: servidor listo: {0}" -f $ready)

$exit = 1
if ($ready) {
    # El cliente se queda 90 s en el mundo (sin la pantalla de accesibilidad del primer arranque)
    $options = Join-Path $ProjectDir "sam-client\run\options.txt"
    $lines = @(); if (Test-Path $options) { $lines = Get-Content $options | Where-Object { $_ -notmatch "^(onboardAccessibility|skipMultiplayerWarning|joinedFirstServer):" } }
    $lines += "onboardAccessibility:false", "skipMultiplayerWarning:true", "joinedFirstServer:true"
    Set-Content -Path $options -Value $lines -Encoding ASCII
    $client = Start-Process -FilePath (Join-Path $ProjectDir "gradlew.bat") -WorkingDirectory $ProjectDir -NoNewWindow -PassThru `
        -RedirectStandardOutput "$Out\rn04-client.log" -RedirectStandardError "$Out\rn04-client.log.err" `
        -ArgumentList ":sam-client:runClient --console=plain -PsamDevServer=127.0.0.1:25567 -PsamDevUser=$User -PsamDevPassword=$password -PsamDevQuitAfterJoin=90"
    $null = $client.Handle
    $start = Get-Date; $joined = $false
    while (((Get-Date) - $start).TotalSeconds -lt 240) {
        Start-Sleep -Seconds 2
        if ($client.HasExited) { break }
        if ((Get-Content $log -Raw -Encoding UTF8) -match "$User joined the game") { $joined = $true; break }
    }
    Write-Output ("RN04: {0} en el mundo: {1}" -f $User, $joined)
    if ($joined) {
        & "$Tools\gradle-watch.ps1" -ProjectDir $ProjectDir -GradleArgs ":sam-server:qaTest --console=plain --tests *unaConexionConElNickDeUnJugadorConectadoNoLoExpulsa -PsamQaOnlineNick=$User" `
            -Log "$Out\rn04-test.log" -StallSeconds 120 -MaxMinutes 6 | Where-Object { $_ -like "VIGILANTE (stderr)*" }
        Get-Content "$Out\rn04-test.log" | Where-Object { $_ -match "QaTest > .* (PASSED|FAILED|SKIPPED)|BUILD (SUCCESSFUL|FAILED)|Expecting|but was|to contain|as \[" } | Select-Object -First 15
        $testOk = (Get-Content "$Out\rn04-test.log" -Raw) -match "BUILD SUCCESSFUL" -and (Get-Content "$Out\rn04-test.log" -Raw) -match "PASSED"
        # Segunda mitad: un segundo cliente que sí se autentica reemplaza a la sesión anterior. Va en su propia
        # carpeta (sam-client/run2): los mods remapeados de run/ están abiertos por el primero
        $run2 = Join-Path $ProjectDir "sam-client\run2"
        New-Item -ItemType Directory -Force (Join-Path $run2 "mods") | Out-Null
        Get-ChildItem (Join-Path $ProjectDir "sam-client\run\mods") -Filter *.jar | Copy-Item -Destination (Join-Path $run2 "mods") -Force
        Set-Content -Path (Join-Path $run2 "options.txt") -Value $lines -Encoding ASCII
        $second = Start-Process -FilePath (Join-Path $ProjectDir "gradlew.bat") -WorkingDirectory $ProjectDir -NoNewWindow -PassThru `
            -RedirectStandardOutput "$Out\rn04-client2.log" -RedirectStandardError "$Out\rn04-client2.log.err" `
            -ArgumentList ":sam-client:runClient2 --console=plain -PsamDevServer=127.0.0.1:25567 -PsamDevUser=$User -PsamDevPassword=$password -PsamDevQuitAfterJoin=5"
        $null = $second.Handle
        if (-not $second.WaitForExit(240000)) { Write-Output "RN04: ATENCIÓN: el segundo cliente sigue abierto (PID $($second.Id))" }
        $text = Get-Content $log -Raw -Encoding UTF8
        $replaced = $text -match "se autenticó desde otra conexión: reemplaza" -and $text -match "$User lost connection: You logged in from another location" `
            -and ([regex]::Matches($text, "$User joined the game")).Count -ge 2
        Write-Output ("RN04: la sesión autenticada reemplazó a la anterior: {0}" -f $replaced)
        if ($testOk -and $replaced) { $exit = 0 }
    }
    if (-not $client.WaitForExit(150000)) { Write-Output "RN04: ATENCIÓN: el cliente sigue abierto (PID $($client.Id))" }
}
Get-Content $log -Encoding UTF8 | Where-Object { $_ -match "auditoría|joined the game|lost connection|logged in from another|Exception" -and $_ -notmatch "COM exception" } | Select-Object -First 15 | ForEach-Object { "SERVIDOR: $_" }

if (-not $server.HasExited) {
    try { & "$Tools\rcon.ps1" -ServerDir $ServerDir -Command "stop" | Out-Null } catch { Write-Output "RN04: RCON falló: $($_.Exception.Message)" }
    if (-not $server.WaitForExit(60000)) { Write-Output "RN04: ATENCIÓN: el servidor sigue vivo (PID $($server.Id))" }
}
Write-Output ("RN04: servidor detenido: {0}" -f $server.HasExited)
exit $exit
