# Corre gradlew con vigilancia: si el log deja de avanzar, toma un volcado de hilos del daemon
# para diagnosticar dónde se trabó. No mata procesos: el corte lo hace el timeout de tareas de Gradle.
param(
    [Parameter(Mandatory = $true)][string]$ProjectDir,
    [Parameter(Mandatory = $true)][string]$GradleArgs,
    [Parameter(Mandatory = $true)][string]$Log,
    [int]$StallSeconds = 90,
    [int]$MaxMinutes = 25,
    [string]$JavaHome = "C:\Program Files\Java\jdk-25.0.2"
)

$env:JAVA_HOME = $JavaHome
$start = Get-Date
$proc = Start-Process -FilePath (Join-Path $ProjectDir "gradlew.bat") -ArgumentList $GradleArgs -WorkingDirectory $ProjectDir `
    -RedirectStandardOutput $Log -RedirectStandardError "$Log.err" -NoNewWindow -PassThru
$null = $proc.Handle  # sin esto, PowerShell no expone ExitCode al terminar
$lastSize = -1
$lastChange = Get-Date
$dumped = $false

while (-not $proc.HasExited) {
    Start-Sleep -Seconds 5
    $size = (Get-Item $Log -ErrorAction SilentlyContinue).Length + (Get-Item "$Log.err" -ErrorAction SilentlyContinue).Length
    if ($size -ne $lastSize) {
        $lastSize = $size
        $lastChange = Get-Date
    }
    $stalled = ((Get-Date) - $lastChange).TotalSeconds
    if ($stalled -ge $StallSeconds -and -not $dumped) {
        Write-Output "VIGILANTE: el log no avanza hace $([int]$stalled) s. Tomando volcado de hilos de los daemons de Gradle..."
        $daemons = Get-CimInstance Win32_Process -Filter "Name='java.exe'" |
            Where-Object { $_.CommandLine -match 'GradleDaemon' -and $_.CommandLine -match [regex]::Escape($JavaHome) }
        foreach ($d in $daemons) {
            $dump = "$Log.jstack-$($d.ProcessId).txt"
            & (Join-Path $JavaHome "bin\jstack.exe") -l $d.ProcessId > $dump 2>&1
            Write-Output "VIGILANTE: volcado del daemon $($d.ProcessId) en $dump"
        }
        $dumped = $true
    }
    if (((Get-Date) - $start).TotalMinutes -ge $MaxMinutes) {
        Write-Output "VIGILANTE: se superaron $MaxMinutes minutos; el build sigue vivo (no se mata desde aquí)."
        break
    }
}

if ($proc.HasExited) {
    Write-Output "VIGILANTE: gradlew terminó con código $($proc.ExitCode) en $([int]((Get-Date) - $start).TotalSeconds) s"
}
