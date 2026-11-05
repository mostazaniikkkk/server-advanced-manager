# Cliente RCON mínimo (protocolo Source RCON que usa Minecraft) para el servidor QA local.
param(
    [Parameter(Mandatory = $true)][string]$ServerDir,
    [Parameter(Mandatory = $true)][string]$Command
)

$props = Get-Content (Join-Path $ServerDir "server.properties")
$port = [int](($props | Where-Object { $_ -match '^rcon\.port=' }) -replace '^rcon\.port=', '')
$password = ($props | Where-Object { $_ -match '^rcon\.password=' }) -replace '^rcon\.password=', ''

function Send-Packet($stream, [int]$id, [int]$type, [string]$body) {
    $payload = [Text.Encoding]::UTF8.GetBytes($body)
    $length = 4 + 4 + $payload.Length + 2
    $buffer = New-Object byte[] (4 + $length)
    [BitConverter]::GetBytes([int]$length).CopyTo($buffer, 0)
    [BitConverter]::GetBytes($id).CopyTo($buffer, 4)
    [BitConverter]::GetBytes($type).CopyTo($buffer, 8)
    $payload.CopyTo($buffer, 12)
    $stream.Write($buffer, 0, $buffer.Length)
}

function Read-Packet($stream) {
    $header = New-Object byte[] 4
    $read = 0
    while ($read -lt 4) { $read += $stream.Read($header, $read, 4 - $read) }
    $length = [BitConverter]::ToInt32($header, 0)
    $data = New-Object byte[] $length
    $read = 0
    while ($read -lt $length) { $read += $stream.Read($data, $read, $length - $read) }
    [pscustomobject]@{
        Id   = [BitConverter]::ToInt32($data, 0)
        Body = [Text.Encoding]::UTF8.GetString($data, 8, [Math]::Max(0, $length - 10))
    }
}

$client = New-Object Net.Sockets.TcpClient("127.0.0.1", $port)
$client.ReceiveTimeout = 10000
$stream = $client.GetStream()
try {
    Send-Packet $stream 1 3 $password
    $auth = Read-Packet $stream
    if ($auth.Id -eq -1) { throw "RCON: contraseña rechazada" }
    Send-Packet $stream 2 2 $Command
    try { (Read-Packet $stream).Body } catch { "(sin respuesta: el servidor pudo haberse detenido)" }
} finally {
    $client.Close()
}
