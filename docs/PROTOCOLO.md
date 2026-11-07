# SAM: especificación del protocolo

> Estado: **v1.0**, 2026-11-04. Implementa la sección 6 de [REQUERIMIENTOS.md](REQUERIMIENTOS.md) v1.1 y las mitigaciones de [AMENAZAS.md](AMENAZAS.md). El transporte WebSocket se justifica en [TRANSPORTE_WEBSOCKET.md](TRANSPORTE_WEBSOCKET.md).
> Las decisiones de diseño (P-01 a P-11) están confirmadas. Quedan abiertas solo las validaciones técnicas de la fase 0 (sección 12). Los nombres de clases usan mappings oficiales de Mojang.

---

## 0. Decisiones de diseño (confirmadas el 2026-11-04)

| # | Tema | Decisión | Alternativas descartadas | Sección |
|---|---|---|---|---|
| P-01 | Codificación de los mensajes SAM | **Payloads personalizados de Fabric** (`CustomPacketPayload` + `StreamCodec` sobre `FriendlyByteBuf`), sin dependencias nuevas | CBOR, Protobuf | 4 |
| P-02 | Compatibilidad entre versiones | Versión `mayor.menor`: el **mayor** debe coincidir; el **menor** se negocia (se usa el menor de los dos) y las capacidades extra van como *feature flags* | Coincidencia exacta | 4.3 |
| P-03 | Cómo sabe el cliente si un servidor **no fijado** usa SAM | Campo `sam` en la respuesta del ping de estado vanilla (en claro). Los servidores **fijados** siempre van por TLS sin preguntar | Intentar TLS siempre y caer a vanilla si falla | 2.4 |
| P-04 | Qué se fija (pin) | **SHA-256 de la SubjectPublicKeyInfo (SPKI)** de la clave del servidor, no del certificado entero | Hash del certificado | 3.3 |
| P-05 | Dónde va el `server_id` en el certificado | Atributo `serialNumber` del Subject (`CN=SAM Server, SERIALNUMBER=<server_id hex>`) | Extensión X.509 con OID propio (requiere registrar un PEN) | 3.1 |
| P-06 | Parámetros de Argon2id | Cliente: m=64 MiB, t=3, p=1. Servidor (sobre `K`): m=19 MiB, t=2, p=1 (mínimo de OWASP). Ajustables tras medir en la fase 0 | Otros costos | 6 |
| P-07 | Frase de 3 palabras de la huella | 3 palabras de la lista BIP-39 en español (2048 palabras, 33 bits) derivadas del pin, más un identicon con paleta fija de 16 colores | Lista EFF en inglés, lista propia, color HSL | 3.5 |
| P-08 | Formato de firma de scripts | Archivo `signature.json` con un lockfile de texto canónico (`ruta\tsha256\n` ordenado) firmado con Ed25519. Sin JSON canónico ni librerías extra | JSON canónico (RFC 8785), JWS | 8.2 |
| P-09 | Reanudación de sesiones TLS y 0-RTT | **Deshabilitadas.** Simplifica el análisis: cada conexión hace un handshake completo | Habilitar la reanudación sin 0-RTT | 3.2 |
| P-10 | ALPN | `sam/1` obligatorio en el handshake TLS | ALPN opcional, sin ALPN | 3.2 |
| P-11 | Clave del dispositivo | **Una clave por servidor**, derivada de una semilla única del dispositivo y del `server_id`: ningún servidor puede reconocer al jugador en otro | Clave global, claves aleatorias independientes | 7 |

---

## 1. Capas

```
┌───────────────────────────────────────────────────────────────┐
│ Protocolo de Minecraft 1.21.1 (handshake, status, login,       │
│ configuration, play) + mensajes SAM (payloads `sam:*`)         │
├───────────────────────────────────────────────────────────────┤
│ TLS 1.3 de SAM (certificado del servidor, pinning en cliente)  │  ← extremo a extremo
├───────────────────────────────────────────────────────────────┤
│ Transporte: TCP directo  |  WebSocket (ws:// o wss:// vía CDN) │
└───────────────────────────────────────────────────────────────┘
```

- Por encima del TLS **todo es Minecraft estándar**: SAM no cambia el framing, la compresión ni los paquetes vanilla. Los mensajes propios viajan como *custom payloads*.
- El pipeline de Netty lo controla **solo SAM** (RNF-02). Orden en el servidor, desde la red hacia el juego:

```
[ws?]  detector → http codec → ws handshake → ws frame→bytes ┐
[tcp]  detector ─────────────────────────────────────────────┴→ SslHandler(TLS 1.3) → pipeline vanilla
                                                                (splitter, decompress, decoder…)
```

---

## 2. Establecimiento de la conexión

### 2.1 Detector de protocolo (servidor)

Handler al inicio del pipeline de cada conexión entrante (TCP), con **timeout de 5 s** para recibir los primeros bytes y un límite de conexiones sin clasificar por IP y global.

| Primeros bytes | Interpretación | Acción |
|---|---|---|
| `0x16 0x03` | ClientHello de TLS | Insertar `SslHandler` (3.2) y quitar el detector |
| `0x47 0x45 0x54 0x20` (`GET `) | Petición HTTP | Si `SAM_WS_ENABLED`: handshake WebSocket (2.3); si no, cerrar |
| `0xFE` | Ping legacy (pre-1.7) | Pipeline vanilla en claro (solo status) |
| Cualquier otro | Handshake vanilla en claro | Pipeline vanilla en claro **restringido** (2.2) |

Un handshake vanilla nunca empieza con `0x16 0x03` ni con `GE`: su primer byte es un VarInt de longitud y el segundo es el ID de paquete `0x00`. Este caso límite se cubre con tests (RS-WS-06).

Si `SAM_TCP_ENABLED=false`, por TCP solo se acepta `GET ` (WebSocket); cualquier otra cosa se cierra.

### 2.2 Camino vanilla en claro (restringido)

Para clientes sin SAM, o para el ping de la lista de servidores de un cliente que todavía no fijó el servidor:

- **Intent `status`**: respuesta de estado normal (MOTD, jugadores, versión) con el campo extra `sam` (2.4).
- **Intent `login`**: se responde con `ClientboundLoginDisconnectPacket` con el mensaje de descarga (código `SAM-K001`, sección 9). **Nunca** se pasa a configuration ni a play.
- **Intent `transfer`**: igual que `login`.

### 2.3 WebSocket

Ver TRANSPORTE_WEBSOCKET.md 4.3. Resumen normativo:

1. Petición `GET <SAM_WS_PATH> HTTP/1.1` con `Upgrade: websocket`, `Connection: Upgrade`, `Sec-WebSocket-Version: 13` y `Sec-WebSocket-Key` (RFC 6455).
2. El cliente envía `Sec-WebSocket-Protocol: sam.v1`. El servidor lo confirma; si el cliente pide otro, se rechaza con `400`.
3. Con cabecera `Origin` → `403` y cierre (RS-WS-05). Con ruta distinta → `404` genérico.
4. Límites: petición HTTP ≤ 8 KiB, handshake ≤ `SAM_WS_HANDSHAKE_TIMEOUT` (5 s), mensaje ≤ `SAM_WS_MAX_MESSAGE` (1 MiB).
5. IP real según RS-WS-02, resuelta **antes** de cualquier otro límite por IP.
6. Tras el `101 Switching Protocols`, los mensajes **binarios** se convierten en un flujo de bytes y se vuelve a pasar por el detector, que **solo acepta** `0x16 0x03` (TLS). Cualquier otra cosa → cierre (RS-WS-01).
7. Ping de WebSocket cada 20 s desde el servidor; sin pong en 60 s → cierre.

### 2.4 Descubrimiento de SAM desde el cliente (P-03)

La respuesta de estado vanilla es un JSON. SAM agrega:

```json
"sam": { "v": "1.0", "id": "<server_id en hex>", "tls": true, "ws": "/ruta-opcional" }
```

> `ws` solo aparece si el operador lo decide (por defecto no se publica la ruta).

Lógica del cliente al conectar a una dirección:

```
¿la dirección está fijada (dirección → server_id)?
 ├─ sí → conectar SIEMPRE por TLS. Si el servidor no habla TLS → abortar (RS-NET-10, SAM-C003)
 └─ no → ping de estado en claro
         ├─ trae "sam" → conectar por TLS y hacer TOFU (3.4)
         └─ no trae "sam" → conexión vanilla normal (servidor sin SAM)
```

- Un MITM podría quitar el campo `sam` de un servidor **nunca visto**, y el cliente se conectaría en vanilla. El servidor SAM real lo expulsaría (2.2), así que no hay login ni credenciales en juego: el ataque solo produce un kick. Para servidores fijados no aplica.
- Las direcciones `ws://` y `wss://` implican SAM: siempre TLS por dentro.
- El ping de estado de un servidor **fijado** va por TLS y verifica el pin, pero **un ping nunca crea un pin**: el TOFU solo ocurre al conectar para jugar, con la pantalla de primera conexión (RS-NET-09).

---

## 3. TLS 1.3 y pinning

### 3.1 Certificado del servidor (P-05)

| Campo | Valor |
|---|---|
| Formato | X.509 v3, autofirmado (o firmado por la CA del operador, 3.6) |
| Clave | Ed25519. Respaldo: ECDSA P-256, si la fase 0 muestra problemas de soporte de Ed25519 en TLS con JSSE |
| Subject | `CN=SAM Server, SERIALNUMBER=<server_id: 32 caracteres hex>` |
| Validez | 10 años. La validez **no** se usa para confiar (manda el pin); solo evita rechazos de librerías |
| Extensiones | `basicConstraints: CA=false`, `keyUsage: digitalSignature` |
| Almacenamiento | `SAM_SERVER_CERT_FILE` (PKCS#12), clave cifrada con `SAM_IDENTITY_PASSPHRASE` (variable de entorno, RS-NET-02) |

`server_id`: 16 bytes aleatorios (CSPRNG), generados una única vez. **Nunca cambia**, ni al rotar la clave.

### 3.2 Perfil TLS (P-09, P-10)

| Parámetro | Valor |
|---|---|
| Versión | **Solo TLS 1.3** |
| Cipher suites | `TLS_AES_128_GCM_SHA256`, `TLS_AES_256_GCM_SHA384`, `TLS_CHACHA20_POLY1305_SHA256` |
| Grupos | `x25519`, `secp256r1` |
| Firmas | `ed25519` (o `ecdsa_secp256r1_sha256` con el respaldo de 3.1) |
| ALPN | `sam/1` obligatorio: si no se negocia, cierre |
| SNI | El cliente envía el hostname si la dirección es un nombre; el servidor lo ignora (un servidor = un certificado) |
| Reanudación / 0-RTT | Deshabilitadas |
| Autenticación del cliente | No (la identidad del dispositivo va por mensajes SAM, sección 7) |
| Validación en el cliente | `TrustManager` propio: **ignora la cadena PKIX** y aplica el pinning de 3.3 (o la CA de 3.6) |

### 3.3 Pin (P-04)

```
pin = SHA-256( SubjectPublicKeyInfo DER del certificado del servidor )
```

Almacén del cliente (`config/sam-client/pins.json`):

```json
{
  "version": 1,
  "servers": {
    "<server_id>": { "pin": "<hex>", "spki": "<base64>", "first_seen": "2026-11-04T18:00:00Z", "name": "Mi Servidor" }
  },
  "addresses": {
    "play.ejemplo.com:25565": "<server_id>",
    "wss://mc.ejemplo.com/a1b2c3": "<server_id>"
  }
}
```

Validación en cada conexión TLS:

```
id   = server_id del Subject del certificado presentado
pin' = SHA-256(SPKI presentada)

si la dirección está fijada a otro server_id               → ABORTAR (SAM-C001: identidad distinta)
si servers[id] existe:
    si pin' == servers[id].pin                             → OK
    si hay una declaración de rotación válida (3.7)        → OK y actualizar el pin
    si no                                                  → ABORTAR (SAM-C002: cambio de clave, RS-NET-08)
si servers[id] no existe:
    si la dirección no estaba fijada                       → TOFU (3.4)
```

> Por qué SPKI y no el certificado: el operador puede reemitir el certificado (por ejemplo, al vencer) con la misma clave sin disparar alertas.

**Escritura y lectura de `pins.json`** (`PinStoreJson`):
- La escritura es determinista (servidores por `server_id`, direcciones por forma canónica) y siempre en forma canónica.
- La lectura usa Gson en modo estricto y por streaming, para detectar claves duplicadas: el árbol de Gson se queda en silencio con la última.
- **Un archivo dañado o manipulado nunca debilita la protección.** Lo inválido se descarta y se informa al jugador; ese servidor vuelve a la primera conexión:
  - JSON ilegible, `version` distinta de 1 o claves de primer nivel duplicadas → almacén vacío;
  - un servidor con el `pin` distinto del SHA-256 de su `spki` (posible manipulación), campos inválidos, faltantes, duplicados o de otro tipo, o con un `server_id` repetido → se descarta junto con sus direcciones;
  - una dirección que no está en forma canónica, ilegible, repetida o que apunta a un servidor no fijado → se descarta.
- Los campos desconocidos se ignoran, por compatibilidad futura.

**Normalización de las direcciones** (`ServerAddress`; las claves de `addresses` están siempre en esta forma):

| Regla | Ejemplo |
|---|---|
| Host en minúsculas, sin punto final | `Play.Ejemplo.COM.` → `play.ejemplo.com` |
| Nombres no ASCII en punycode (como vanilla) | `bücher.example` → `xn--bcher-kva.example` |
| IPv4 sin ceros a la izquierda (se rechazan, por ambigüedad octal) | `01.2.3.4` → error |
| IPv6 entre corchetes, en forma completa; IPv4 mapeado → IPv4; sin zone ID | `[::1]` → `[0:0:0:0:0:0:0:1]` |
| **TCP sin puerto ≠ TCP con `:25565`**: sin puerto, vanilla consulta el registro SRV y puede llegar a otro destino | `h.com` y `h.com:25565` son direcciones distintas |
| WebSocket: se omite el puerto por defecto (80 / 443); ruta vacía = `/`; la ruta distingue mayúsculas | `WSS://h.com:443` → `wss://h.com/` |
| Se rechazan `usuario@host`, otros esquemas, `?`/`#` en la ruta y hosts de más de 253 caracteres | |

La validación **nunca consulta el DNS**.

### 3.4 Primera conexión (TOFU)

1. TLS completo con un `TrustManager` que **acepta provisoriamente** y guarda el certificado.
2. Antes de enviar cualquier credencial, el cliente muestra la **pantalla de primera conexión** (protegida, RS-LUA-07): nombre del servidor, huella (3.5) y el texto "Compárala con la que publica el servidor".
3. Si el jugador acepta, se escriben `servers[id]` y `addresses[dirección]`. Si cancela, desconexión sin pin.
4. Si después, en la AuthScreen, el servidor pide **login** (no registro) para un servidor recién fijado, se muestra el aviso de RN-42.

### 3.5 Huella visual (P-07)

```
h        = SHA-256("SAM-fp-v1" ‖ pin)                          pin: 32 bytes (3.3)
n        = entero big-endian de h[0..5)                        40 bits
palabras = lista[(n >> 29) & 0x7FF], lista[(n >> 18) & 0x7FF], lista[(n >> 7) & 0x7FF]
celdas   = entero big-endian de h[5..7)                        16 bits
           celda (fila r, columna c) pintada si el bit (15 − (3r + min(c, 4−c))) está en 1
color    = PALETA[h[7] & 0x0F]
hex      = pin[0..16) en hexadecimal mayúscula, 8 grupos de 4 separados por espacio
```

- **Lista de palabras**: el archivo oficial de **BIP-39 en español** (`bitcoin/bips`, `bip-0039/spanish.txt`), incluido **sin modificar** en `sam-common` (SHA-256 `46846a5a0139d1e3cb77293e521c2865f7bcdb82c44e8d0a06a2cd0ecba48c0b`, verificado en los tests y contra el paquete `mnemonic` de Trezor). El archivo está en NFD; al cargarlo se normaliza a **NFC** para que la fuente del juego dibuje bien las tildes. En NFC, las 4 primeras letras identifican cada palabra. La lista y su orden **no cambian** dentro de la versión mayor del protocolo.
- **Paleta** (16 colores, en este orden): `C62828 AD1457 6A1B9A 4527A0 283593 1565C0 0277BD 00838F 00695C 2E7D32 558B2F 9E9D24 F9A825 EF6C00 D84315 4E342E`. Se usa una paleta fija en lugar de HSL para evitar diferencias de redondeo entre implementaciones.
- El identicon es simétrico de izquierda a derecha: las columnas 3 y 4 repiten las 1 y 0.

Ejemplo de presentación: **«náusea · ducha · límite»** + identicon + `E96E 02D8 E47F 2A7C …`.

**Vectores** (implementación de referencia en Python, independiente; fijados en `ServerFingerprintTest`):

| pin | palabras | celdas (máscara) | color | hex |
|---|---|---|---|---|
| `000102…1e1f` | satán · testigo · chupar | `0x456d40` | `4527A0` | `0001 0203 0405 0607 0809 0A0B 0C0D 0E0F` |
| `ff…ff` (32 × `0xFF`) | culpa · oír · leal | `0x000080` | `1565C0` | `FFFF FFFF FFFF FFFF FFFF FFFF FFFF FFFF` |
| SHA-256(`"sam"`) | náusea · ducha · límite | `0xa8fc84` | `00695C` | `E96E 02D8 E47F 2A7C 03BE 5117 B3ED 175C` |

### 3.6 Modo CA (opcional)

- La CA del operador se instala en el cliente como archivo `config/sam-client/ca/<nombre>.pem` (por ejemplo, desde un modpack).
- Si el certificado del servidor viene con cadena hasta una CA instalada y el `server_id` coincide, se acepta sin TOFU y **sin alertas de rotación**.
- La CA solo es válida para los `server_id` que declara: `config/sam-client/ca/<nombre>.json` con la lista de IDs permitidos. Así una CA no puede firmar identidades de otros servidores.

### 3.7 Rotación firmada por la clave anterior (RS-NET-03)

Tras rotar, durante `SAM_ROTATION_GRACE` (por defecto 180 días), el servidor envía en `sam:hello` una **declaración de rotación**:

```
RotationStatement {
  server_id      : bytes[16]
  old_pin        : bytes[32]          SHA-256 de la SPKI anterior
  new_spki       : bytes[44]          SPKI Ed25519 completa de la clave nueva
  issued_at      : int64 (epoch s, big-endian)
  signature      : bytes[64]          Ed25519 con la clave ANTERIOR sobre
                   "SAM-rot-v1" ‖ server_id ‖ old_pin ‖ new_spki ‖ issued_at
}
```

> Corrección del ciclo 6 de TDD: la versión anterior llevaba `new_pin` (el hash) en lugar de `new_spki`. Con eso no se podía verificar una cadena A→B→C, porque la declaración B→C la firma B y el cliente solo habría tenido el hash de B, no su clave.

Como la declaración llega **después** del TLS (que el cliente aceptó provisoriamente para este caso), el cliente (`RotationVerifier`):

1. Parte de la clave fijada (el cliente guarda la SPKI completa, no solo el hash).
2. Busca una declaración del mismo `server_id` cuyo `old_pin` sea el pin de la clave actual y verifica su firma con esa clave. Firma inválida → se rechaza todo.
3. Avanza a `new_spki` y repite hasta llegar a la SPKI presentada en este TLS. Si no hay camino, hay un ciclo o llegan más de 4 declaraciones → se rechaza.
4. Si llega, reemplaza la clave fijada y registra el cambio en su log local.

Si algo falla → SAM-C002. Las declaraciones de otros `server_id` se ignoran.

**Vectores** (librería `cryptography` de Python, independiente; claves de los tests 1, 2 y 3 de la RFC 8032 §7.1; `server_id` = `00…01`; fijados en `RotationVerifierTest`):

| Rotación | issued_at | firma |
|---|---|---|
| K1 → K2 | 1793800000 | `b31a237a3262c30491bb6c2abba4de49bb1c7db822814e9f466ed721d117ff3835f42d54ba1f5c580894acf933fa1ce254997125c59a00461e60ae9b9fa9fc0d` |
| K2 → K3 | 1793900000 | `e0ac1e9456590e2058cb51810691ff163e2c340b45d5ce8e000e9394ef169432c3859c3d844b8464723892844fbee62ec958a7796d4a4d7d94a17aaea94a1900` |

---

## 4. Mensajes SAM

### 4.1 Transporte de los mensajes (P-01)

- Cada mensaje es un **custom payload** de Minecraft con identificador `sam:<nombre>`, registrado con `PayloadTypeRegistry` de Fabric para la fase de **configuration** o de **play**.
- Codificación con `StreamCodec<FriendlyByteBuf, T>`. Tipos usados: `VarInt`, `VarLong`, `bool`, `byte[]` con prefijo VarInt, `String` UTF-8 con longitud máxima, `UUID`, `Optional<T>`, listas con prefijo VarInt.
- **Decodificación estricta** (RS-NET-11): toda longitud se valida contra su máximo **antes** de reservar memoria; los bytes sobrantes al final del payload son error; los enums fuera de rango son error. Cualquier error → desconexión con `SAM-P001` y entrada en la auditoría.

### 4.2 Límites de tamaño

| Dirección | Límite vanilla del payload | Política de SAM |
|---|---|---|
| Servidor → cliente | 1 MiB | Mensajes ≤ 256 KiB; los scripts se fragmentan (8.3) |
| Cliente → servidor | 32 767 bytes | Ningún mensaje del cliente necesita más de 4 KiB; límite por tipo en la tabla 5.6 |

### 4.3 Versionado (P-02)

- `protocol = (mayor, menor)`. Versión inicial: **1.0**.
- **Mayor** distinto → kick `SAM-K002` con el link de descarga.
- **Menor**: se usa `min(cliente, servidor)`. Un menor nuevo solo **agrega** mensajes o campos opcionales al final, nunca cambia los existentes.
- **Feature flags**: lista de strings en `sam:hello` (por ejemplo, `oauth.discord`, `lua.gui`) para capacidades que dependen de la configuración y no de la versión.

### 4.4 Máquina de estados

Cada lado mantiene un estado explícito por conexión. **Un mensaje que no corresponde al estado actual es un error de protocolo** (`SAM-P002`): desconexión.

```
CONFIGURATION
  HELLO ──► DEVICE ──► AUTH ──► (ENROLL_TOTP | EMAIL_VERIFY)* ──► SCRIPTS ──► DONE → play
                         │
                         └──► OAUTH (subestado de AUTH)
PLAY
  READY (mensajes de cuenta, Lua y avisos)
```

---

## 5. Flujo de configuration

La tarea de configuration `sam:auth` (`ConfigurationTask` de Fabric) **retiene** al cliente hasta `DONE`. Timeout total: `SAM_AUTH_TIMEOUT` (120 s), extendido a 300 s mientras haya un flujo OAuth abierto. El keep-alive vanilla sigue activo durante la espera.

### 5.1 Hello

```
S → C  sam:hello
         protocol          (mayor, menor)
         server_id         bytes[16]
         server_name       String ≤ 64
         features          List<String ≤ 32> ≤ 32
         rotation          List<RotationStatement> ≤ 4        (3.7, opcional)
         account_state     enum { NEW, REGISTERED, RESERVED }
         policy            AuthPolicyView                      (5.3)

C → S  sam:hello_ack
         protocol          (mayor, menor)
         client_version    String ≤ 32
         device_pub        bytes[32]                           (Ed25519 de ESTE servidor, sección 7)
```

- `account_state` revela si el nick está registrado: es inherente al flujo (R-ACC-02).
- Si el cliente no responde en 10 s → `SAM-K003`.
- **Estado de la implementación:** `rotation` todavía no viaja; se agrega junto con la rotación del certificado (RS-NET-03). Hasta la primera release, el formato puede cambiar sin subir la versión.

### 5.2 Dispositivo

```
S → C  sam:device_challenge
         nonce             bytes[32]

C → S  sam:device_proof
         signature         bytes[64]                           (sección 7)
         session_token     Optional<bytes ≤ 256>               (si tiene uno para este server_id)
```

- Si hay `session_token` válido, ligado a este `device_pub` y permitido por la política (TTL, dispositivo conocido, admin con TOTP vigente), se salta a `SCRIPTS` (o a `AUTH` solo con TOTP si la política lo exige).
- Un dispositivo conocido con token válido entra al **carril prioritario** de la cola de login (RF-AUTH-06b).

### 5.3 Autenticación

`AuthPolicyView` (lo que el cliente necesita para dibujar la AuthScreen):

```
methods         List<enum { PASSWORD, TOTP, PASSWORD_TOTP, GOOGLE, DISCORD }>
require_totp    bool          (admin o cuenta con TOTP activo)
must_enroll     bool          (admin sin TOTP: hay que enrolarlo, RF-ADM-03)
email_verify    enum { BEFORE_PLAY, LATER }
min_password    VarInt
```

Mensajes del cliente (uno por intento):

| Mensaje | Campos | Uso |
|---|---|---|
| `sam:register` | `k: bytes[32]`, `email: String ≤ 254` | Registro (RF-AUTH-01). `k` según la sección 6 |
| `sam:login_password` | `k: bytes[32]`, `totp: Optional<String 6>` | `PASSWORD` o `PASSWORD_TOTP` |
| `sam:login_totp` | `code: String ≤ 16` | **Segundo paso** tras `NEED_TOTP`: código de 6 dígitos o de respaldo (`xxxx-xxxx`). No hay login solo con TOTP; `TOTP` y `PASSWORD_TOTP` de `AuthMethod` quedan reservados |
| `sam:oauth_start` | `provider: enum` | Inicia OAuth (5.4) |
| `sam:recovery_request` | `email: String ≤ 254` | "¿Olvidaste tu contraseña?" |
| `sam:recovery_complete` | `code: String ≤ 16`, `k_new: bytes[32]` | Completa la recuperación |
| `sam:email_verify` | `code: String ≤ 16` | Verificación del correo |

Respuesta del servidor:

```
S → C  sam:auth_result
         status        enum { OK, FAILED, LOCKED, NEED_TOTP, NEED_ENROLL,
                              NEED_EMAIL_VERIFY, RECOVERY_PENDING, RECOVERY_SENT }
         retry_after   Optional<VarInt segundos>
         detail        Optional<String ≤ 128>      (texto genérico; nunca revela la causa exacta)
```

- `FAILED` es idéntico para "contraseña incorrecta", "TOTP incorrecto" y "cuenta inexistente" en recuperación (RS-AUTH-05, RS-AUTH-07).
- `RECOVERY_PENDING`: la nueva contraseña quedó en espera por venir de un dispositivo desconocido (RN-43).
- El servidor solo hace Argon2 **después** de los chequeos baratos: estado correcto, límites por IP y cuenta, bloqueo vigente (RF-AUTH-06b).

Enrolamiento de TOTP:

```
S → C  sam:totp_enroll        secret_uri: String ≤ 256 (otpauth://, para el QR), backup_codes: List<String> = 10
C → S  sam:totp_confirm       totp: String 6
S → C  sam:auth_result        OK | FAILED
```

> `sam:totp_enroll` contiene el secreto TOTP: solo viaja por TLS y el cliente **no** lo guarda; solo lo muestra.

### 5.4 OAuth

```
C → S  sam:oauth_start         provider, port: VarInt
          (antes de pedirlo, el cliente ya abrió 127.0.0.1:<port>, que espera un solo request;
           el servidor arma redirect_uri = http://127.0.0.1:<port>/ y la usa también en el canje)
S → C  sam:oauth_url           url: String ≤ 2048
          (el cliente lanza el navegador del sistema con la URL)
C → S  sam:oauth_code          code: String ≤ 1024, state: String ≤ 128
S → C  sam:auth_result         OK | FAILED | NEED_TOTP
```

Alternativa de device flow (solo Google):

```
S → C  sam:oauth_device        user_code: String ≤ 16, verification_url: String ≤ 256, expires_in: VarInt
          (el servidor sondea a Google; el cliente solo muestra código y QR)
S → C  sam:auth_result
```

- `state` = 32 bytes aleatorios en base64url, de un solo uso, que el servidor asocia a **esta conexión** y a esta cuenta (RS-OAUTH-03).
- El `code_verifier` de PKCE nunca sale del servidor.

### 5.5 Scripts

```
S → C  sam:scripts_offer
         keylist        SignedBlob                        (8.1: claves de firma autorizadas)
         scripts        List<ScriptRef> ≤ 128
                          id        String ≤ 64
                          version   String ≤ 32
                          sha256    bytes[32]             (del paquete del script, 8.2)
                          size      VarInt
                          required  bool
                          caps      List<String ≤ 32> ≤ 32

C → S  sam:scripts_want        hashes: List<bytes[32]> ≤ 128      (los que no tiene en caché)
S → C  sam:script_chunk        sha256, index: VarInt, total: VarInt, data: bytes ≤ 256 KiB
          (el cliente verifica firma y hash al completar cada script; ver RS-SIG-05 y RF-LUA-05)
          → pantalla de consentimiento (protegida)
C → S  sam:scripts_consent     accepted: List<String id> ≤ 128
S → C  sam:done                (o kick SAM-K010 según SAM_SCRIPTS_CLIENT_ON_REJECT)
```

Límite total de descarga por conexión: 16 MiB (configurable). Los fragmentos fuera de orden o de un hash no ofrecido → `SAM-P002`.

### 5.6 Límites por mensaje del cliente

| Mensaje | Máximo |
|---|---|
| `sam:hello_ack`, `sam:device_proof` | 512 B |
| `sam:register`, `sam:login_*`, `sam:recovery_*`, `sam:email_verify`, `sam:totp_confirm` | 512 B |
| `sam:oauth_code` | 1,5 KiB |
| `sam:scripts_want`, `sam:scripts_consent` | 4 KiB |
| `sam:lua_msg` (play) | 4 KiB, con rate limit por script |

### 5.7 Fase play

| Mensaje | Dirección | Uso |
|---|---|---|
| `sam:account_open` | S → C | Abre la GUI de cuenta (lo disparan los comandos de RF-AUTH-07; ningún comando lleva secretos) |
| `sam:account_*` | ambos | Cambio de contraseña o correo, TOTP, vinculaciones, dispositivos, exportación y borrado. Reutilizan los formatos de 5.3; toda operación sensible exige reautenticación (`k` o TOTP) en el mismo mensaje |

Primera versión de la GUI de cuenta (RF-AUTH-07d):

```
C → S  sam:account_request     (vacío; al abrir "Opciones de cuenta")
S → C  sam:account_info        email: String ≤ 254 (enmascarado, RS-AUTH-07), email_verified: bool,
                               google: enum { UNAVAILABLE, AVAILABLE, LINKED },
                               totp: enum { UNAVAILABLE, OFF, ON }      (UNAVAILABLE: sin SAM_DATA_KEY)
C → S  sam:account_email       k: bytes[32], code: Optional<String ≤ 16>, email: String ≤ 254   (RF-AUTH-07b)
C → S  sam:oauth_start         provider, port                             (5.4; en play = vincular)
S → C  sam:oauth_url           url
C → S  sam:oauth_code          code, state
C → S  sam:account_unlink      k: bytes[32], code: Optional<String ≤ 16>, provider              (RF-OAUTH-02)
C → S  sam:totp_begin          k: bytes[32]                                (RF-AUTH-04: activar)
S → C  sam:totp_enroll         secret_uri: String ≤ 512 (otpauth://), backup_codes: List<String ≤ 16> = 10
C → S  sam:totp_confirm        code: String ≤ 16                           (el primer código lo activa)
C → S  sam:totp_disable        k: bytes[32], code: String ≤ 16
S → C  sam:account_result      status: enum { OK, FAILED, LOCKED }, detail: Optional<String ≤ 128>
                               (después de cada operación llega un account_info nuevo)
```

Con el 2FA activo, `account_email`, `account_unlink` y `totp_disable` exigen el código además de `k`. Los fallos de contraseña o de código en play cuentan para el mismo tope que en el login (SAM-K004).
| `sam:lua_msg` | ambos | Canal de un script: `script_id`, `channel: String ≤ 32`, `data: bytes ≤ 4 KiB` |
| `sam:notice` | S → C | Avisos (actualización disponible para admins, alerta del trust store) |

---

## 6. Derivación de la contraseña (RS-AUTH-01, P-06)

### 6.1 En el cliente

```
salt_c = SHA-256( "SAM-pw-v1" ‖ server_id ‖ UTF-8(lower(usuario)) )[0..16]
K      = Argon2id( password = UTF-8(NFKC(contraseña)),
                   salt     = salt_c,
                   m = 65536 KiB, t = 3, p = 1, longitud = 32 )
```

- La contraseña se normaliza con **NFKC** para que el mismo texto escrito en distintos teclados dé el mismo `K`.
- Antes de derivar, el cliente verifica la longitud mínima (`min_password`) y la lista de contraseñas comunes (RN-45).
- La derivación corre fuera del hilo de render, y la AuthScreen muestra "Verificando…" mientras tanto.
- `K` se borra de memoria (arreglo de bytes puesto a cero) tras enviarlo.

### 6.2 En el servidor

```
registro:  salt_s = 16 bytes aleatorios
           H      = Argon2id(K, salt_s, m = 19456 KiB, t = 2, p = 1, longitud = 32)
           se guarda en formato PHC:  $argon2id$v=19$m=19456,t=2,p=1$<salt_s>$<H>
login:     recalcular con los parámetros guardados y comparar en tiempo constante
```

- Si los parámetros del servidor cambian, se rehashea de forma transparente en el siguiente login exitoso.
- Los parámetros del **cliente** son parte del protocolo: cambiarlos exige una nueva etiqueta (`SAM-pw-v2`) y una migración.

### 6.3 Vectores de prueba

Calculados con **argon2-cffi 23.1.0** (libargon2, la implementación de referencia en C), independiente de la librería que usa SAM (BouncyCastle). Están fijados en `PasswordDerivationTest`. `SID_1` = `00000000000000000000000000000001`, `SID_2` = `00000000000000000000000000000002`.

| Caso | server_id | usuario | contraseña | K (hex) |
|---|---|---|---|---|
| V-PW-1 | `SID_1` | `Steve` | `correct horse battery staple` | `2670fc91c53990ea43eee76bdd79ab9dc1c573e61eaa334ba76f3d632e453ff0` |
| V-PW-2 | `SID_1` | `steve` | `correct horse battery staple` | igual a V-PW-1 (usuario sin distinguir mayúsculas) |
| V-PW-3 | `SID_1` | `Alex` | `contraseña` en NFC **y** en NFD | `94714c539adbeaee90659b787bca88a187ae136684ec47c06e7a629b7c4c6c4d` (ambas) |
| V-PW-4 | `SID_1` | `Steve` | `ｃｏｒｒｅｃｔ horse battery staple` (ancho completo) | igual a V-PW-1 (NFKC) |
| V-PW-5 | `SID_2` | `Steve` | `correct horse battery staple` | `1e84d73bb6c8debda213736336d99b3c756f33ef6a85deb14f96b0b8c783b1ed` (otro servidor, otro K) |

Salts intermedios: `salt_c(SID_1, "Steve")` = `dbbc407f54f9da1064ac152aa8bfce53`, `salt_c(SID_1, "Alex")` = `4dd1f807568c9881943f3541a17464a2`.

La librería Argon2 se valida además contra el vector oficial de la **RFC 9106, sección 5.3** (`Argon2idTest`).

---

## 7. Prueba de posesión del dispositivo (RS-NET-12, P-11)

### 7.1 Clave por servidor

```
seed            = 32 bytes aleatorios, generados una vez por instalación
                  y guardados en el almacén seguro del sistema operativo (RF-AUTH-05)
clave_servidor  = Ed25519 con semilla HKDF-SHA256(ikm = seed, salt = vacío,
                                                   info = "SAM-dev-v1" ‖ server_id, longitud = 32)
device_pub      = clave pública de clave_servidor
```

- Cada servidor ve una `device_pub` distinta: dos servidores no pueden reconocer al mismo jugador por su clave.
- Hay **un solo secreto** que proteger y respaldar (`seed`); las claves por servidor se recalculan cuando hacen falta y no se guardan.

### 7.2 Firma del desafío

```
binding = TLS-Exporter("EXPORTER-SAM-device-v1", contexto vacío, 32)   si la implementación lo expone
        | SHA-256( certificado del servidor en DER )                     en otro caso

mensaje = "SAM-dev-v1" ‖ server_id ‖ binding ‖ nonce ‖ UTF-8(lower(usuario))
firma   = Ed25519( clave_servidor, mensaje )
```

- La variante se elige en la fase 0 y es **la misma en cliente y servidor** (no se negocia, para evitar downgrades).
- El servidor valida la firma con el `device_pub` de `sam:hello_ack` y la asocia a la cuenta en el primer login exitoso desde ese dispositivo.
- **Token de sesión**: 32 bytes aleatorios. El servidor guarda solo `SHA-256(token)`, ligado a (cuenta, `device_pub`, vencimiento, política). Se presenta en `sam:device_proof` y sirve únicamente junto con una firma válida del mismo dispositivo.
- La firma incluye el `server_id` y el `binding` de la conexión, así que no se puede reenviar a otro servidor ni a otra conexión.

---

## 8. Firmas

### 8.1 SignedBlob (listas firmadas por el servidor)

```
SignedBlob {
  type        : String ≤ 32        ("keylist")
  version     : VarInt
  issued_at   : VarLong (epoch s)
  body        : bytes ≤ 64 KiB
  signature   : bytes[64]           Ed25519 con la clave de identidad del servidor sobre
                                    "SAM-blob-v1" ‖ type ‖ 0x00 ‖ version ‖ issued_at ‖ body
}
```

`keylist.body` = lista de `(key_id: bytes[8], public_key: bytes[32], label: String ≤ 64)`, donde `key_id = SHA-256(public_key)[0..8]`. Solo contiene claves **confirmadas** desde la consola (RS-SIG-03).

> Si el certificado del servidor usa ECDSA P-256 (respaldo de 3.1), las firmas de esta sección usan ECDSA P-256 con SHA-256.

### 8.2 Firma de scripts (P-08)

Estructura del script en el datapack:

```
data/<namespace>/sam_scripts/<script>/
  manifest.json
  main.lua
  ui/panel.lua
  assets/icono.png
  signature.json        ← generado por sam-signer
```

Lockfile canónico (no se guarda; se reconstruye al verificar):

```
<ruta relativa con '/'>\t<sha256 hex en minúsculas>\n     (una línea por archivo, salvo signature.json,
                                                          ordenadas por bytes UTF-8 de la ruta)
```

`signature.json`:

```json
{
  "format": "sam-sig-v1",
  "key_id": "<8 bytes hex>",
  "lock_sha256": "<sha256 hex del lockfile>",
  "signature": "<base64 de Ed25519 sobre 'SAM-script-v1' ‖ lock_sha256 (32 bytes)>"
}
```

Verificación (servidor al cargar y cliente en cada carga, RN-31): reconstruir el lockfile → comparar `lock_sha256` → verificar la firma con una clave del trust store (servidor) o de la `keylist` (cliente). Cualquier archivo de más, de menos o modificado invalida la firma.

**Rutas** (`ScriptPath`): mismas reglas que las *resource locations* de Minecraft. Segmentos de `[a-z0-9_.-]` separados por `/`, sin `.` ni `..` como segmento, sin segmentos vacíos ni separador final, hasta 256 caracteres. Solo minúsculas ASCII: así no hay colisiones de mayúsculas en Windows (`Main.lua` vs `main.lua`) ni trucos de Unicode. Cualquier otra ruta → rechazo. Máximo 256 archivos sin contar `signature.json`. Solo se excluye el `signature.json` de la **raíz**; uno en una subcarpeta es un archivo más.

**Vector** (implementación de referencia en Python; fijado en `LockfileTest`), con los archivos `manifest.json` = `{"id":"demo","version":"1.0.0"}\n`, `main.lua` = `print("hola")\n`, `ui/panel.lua` = `return {}\n`, `assets/icono.png` = bytes `00…0f`, `sub/signature.json` = `incluido` y `signature.json` = `ignorado`:

```
assets/icono.png	be45cb2605bf36bebde684841a28f0fd43c69850a3dce5fedba69928ee3a8991
main.lua	373de7452fc229c503ef11123bfd815d27ea516f0fe22fab908f4e490d29b09b
manifest.json	0b81a9cb125c5c2bb94a33e7556417b6530b63c4f5187b02c68fc422231a5e15
sub/signature.json	d01d3db53ce07cd9972426c565b7b222a18bdc53b0792d8daece9fe798d585d8
ui/panel.lua	1232d8379de77e154ca533689af2e42629dd7574bda5a0a390799849f07607c3
```

`lock_sha256` = `e0f67bcd51d697c24ce1826b3b5495f0c62b6e877493ee353005854f7a72f38d`

**`signature.json`: forma canónica y lectura estricta** (`ScriptSignature`). La escritura es siempre:

```
{"format":"sam-sig-v1","key_id":"<16 hex>","lock_sha256":"<64 hex>","signature":"<base64 de 64 bytes>"}\n
```

La lectura admite otro orden de claves y espacio en blanco, pero rechaza todo lo que pueda leerse distinto en dos implementaciones:
- más de 512 bytes, o cualquier carácter fuera del ASCII imprimible;
- espacio en blanco que no sea el de JSON (espacio, tab, LF, CR). El `\s` de Java aceptaría también `\f` y `\x0B`;
- claves duplicadas (un lector podría quedarse con la primera y otro con la última), desconocidas o faltantes;
- escapes (`a`), valores que no sean strings, comas finales o texto tras el objeto;
- hex en mayúsculas o de longitud incorrecta, y base64 no canónico (bits de relleno distintos de cero).

`key_id` = primeros 8 bytes de SHA-256 de la clave pública cruda (32 bytes), en hex. Mensaje firmado: `"SAM-script-v1" ‖ lock_sha256` (32 bytes).

**Vector** (`cryptography` de Python; fijado en `ScriptSignatureTest` y `ScriptSigningTest`): el lockfile de arriba firmado con la clave K1 de la RFC 8032 (`key_id` = `21fe31dfa154a261`):

```
{"format":"sam-sig-v1","key_id":"21fe31dfa154a261","lock_sha256":"e0f67bcd51d697c24ce1826b3b5495f0c62b6e877493ee353005854f7a72f38d","signature":"3LVXhNjtUBJ6g2kmsCTjBda7+iNyk6Id/pHFIN6dTuUDjhaPy9RpeyRrG0CEniaqjYCvYXnskdxox4cKv6t7Aw=="}
```

**Resultado de la verificación** (`ScriptVerifier`), en este orden: `MISSING_SIGNATURE`, `MALFORMED_SIGNATURE`, `INVALID_FILES`, `UNKNOWN_KEY`, `LOCK_MISMATCH`, `BAD_SIGNATURE` o válido.

El `sha256` de `ScriptRef` (5.5) es el `lock_sha256`, y el paquete que se transfiere es un archivo `.zip` **sin compresión** con exactamente los archivos del lockfile más `signature.json`. El cliente lo descomprime en memoria con límites de cantidad de archivos (≤ 256) y de tamaño total.

### 8.3 Claves de `sam-signer`

- Clave privada en un archivo PKCS#8 cifrado (PBES2, scrypt o PBKDF2-SHA256 con ≥ 600 000 iteraciones) con passphrase (RS-SIG-07).
- Comandos: `sam-signer keygen`, `sam-signer sign <carpeta>`, `sam-signer verify <carpeta>`, `sam-signer pubkey`.

---

## 9. Errores y códigos de desconexión

Formato del mensaje al jugador: texto traducible + código entre corchetes (por ejemplo, `[SAM-K002]`). El código va también a la auditoría.

| Código | Lado | Causa | Mensaje (resumen) |
|---|---|---|---|
| SAM-K001 | Servidor | Cliente sin SAM (vanilla en claro) | "Este servidor requiere SAM Client: <link>" |
| SAM-K002 | Servidor | Versión mayor incompatible | "Tu SAM Client es incompatible: <link>" |
| SAM-K003 | Servidor | Timeout del handshake SAM o de la autenticación | "Tiempo de espera agotado" |
| SAM-K004 | Servidor | Demasiados intentos / cuenta bloqueada | "Demasiados intentos. Reintenta en N min" |
| SAM-K005 | Servidor | Servidor saturado (cola de login llena) | "Servidor ocupado, reintenta en unos segundos" |
| SAM-K006 | Servidor | Configuración inválida, el login está cerrado (RF-CFG-04) | "Inicio de sesión no disponible" |
| SAM-K007 | Servidor | Nick inválido o reservado | "Nombre de usuario no permitido" |
| SAM-K010 | Servidor | Scripts requeridos rechazados | "Debes aceptar los scripts requeridos" |
| SAM-K011 | Servidor | Sesión reemplazada por un login completo desde otro lugar (RF-AUTH-06c) | "Iniciaste sesión desde otro lugar" |
| SAM-P001 | Ambos | Mensaje mal formado | "Error de protocolo" |
| SAM-P002 | Ambos | Mensaje fuera de estado | "Error de protocolo" |
| SAM-C001 | Cliente | La dirección fijada presenta otro `server_id` | Pantalla de advertencia de identidad |
| SAM-C002 | Cliente | Cambio de clave sin rotación válida | Pantalla de advertencia (RS-NET-08) |
| SAM-C003 | Cliente | Servidor fijado sin TLS o sin SAM (downgrade) | Pantalla de advertencia (RS-NET-10) |
| SAM-C004 | Cliente | Firma o hash de script inválido | El script se descarta; si es `required`, desconexión |

---

## 10. Timeouts y límites (resumen)

| Elemento | Valor por defecto | Configurable |
|---|---|---|
| Primeros bytes (detector) | 5 s | No |
| Handshake WebSocket | 5 s | `SAM_WS_HANDSHAKE_TIMEOUT` |
| Handshake TLS | 10 s | No |
| `sam:hello_ack` | 10 s | No |
| Autenticación completa | 120 s (300 s con OAuth) | `SAM_AUTH_TIMEOUT` |
| Ping WebSocket / cierre sin pong | 20 s / 60 s | No |
| Conexiones sin clasificar por IP / global | 8 / 256 | `SAM_NET_UNCLASSIFIED_PER_IP` / `_GLOBAL` (los proxies de confianza cuentan solo en el global; en el handshake WebSocket cuenta la IP real) |
| Logins pendientes por IP / global | 3 / 50 | `SAM_AUTH_PENDING_*` |
| Descarga de scripts por conexión | 16 MiB | Sí |

---

## 11. Plan de pruebas del protocolo

| Área | Pruebas |
|---|---|
| Detector | Cada fila de 2.1, bytes parciales, timeout, handshake vanilla con longitud 0x16 (caso límite) |
| WebSocket | Ruta errónea, `Origin`, texto en vez de binario, fragmentación, mensajes > límite, slowloris, solo TLS dentro del túnel |
| TLS | Solo 1.3, ALPN obligatorio, Ed25519 y respaldo P-256, rechazo de reanudación |
| Pinning | TOFU, pin correcto, cambio de clave, rotación válida e inválida, cadena de rotaciones, `server_id` duplicado con otra clave, CA con `server_id` no autorizado, downgrade |
| Mensajes | Fuzzing de cada `StreamCodec` (Jazzer), mensajes fuera de estado, bytes sobrantes, longitudes al límite |
| Autenticación | Vectores de 6.3, comparación en tiempo constante, respuestas idénticas en recuperación, carril prioritario, login duplicado |
| Dispositivo | Firma reenviada a otro servidor, token sin firma, token de otro dispositivo |
| Scripts | Lockfile con archivos de más o de menos, rutas maliciosas, zip con compresión o demasiados archivos, fragmentos fuera de orden |
| MITM | Proxy de pruebas que termina TLS con otra clave → el cliente debe abortar (SAM-C002) |

---

## 12. Validaciones de la fase 0

1. ✅ **Resuelto (ciclo 14):** la JSSE de la JDK completa handshakes TLS 1.3 con certificado **Ed25519**, ALPN `sam/1` y las suites del perfil (`SamTlsTest`). No hace falta el respaldo P-256.
   - Hallazgo: la JSSE solo aplica ALPN si el cliente ofrece la extensión. Un cliente TLS cualquiera **sin** ALPN completa el handshake, así que el servidor agrega un `AlpnGuard` que cierra la conexión si al terminar el handshake no se negoció `sam/1`. Cuando el cliente ofrece otros protocolos, la JSSE aborta sola.
2. ✅ **Resuelto:** el código se compila con `release 21`, y la JSSE de Java 21 no expone una API pública de *TLS exporter*. La sección 7 usa la variante **hash del certificado del servidor + nonce**: no depende de la versión de la JDK y es suficiente porque el pinning ya autentica al servidor.
3. Puntos de inserción del `SslHandler` en `Connection` y `ServerConnectionListener` de 1.21.1, y convivencia con la compresión y el cifrado vanilla (este último no se activa: el servidor es offline).
4. Que la `ConfigurationTask` de Fabric retenga al cliente 300 s sin que lo desconecte el keep-alive.
5. Costo real de Argon2id con P-06 en una PC modesta (objetivo ≤ 1 s en el cliente) y en el servidor bajo carga.
6. Que el campo `sam` en el JSON de estado no rompa clientes vanilla ni otros mods de lista de servidores.
7. Tamaños reales de los payloads (`CustomPacketPayload`) en configuration y play en 1.21.1.
