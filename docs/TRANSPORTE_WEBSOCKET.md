# SAM: transporte por WebSocket (decisión de diseño)

> Estado: **decisión tomada y consolidada**, 2026-11-04. Los requisitos de la sección 5 ya están en [REQUERIMIENTOS.md](REQUERIMIENTOS.md) 6.4 (que manda) y las amenazas de la sección 6 en [AMENAZAS.md](AMENAZAS.md) 5.6. Este documento queda como justificación del diseño.
> Depende de la decisión de T-NET-04 (AMENAZAS.md, sección 10): **TLS 1.3 en toda la conexión, desde el primer byte**.

## 1. Contexto

Los operadores quieren poner el servidor **detrás del proxy de Cloudflare** (u otro CDN) para ocultar su IP y absorber ataques DDoS. El proxy gratuito de Cloudflare solo acepta HTTP(S) y WebSocket, no TCP crudo (para eso existe Spectrum, que es de pago). El protocolo de Minecraft es TCP crudo, así que no pasa.

La solución es usar **WebSocket como transporte**: los bytes de la conexión viajan dentro de mensajes binarios de un WebSocket, que para el CDN es tráfico web normal. Como SAM ya exige `sam-client` (RF-AUTH-10), pedir que el cliente hable WebSocket no le agrega ningún requisito al jugador.

## 2. Alternativas evaluadas

| Alternativa | Qué es | Veredicto |
|---|---|---|
| **Mod "Cloudflared"** (dragon-forge) | Orquesta el ejecutable `cloudflared`: túnel en el host y `cloudflared access tcp` en el cliente | **Descartada.** Exige un binario externo en ambos lados, que descarga y ejecuta sin verificar; todos los jugadores llegan como `127.0.0.1` (sin IP real); detecta el estado parseando logs; su licencia prohíbe obras derivadas |
| **WSMC** (rikka0w0) | Mod Fabric/Forge/NeoForge que acepta WebSocket en el mismo puerto que TCP y agrega `ws://`/`wss://` al cliente | **Descartada como dependencia**, aunque valida la idea (ver 2.1) |
| **BambiettaServer** (proyecto propio, Rust) | Servidor completo para 1.20.4 que acepta TCP, `ws://` y `wss://` en el mismo puerto | **Referencia de diseño, no se reutiliza.** Es otra versión del juego y otro lenguaje, y no es un mod. Su contrato (`docs/WEBSOCKET.md`) sirve de modelo para el transporte |
| **Implementación propia en SAM** | Handler de Netty en `sam-server` y transporte cliente en `sam-client` | **Elegida** |

### 2.1 Por qué no usar WSMC

En teoría WSMC y SAM conviven: WSMC trabaja en el transporte (debajo del protocolo) y SAM agrega mensajes por encima. Pero:

1. **Dueño único del pipeline de Netty.** SAM inserta TLS 1.3 desde el primer byte y detecta qué tipo de conexión entra. El WebSocket tiene que quedar **por fuera** del TLS de SAM. Si dos mods reordenan el pipeline, el orden de los handlers es el lugar donde aparecen bugs sutiles y fallas de seguridad.
2. **La IP real del jugador es parte del modelo de amenazas.** `/ipban`, el rate limit por IP (RF-AUTH-06), los límites de conexiones (RN-12) y la auditoría dependen de ella. Decidir cuándo confiar en `CF-Connecting-IP` o `X-Forwarded-For` tiene que estar en el código de SAM, auditado y testeado junto al resto.
3. **Límites contra DoS** (tamaño de mensaje, timeouts del handshake HTTP, ruta secreta) bajo la misma política que RN-21.
4. **Distribución.** SAM se distribuye en dos jars; un tercer mod obligatorio empeora la instalación. Además la licencia de WSMC no está declarada en su README y su ritmo de versiones no depende de nosotros.

El costo de hacerlo propio es bajo: un detector de protocolo, el codec WebSocket de Netty y un adaptador de bytes en cada lado.

## 3. Decisión

**SAM implementa su propio transporte WebSocket**, en el **mismo puerto** que el TCP, con detección automática por los primeros bytes. El WebSocket es solo un transporte: por dentro viaja exactamente lo mismo que por TCP, incluido el TLS 1.3 de SAM.

## 4. Diseño

### 4.1 Capas

```
Cliente SAM                                            Servidor SAM
───────────                                            ────────────
protocolo Minecraft + mensajes SAM                     protocolo Minecraft + mensajes SAM
TLS 1.3 de SAM (pinning, RS-NET-03)   ═══ extremo a extremo ═══   TLS 1.3 de SAM
WebSocket (mensajes binarios)  ──>  [Cloudflare: termina su TLS]  ──>  WebSocket
TLS del CDN (wss://)                                   (ws:// o wss:// según el despliegue)
TCP                                                    TCP
```

- El **TLS de SAM va dentro del WebSocket**. Cloudflare termina *su* TLS (el de `wss://`), pero solo ve los bytes cifrados del TLS de SAM: **no puede leer ni alterar** el tráfico del juego, y el pinning del certificado del servidor sigue funcionando igual que por TCP.
- Por eso el WebSocket **no aporta seguridad propia** y no hace falta que sea `wss://` hasta el servidor. Entre el CDN y el servidor puede ir `ws://`; la confidencialidad la da el TLS de SAM.

### 4.2 Detección en el servidor

Un handler al inicio del pipeline mira los primeros bytes de cada conexión nueva:

| Primeros bytes | Interpretación | Acción |
|---|---|---|
| `GET ` (ASCII) | Upgrade a WebSocket | Handshake HTTP → codec WebSocket → adaptador de bytes → **se vuelve a detectar** dentro del túnel |
| `0x16 0x03` | ClientHello de TLS | TLS 1.3 de SAM → pipeline vanilla |
| Otro | Handshake vanilla en claro | Solo *status ping* y kick con el mensaje de descarga (decisión de T-NET-04) |

Dentro del WebSocket solo se acepta **TLS**: los clientes que llegan por WebSocket son siempre `sam-client`, así que no hace falta el camino en claro (ni siquiera para el *status ping*). Cualquier otra cosa → cierre.

### 4.3 Handshake HTTP y framing

- Petición `GET <ruta> HTTP/1.1` con `Upgrade: websocket` (RFC 6455). La ruta debe coincidir con `SAM_WS_PATH`; si no, `404` y cierre.
- Subprotocolo opcional: si el cliente pide uno, el servidor confirma `sam` o rechaza.
- Solo **mensajes binarios**. Un mensaje de texto cierra la conexión.
- Los mensajes forman un **flujo de bytes**, igual que TCP: un mensaje puede traer varios fragmentos del flujo o una parte de uno. Ninguno de los dos lados asume que un mensaje equivale a un paquete.
- Pings de WebSocket periódicos, además del keep-alive de Minecraft, para que el CDN no cierre la conexión por inactividad.

### 4.4 IP real del jugador

- Por defecto, la IP es la del socket (en un despliegue con Cloudflare, sería la de Cloudflare).
- Si la conexión **viene de un proxy de confianza**, la IP se toma de la cabecera configurada: `CF-Connecting-IP` para Cloudflare, `X-Forwarded-For` (el último salto agregado por el proxy) para nginx o Caddy.
- "De confianza" = la IP del socket está dentro de `SAM_WS_TRUSTED_PROXIES` (lista de CIDR). Para Cloudflare, SAM incluye los rangos publicados, actualizados con cada release, y el operador puede reemplazarlos.
- Si la cabecera llega desde una IP **fuera** de esa lista, **se ignora** y se registra en la auditoría.
- La IP resuelta es la que usa todo SAM: bans, rate limits, límites de conexiones, auditoría.

### 4.5 Cliente

- Sintaxis de la dirección: `wss://host[:puerto]/ruta` o `ws://...` en la lista de servidores.
- El mixin sobre `ServerAddress` **solo valida la sintaxis**, sin efectos secundarios: no resuelve DNS, no abre conexiones y no bloquea el hilo de render (el mod Cloudflared lanzaba procesos mientras el jugador escribía).
- Al conectar (y al hacer el ping de la lista de servidores), fuera del hilo de render: TCP → TLS del CDN si es `wss://` → handshake WebSocket → **TLS de SAM** → protocolo normal.
- El pin del servidor se asocia a la identidad del servidor (RS-NET-03), no a la dirección: un servidor accesible por TCP y por WebSocket es **el mismo servidor** para el cliente.

### 4.6 Dependencias

El codec de WebSocket está en `netty-codec-http`. Hay que verificar en la fase 0 si Minecraft 1.21.1 ya lo incluye; si no, se embebe con jar-in-jar en `sam-common` con la misma versión de Netty que trae el juego (RN-39).

## 5. Requerimientos

| ID | Requerimiento |
|---|---|
| RF-WS-01 | El servidor acepta WebSocket en el **mismo puerto** que TCP, con detección automática (4.2). Se activa con `SAM_WS_ENABLED`. |
| RF-WS-02 | `SAM_WS_PATH`: ruta obligatoria del endpoint (por defecto, una ruta aleatoria generada en el primer arranque). Otra ruta → `404`. |
| RF-WS-03 | `SAM_TCP_ENABLED=false` permite apagar el TCP directo y aceptar solo WebSocket, para que el servidor no sea alcanzable sin pasar por el CDN. El *status ping* en claro y el kick con el link de descarga siguen disponibles por WebSocket solo si el operador lo habilita. |
| RF-WS-04 | El cliente acepta direcciones `ws://` y `wss://` en la lista de servidores, incluido el ping de estado. |
| RF-WS-05 | `/sam info` muestra el estado del transporte: si está activo, la ruta (enmascarada), los proxies de confianza y cuántas conexiones entraron por cada transporte. |
| RF-WS-06 | La documentación para operadores incluye una guía para Cloudflare: registro DNS con proxy, puertos que acepta Cloudflare, `SAM_TCP_ENABLED=false` y firewall que solo permita los rangos de Cloudflare. |

| ID | Seguridad |
|---|---|
| RS-WS-01 | Dentro del WebSocket **solo se acepta TLS 1.3 de SAM**. El WebSocket no reemplaza ni debilita ninguna garantía del canal (RS-NET). |
| RS-WS-02 | Las cabeceras de IP solo se aceptan desde `SAM_WS_TRUSTED_PROXIES` (4.4); en cualquier otro caso se ignoran y se audita el intento. |
| RS-WS-03 | Límites: tamaño máximo de la petición HTTP (cabeceras incluidas), tamaño máximo de mensaje WebSocket, timeout del handshake HTTP (por defecto 5 s), límite de conexiones en estado "handshake" por IP y global. Al excederlos, cierre inmediato. |
| RS-WS-04 | Mensajes de texto, fragmentación inválida, frames de control mal formados o un subprotocolo desconocido → cierre sin respuesta detallada. |
| RS-WS-05 | Se rechazan las peticiones con cabecera `Origin`: `sam-client` nunca la envía y los navegadores siempre lo hacen (T-WS-08, agregada en la consolidación). |
| RS-WS-06 | Fuzzing del detector de protocolo y del handshake HTTP (Jazzer, igual que RN-21). |

### 5.1 `.env`

```dotenv
# ===== Transporte WebSocket =====
SAM_WS_ENABLED=false
SAM_WS_PATH=/<aleatoria>                      # generada en el primer arranque
SAM_TCP_ENABLED=true                          # false = solo WebSocket (recomendado detrás de un CDN)
SAM_WS_TRUSTED_PROXIES=cloudflare             # cloudflare | lista de CIDR | vacío
SAM_WS_REAL_IP_HEADER=CF-Connecting-IP        # o X-Forwarded-For
SAM_WS_MAX_MESSAGE=1MiB
SAM_WS_HANDSHAKE_TIMEOUT=5s
```

> Igual que en REQUERIMIENTOS.md 8.3, los nombres definitivos se cierran en la fase 0.

## 6. Amenazas nuevas

| ID | Amenaza | Actor | Impacto | Prob. | Mitigación | Residual |
|---|---|---|---|---|---|---|
| T-WS-01 | **IP falsificada** con `X-Forwarded-For` o `CF-Connecting-IP` para evadir bans y rate limits, o para culpar a otra IP | AT-01, AT-02 | Alto | **Alta** si se confía en la cabecera sin más | RS-WS-02 | Bajo |
| T-WS-02 | **Saltarse el CDN**: el atacante descubre la IP real del servidor y lo ataca directo | AT-01 | Alto | Media | RF-WS-03 + firewall solo para los rangos de Cloudflare (RF-WS-06) | Depende de la configuración del operador; se documenta |
| T-WS-03 | **DoS en el handshake HTTP**: conexiones lentas (*slowloris*), cabeceras gigantes, mensajes WebSocket enormes | AT-01 | Alto | Alta | RS-WS-03 | Bajo |
| T-WS-04 | **Downgrade dentro del túnel**: hablar en claro dentro del WebSocket para evitar el TLS de SAM | AT-02, AT-03 | Alto | Baja | RS-WS-01 (solo TLS dentro del WebSocket) y RN-18 en el cliente | Bajo |
| T-WS-05 | **El CDN como MITM**: Cloudflare termina el TLS de `wss://` | Proveedor | Medio | Baja | El TLS de SAM va extremo a extremo por dentro (4.1); el CDN solo ve bytes cifrados | Bajo: el CDN conoce metadatos (IPs, tiempos, volumen) |
| T-WS-06 | **Orden incorrecto del pipeline** (el WebSocket queda dentro del TLS, o el TLS no se aplica en algún camino) | Bug | **Crítico** | Media | SAM es el único dueño del pipeline (2.1) + tests de integración por cada camino de la tabla 4.2 | Bajo |
| T-WS-07 | **Escaneo de endpoints**: se descubre que el servidor es de Minecraft por la ruta | AT-01 | Bajo | Media | Ruta aleatoria (RF-WS-02) y `404` genérico | Bajo |
| T-WS-08 | **WebSocket desde un navegador**: una página web abre conexiones al servidor desde los navegadores de sus visitantes (DoS distribuido, o IPs de víctimas baneadas) | AT-01 | Medio | Baja | RS-WS-05 (rechazo de `Origin`) | Bajo |

## 7. Validaciones de la fase 0

1. ¿Minecraft 1.21.1 incluye `netty-codec-http`? Si no, jar-in-jar con la versión correcta.
2. Que Cloudflare (plan gratuito, registro con proxy) mantenga conexiones WebSocket largas con el keep-alive de Minecraft y los pings de 4.3, y medir la latencia agregada.
3. Que el TLS 1.3 de SAM funcione sin problemas dentro del WebSocket. Ojo: JSSE de JDK 21 no expone una API pública de *TLS exporter*; si se usa JSSE, la prueba de posesión del dispositivo usa la alternativa de RS-NET-12 (hash del certificado + nonce), o se evalúa BouncyCastle JSSE.
4. Qué puertos acepta Cloudflare para WebSocket con proxy (443, 8443, etc.: hay que confirmar la lista actual) y documentarlo en RF-WS-06.
5. Integración del mixin del cliente con `ServerAddress`, `ConnectScreen` y el ping de la lista de servidores sin bloquear el hilo de render.
6. Que el pipeline sea compatible con otros mods de red comunes (por ejemplo, de proxy o de compresión).

## 8. Pendiente

- ~~Incorporar RF-WS, RS-WS y T-WS a REQUERIMIENTOS.md y AMENAZAS.md~~ Hecho (REQUERIMIENTOS.md 6.4, AMENAZAS.md 5.6). En REQUERIMIENTOS.md la numeración de RF-WS cambió levemente (se agregó RF-WS-05 sobre el pin por identidad).
- Agregar el transporte a `docs/PROTOCOLO.md` cuando se escriba: detector, handshake HTTP y relación con el TLS de SAM.
