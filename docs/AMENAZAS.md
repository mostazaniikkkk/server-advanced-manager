# SAM: modelo de amenazas

> Estado: **v1.0, consolidado**, 2026-11-04. Todas las amenazas tienen una decisión (sección 10), ya incorporada a [REQUERIMIENTOS.md](REQUERIMIENTOS.md) v1.1. Incluye las amenazas del transporte WebSocket ([TRANSPORTE_WEBSOCKET.md](TRANSPORTE_WEBSOCKET.md)).
> Método: STRIDE por componente. Cada amenaza indica el actor, el impacto, la probabilidad, las mitigaciones (con referencias a requerimientos) y el riesgo residual.
> Las amenazas sin cobertura en los requerimientos generan **requerimientos nuevos (RN-xx)**, listados en la sección 9.

---

## 1. Alcance y supuestos

**Dentro del alcance**: `sam-server`, `sam-client`, `sam-common`, `sam-signer`, el protocolo cliente↔servidor, las integraciones con Google, Discord, SMTP y GitHub, el `.env`, la base de datos y el runtime de Lua en ambos lados.

**Supuestos**

| ID | Supuesto |
|---|---|
| S-01 | El servidor corre en **modo offline**: Mojang no autentica a nadie y el nick que envía el cliente no está verificado. |
| S-02 | El **operador** del servidor es confiable *para su propio servidor*. Los jugadores confían en el operador en la medida en que eligen jugar ahí, pero **no** le dan acceso a su PC más allá del juego (RS-LUA-00). |
| S-03 | Quien tiene **escritura total** sobre el sistema de archivos del servidor (puede reemplazar `sam-server.jar`) controla el servidor por completo. Ninguna mitigación de SAM resiste eso; ver la sección 8. |
| S-04 | La PC del jugador no está comprometida. El malware local y otros mods maliciosos del cliente quedan fuera del alcance. |
| S-05 | TLS 1.3 y las primitivas criptográficas estándar (Ed25519, AES-GCM, Argon2id, SHA-256) son seguras, y sus implementaciones (JSSE o BouncyCastle) se mantienen actualizadas. |
| S-07 | El CDN (Cloudflare), si se usa, es honesto en cuanto a no alterar el tráfico; igualmente no puede leerlo ni modificarlo sin que se detecte, porque el TLS de SAM va por dentro. |
| S-06 | SAM es open source: **el atacante conoce todo el código y el protocolo**. La seguridad no depende del secreto del diseño. |

---

## 2. Activos

| ID | Activo | Por qué importa |
|---|---|---|
| AC-01 | Credenciales de jugadores (contraseña y su derivado) | Toma de cuentas; los jugadores reutilizan contraseñas en otros servicios |
| AC-02 | **Privilegios de admin** (OP, `sam.admin`, consola) | Control total del servidor y de sus datos |
| AC-03 | Secretos TOTP y códigos de respaldo | Saltear el 2FA de los admins |
| AC-04 | Tokens de sesión y claves de dispositivo | Entrar sin credenciales |
| AC-05 | Correos de los jugadores (datos personales) | Privacidad y GDPR; vector de phishing |
| AC-06 | Clave de identidad del servidor | Suplantar al servidor ante los clientes y firmar listas de claves de scripts |
| AC-07 | Claves de firma de scripts | Distribuir código a los clientes |
| AC-08 | `.env` (secretos OAuth, SMTP, clave de cifrado de datos) | Contiene todos los demás secretos |
| AC-09 | **La PC del jugador** | Un escape de la sandbox de Lua en el cliente equivale a ejecutar código en su máquina |
| AC-10 | Disponibilidad del servidor | DoS durante el login, que es costoso (Argon2) |
| AC-11 | Integridad del mundo y de los datos de jugadores | Grief, robo de inventarios, sanciones falsas |
| AC-12 | Integridad de las releases del mod | Cadena de suministro hacia todos los servidores y clientes |

---

## 3. Actores de amenaza

| ID | Actor | Capacidades |
|---|---|---|
| AT-01 | **Atacante anónimo de internet** | Bots, credential stuffing, escaneo de servidores públicos, conexiones masivas |
| AT-02 | **Jugador malicioso con cliente modificado** | Envía paquetes arbitrarios, finge tener el mod, cambia su nick |
| AT-03 | **Atacante de red (MITM)** | Wi-Fi pública, ISP, ARP spoofing: lee, modifica e inyecta tráfico |
| AT-04 | **Servidor falso** | Instala SAM (es open source) y se hace pasar por un servidor conocido para robar contraseñas reutilizadas |
| AT-05 | **Operador malicioso** (desde la perspectiva del jugador) | Escribe scripts de cliente que intentan dañar o espiar al jugador |
| AT-06 | **Acceso parcial al hosting** | Panel web o FTP filtrado: lee o modifica archivos sueltos (datapacks, `.env`, backups) sin control total |
| AT-07 | **Insider** (staff o admin deshonesto) | Abusa de privilegios legítimos |
| AT-08 | **Cadena de suministro** | Releases falsas, typosquatting, dependencias comprometidas, cuenta de GitHub del maintainer comprometida |
| AT-09 | **Control de una cuenta externa del jugador** | Controla el Gmail o la cuenta de Discord de la víctima |

---

## 4. Fronteras de confianza

```
 [PC del jugador]                         [Servidor dedicado]                [Externos]
 ┌─────────────────────┐  TLS 1.3 de SAM     ┌───────────────────────┐   HTTPS   ┌──────────────┐
 │ sam-client          │◄═══════ F1 ═══════►│ sam-server            │◄── F4 ──►│ Google/Discord│
 │                     │ (TCP, o WebSocket   │                       │          │               │
 │                     │  vía CDN: F9)       │                       │          │               │
 │  ┌───────────────┐  │                     │  ┌─────────────────┐  │◄── F5 ──►│ SMTP          │
 │  │ Lua (cliente) │F2│                     │F3│ Lua (servidor)  │  │◄── F6 ──►│ GitHub API    │
 │  └───────────────┘  │                     │  └─────────────────┘  │          └──────────────┘
 │ navegador ◄─ F7 ─► loopback 127.0.0.1     │ .env · DB · datapacks │◄── F8 (sistema de archivos, hosting)
 └─────────────────────┘                     └───────────────────────┘
```

| Frontera | Qué la cruza | Riesgo principal |
|---|---|---|
| F1 | Todo el tráfico del juego y los mensajes SAM, dentro de TLS 1.3 | MITM en la primera conexión, suplantación, downgrade (ver T-NET) |
| F9 | CDN o proxy WebSocket entre cliente y servidor | IP falsificada en cabeceras, saltarse el CDN, DoS del handshake HTTP (ver T-WS) |
| F2 | Código del servidor → JVM del jugador | **Escape de la sandbox = ejecución remota de código en la PC del jugador** |
| F3 | Scripts del operador → servidor | Escalada a comandos de consola |
| F4 | OAuth | Validación de tokens, CSRF |
| F5 | Correo | Toma de cuentas vía recuperación, spam |
| F6 | Aviso de actualizaciones | Respuestas falsas |
| F7 | Redirect de OAuth al loopback | Intercepción local del código |
| F8 | Archivos del servidor | Robo de secretos, alteración de scripts |

---

## 5. Amenazas por componente

Escala: **Impacto**: Crítico / Alto / Medio / Bajo. **Probabilidad** (antes de aplicar los RN): Alta / Media / Baja.

> Las columnas "Mitigaciones" y "Residual" describen el análisis original. La decisión final de cada amenaza está en la sección 10 y ya figura en REQUERIMIENTOS.md v1.1. Donde la decisión cambió el análisis, la fila lo indica con **→ Decisión**.

### 5.1 Autenticación (AUTH)

| ID | Amenaza | Actor | Impacto | Prob. | Mitigaciones | Residual |
|---|---|---|---|---|---|---|
| T-AUTH-01 | **Fuerza bruta y credential stuffing** sobre `password` | AT-01 | Alto | Media | Argon2id (RS-AUTH-01), rate limit y bloqueo (RF-AUTH-06), política de complejidad | Las contraseñas débiles siguen cayendo ante ataques lentos y distribuidos. **RN-01** (bloqueo exponencial) y **RN-02** (aviso por correo de intentos fallidos). **→ Decisión (RN-45)**: lista offline de contraseñas comunes, chequeada en el cliente. |
| T-AUTH-02 | **Bloqueo abusivo**: el atacante falla a propósito para bloquear la cuenta de la víctima | AT-01, AT-02 | Medio | **Alta** | Ninguna: RF-AUTH-06 lo *habilita* | **RN-03**: bloqueo por (cuenta, IP) y los dispositivos de confianza quedan exentos del bloqueo global. |
| T-AUTH-03 | **Expulsión por login duplicado**: en offline, un atacante se conecta con el nick de un admin conectado y vanilla **expulsa al jugador legítimo** antes de que el atacante se autentique | AT-02 | Alto | **Alta** | Ninguna | **RN-04** (crítico): una conexión nueva con un nick ya conectado se rechaza; solo si se autentica completamente reemplaza a la sesión anterior. |
| T-AUTH-04 | **Saltear la autenticación**: llegar a la fase *play* sin completar la tarea de SAM (excepción, condición de carrera, otro mod, `/reload` a mitad del login) | AT-02 | **Crítico** | Media | Login en la fase de configuration (RF-AUTH-02, 5.3), fail-closed por configuración (RF-CFG-04) | **RN-05**: cualquier excepción o estado inesperado durante la tarea → desconexión (fail-closed también en runtime). Hay que probarlo con GameTests. |
| T-AUTH-05 | **Robo de nick ("squatting")**: registrar primero el nick de un jugador conocido | AT-01 | Medio | Alta | Inherente al modo offline. Normalización de nicks (RS-AUTH-06) | Aceptado (R-ACC-01). **RN-06**: el admin puede reservar nicks. |
| T-AUTH-06 | **Nicks inválidos y homoglifos**: el cliente en offline puede enviar nicks con caracteres raros para imitar a un admin | AT-02 | Alto | Media | RS-AUTH-06 | **RN-07**: SAM valida estrictamente `[A-Za-z0-9_]{3,16}` sin depender de vanilla, y compara contra los admins sin distinguir mayúsculas. **→ Decisión**: validación configurable (`off`/`strict`/`strict_similarity`) con un mínimo no desactivable. |
| T-AUTH-07 | **Fuerza bruta del método `totp`** (sin contraseña): cada intento acierta con probabilidad ≈ 3/10⁶, porque con una ventana de ±1 paso hay 3 códigos válidos | AT-01 | **Crítico** si la cuenta es de un admin | Media | Rate limit más duro (nota de la sección 5.0), anti-replay | **Cálculo**: con un límite fijo de 5 intentos cada 15 minutos son 480 intentos al día, una probabilidad de ≈0,14 % diaria y de **≈41 % en un año**. **RN-01** (bloqueo exponencial) la baja a ≈0,02 % al año. **RN-08**: `totp` sin contraseña **no** se permite para admins por defecto. |
| T-AUTH-08 | **Replay del código TOTP** observado por alguien | AT-03 | Medio | Baja | Un código no se acepta dos veces (5.0), canal cifrado | Bajo |
| T-AUTH-09 | **Phishing con servidor falso**: el servidor falso usa SAM, el jugador escribe la misma contraseña que en el servidor real, y el falso **la recibe en claro**, porque él mismo es el extremo del canal cifrado. El pinning no ayuda porque es otro servidor. | AT-04 | **Crítico** | **Alta** (es gratis montar un servidor) | Ninguna | **RN-09** (crítico): **derivación de la contraseña ligada al servidor** en el cliente. El servidor nunca ve la contraseña real, sino `Argon2id(password, server_id + usuario)`, que no sirve en otro servidor. Mejora futura: un PAKE asimétrico (OPAQUE). **RN-42**: huella visual del certificado y aviso de servidor desconocido (ver 7.1). |
| T-AUTH-10 | **Toma de cuenta vía correo**: el atacante controla el correo de la víctima y recupera la contraseña | AT-09 | Alto | Media | El TOTP sigue siendo obligatorio tras la recuperación (RF-AUTH-01c) | Las cuentas sin TOTP caen. Se notifica el cambio de contraseña. **→ Decisión (RN-43)**: desde un dispositivo desconocido la nueva contraseña se activa tras 24 h y los dispositivos de confianza pueden cancelarla. |
| T-AUTH-11 | **Cambio de correo sin autorización** (sesión robada) seguido de una recuperación | AT-02 | Alto | Media | Ninguna explícita | **RN-10**: cambiar el correo exige la contraseña (y el TOTP si está activo), confirmar el correo nuevo y avisar al anterior, con un periodo de espera antes de poder recuperar la cuenta con el correo nuevo. |
| T-AUTH-12 | **Ocupar un correo ajeno**: registrarse con el correo de la víctima para que ella no pueda usarlo (límite de 1 cuenta por correo) | AT-01 | Medio | Media | Verificación del correo (RF-AUTH-01b) | **RN-11**: un correo **no verificado** no cuenta para el límite ni sirve para recuperar la cuenta, y vence en 24 h. **→ Decisión**: se quita `SAM_REGISTER_EMAIL_VERIFY=off`. |
| T-AUTH-13 | **Enumeración de cuentas** | AT-01 | Bajo | Alta | Mensajes genéricos (RS-AUTH-05, RS-AUTH-07) | Inherente: la pantalla de registro o de login revela si el nick existe. Aceptado (R-ACC-02). |
| T-AUTH-14 | **DoS del login**: muchas conexiones retenidas en configuration, cada una disparando Argon2, que consume mucha memoria | AT-01 | Alto | **Alta** | Argon2 fuera del hilo principal (RNF-01) | **RN-12**: cola de Argon2 acotada, límite de logins pendientes por IP y global, parámetros de Argon2 que acoten la RAM, y verificaciones baratas antes de hashear. RN-09 traslada la parte más cara al cliente. **→ Decisión**: además, carril prioritario para dispositivos conocidos con sesión válida. |
| T-AUTH-15 | **Privilegios antes del 2FA vía LuckPerms**: otros mods consultan LuckPerms directamente y SAM no puede interceptar esas consultas | AT-02 (con una cuenta de staff robada sin TOTP) | **Crítico** | Media | RF-ADM-04 (solo cubre OP y fabric-permissions-api) | **RN-13**: SAM registra un **contexto de LuckPerms `sam:verified=true`**, y la documentación indica asignar los permisos de staff solo bajo ese contexto. Además, mixins sobre el nivel de permiso vanilla. |
| T-AUTH-16 | **Escalada por "consola falsa"**: los comandos reservados a la consola (`sam admin add`, `sam auth reset`) también se pueden ejecutar desde **RCON, bloques de comando, funciones de datapacks o Lua** ("ejecutar como consola", RF-LUA-03), porque todos corren con nivel 4 | AT-06, AT-05, AT-02 | **Crítico** | **Alta** | Ninguna | **RN-14** (crítico): los comandos sensibles de SAM solo se aceptan desde la **consola real (stdin)**. Por defecto se rechazan desde RCON, bloques de comando, funciones y Lua. Lua tiene además una lista blanca de comandos ejecutables. |
| T-AUTH-17 | **Credenciales en el chat**: comandos como `/sam auth changepassword <x>` viajan por el tráfico vanilla, que en offline no va cifrado, y vanilla los registra en el log | AT-03, AT-06 | Alto | Alta | Ninguna | **RN-15**: ninguna operación con secretos (contraseña, correo, TOTP, vinculación) acepta argumentos por comando. Todas se hacen desde la GUI de SAM por el canal seguro. |
| T-AUTH-18 | **Robo de token de sesión** | AT-03, AT-06 | Alto | Baja | Token ligado a la clave del dispositivo (RS-NET-07), TTL corto para admins (RF-ADM-05) | Si hay malware en la PC, se roba también la clave (fuera del alcance, S-04). **→ Decisión (RN-44)**: clave del dispositivo en el almacén seguro del sistema operativo. |
| T-AUTH-19 | **Insider**: un admin abusa de sus privilegios o altera la auditoría | AT-07 | Alto | Baja | Auditoría (RF-ADM-06) | **RN-16**: log de auditoría encadenado por hash (detecta borrados) y exportable. Un admin con acceso a la consola sigue teniendo control total (R-ACC-03). |

### 5.2 Red y protocolo (NET)

| ID | Amenaza | Actor | Impacto | Prob. | Mitigaciones | Residual |
|---|---|---|---|---|---|---|
| T-NET-01 | **MITM en la primera conexión** (TOFU) | AT-03 | Alto | Baja | Pinning (RS-NET-03), CA opcional (RS-NET-04) | Aceptado sin CA (R-ACC-04); la ventana es solo la primera conexión. |
| T-NET-02 | **El jugador acepta el cambio de clave** sin leer la advertencia | AT-03 | Alto | Media | Advertencia (RS-NET-03) | **RN-17**: aceptar el cambio exige escribir el nombre del servidor. Si la cuenta es de un admin, **no se puede aceptar** desde el cliente y hay que revocar el pin a mano. |
| T-NET-03 | **Downgrade**: un MITM elimina el canal SAM y el cliente se conecta "como vanilla" a un servidor que ya tenía fijado | AT-03 | Medio | Media | Ninguna | **RN-18**: si un servidor fijado no inicia el handshake de SAM, el cliente aborta la conexión. |
| T-NET-04 | **Secuestro de la sesión vanilla**: en offline, el tráfico del juego **no va cifrado ni autenticado**, así que un MITM puede **inyectar comandos** en la conexión de un admin ya autenticado | AT-03 | **Crítico** | Media | Ninguna (el canal SAM solo protege los mensajes de SAM) | **RN-19** (crítico): **activar el cifrado vanilla también en offline**. Desde 1.20.5, el paquete de solicitud de cifrado trae el campo `shouldAuthenticate`; con `false`, el cliente cifra sin consultar a Mojang. Además se hace **channel binding**: el handshake de SAM firma el hash del secreto compartido vanilla, lo que detecta un MITM. **→ Decisión**: se reemplaza RN-19 por **TLS 1.3 en toda la conexión** desde el primer byte, con el certificado del servidor y pinning (ver 7.2). |
| T-NET-05 | Falta de integridad en el cifrado vanilla (AES-CFB8, sin MAC) | AT-03 | Medio | Baja | RN-19 + canal SAM con AEAD | **→ Decisión**: cerrada. TLS 1.3 da integridad AEAD a todo el tráfico. |
| T-NET-06 | Replay o reordenamiento de mensajes SAM | AT-03 | Medio | Baja | Contadores en el canal SAM | **→ Decisión**: cerrada. TLS 1.3 protege contra replay y reordenamiento. |
| T-NET-07 | **Robo de la clave de identidad del servidor** | AT-06 | Alto | Media | Permisos y passphrase (RS-NET-01) | Con la clave, se puede suplantar al servidor ante los clientes que lo tienen fijado. **RN-20**: procedimiento de rotación y revocación documentado. Con CA se rota sin alertas. **→ Decisión**: passphrase desde variable de entorno + rotación firmada por el certificado anterior. |
| T-NET-08 | **Cliente que finge tener el mod** | AT-02 | Bajo | Alta | RS-AUTH-04: el servidor valida todo | Bajo |
| T-NET-09 | Payloads malformados o gigantes (parsers) | AT-02 | Alto | Media | — | **RN-21**: límite de tamaño por payload, parsing estricto y fuzzing de los decoders. |

### 5.3 OAuth (Google y Discord)

| ID | Amenaza | Actor | Impacto | Prob. | Mitigaciones | Residual |
|---|---|---|---|---|---|---|
| T-OAU-01 | Intercepción del código en el loopback por otro proceso local | Local | Medio | Baja | PKCE con el verifier solo en el servidor (5.5) | Bajo |
| T-OAU-02 | **CSRF o vinculación forzada**: el atacante logra que la víctima vincule una cuenta de Google ajena, o al revés | AT-02 | Medio | Baja | `state` de un solo uso (RS-OAUTH-03) | **RN-22**: el `state` queda ligado a la conexión concreta y a la cuenta SAM que inició el flujo. |
| T-OAU-03 | **Validación incorrecta del ID token** (`alg=none`, `aud` ajeno, token expirado) | AT-02 | **Crítico** | Baja | Validación completa (5.5) | **RN-23**: usar una librería mantenida (nimbus-jose-jwt) con una lista blanca de algoritmos, y tests negativos. |
| T-OAU-04 | Cuenta de Google de la víctima comprometida | AT-09 | Medio | Media | Los admins exigen TOTP (RF-OAUTH-04) | Las cuentas de jugadores normales caen. Aceptado (R-ACC-06). |
| T-OAU-05 | **Pantalla de consentimiento engañosa**: un servidor falso usa el nombre del real en su app de Google | AT-04 | Bajo | Media | Cada servidor tiene su propio `client_id` | Solo obtiene el `sub` de la víctima; **no** sirve para entrar al servidor real. OAuth resiste el phishing entre servidores. |
| T-OAU-06 | Filtración del `client_secret` | AT-06 | Medio | Media | Solo en el `.env` (RS-OAUTH-04) | Sin el redirect y el PKCE del servidor, el impacto es bajo. Se rota desde la consola de Google. |
| T-OAU-07 | Puerto fijo de Discord ocupado o secuestrado por otro proceso | Local | Bajo | Baja | Se valida en la fase 0 (RF-OAUTH-07) | Bajo |

### 5.4 Scripts Lua (LUA)

| ID | Amenaza | Actor | Impacto | Prob. | Mitigaciones | Residual |
|---|---|---|---|---|---|---|
| T-LUA-01 | **Escape de la sandbox en el cliente**: una función de la API o un bug de Cobalt filtra un objeto Java y el script ejecuta código nativo en la PC del jugador | AT-05, AT-06 | **Crítico** | Media | Lista blanca (RS-LUA-02), principio RS-LUA-00, tests maliciosos (RS-LUA-02c) | **Es el riesgo más grave para los jugadores**: si el servidor está comprometido (S-03), **la sandbox es la última línea de defensa**. **RN-24**: la API nunca expone objetos Java (solo tablas y valores primitivos copiados), con revisión de seguridad obligatoria de cada función nueva de la API, fuzzing, Cobalt con versión fija y seguimiento de sus CVE. |
| T-LUA-02 | Escape de la sandbox en el servidor | AT-05 | Alto | Baja | Igual que T-LUA-01 | El operador ya controla su servidor; el impacto es menor. |
| T-LUA-03 | **DoS por script**: loops infinitos, memoria, consumo del tick de render en el cliente | AT-05 | Medio | Media | Límites (RS-LUA-03) | **RN-25**: Cobalt no limita la memoria de forma nativa; hace falta una contabilidad aproximada por asignación, validada en la fase 0. También hay un presupuesto de tiempo por frame en el cliente. |
| T-LUA-04 | **Phishing con GUI**: un script dibuja una pantalla "Inicia sesión con Google" o una AuthScreen falsa para pedir contraseñas | AT-05 | Alto | Media | Pantallas protegidas (RS-LUA-07) | Un script sigue pudiendo crear un formulario genérico. **RN-26**: toda pantalla creada o reemplazada por un script lleva una **marca no removible** ("Interfaz del servidor"), y la AuthScreen muestra el aviso "SAM nunca te pedirá tu contraseña de Google dentro del juego". |
| T-LUA-05 | **Keylogging**: un script registra eventos de teclado y captura lo que se escribe en pantallas protegidas | AT-05 | Alto | Media | RS-LUA-07 | **RN-27**: mientras hay una pantalla protegida abierta, los scripts **no reciben ningún evento** de entrada, render ni tick de UI. |
| T-LUA-06 | **Fingerprinting o recolección de datos del cliente** (mods instalados, opciones, resource packs, resolución) | AT-05 | Bajo | Media | RS-LUA-00 | **RN-28**: la API de lectura de estado expone una lista cerrada de datos de partida y nada del entorno del cliente. |
| T-LUA-07 | **Imágenes maliciosas** en los recursos de un script (bugs del decodificador PNG) | AT-05 | Alto | Baja | Límite de tamaño (RF-LUA-08) | **RN-29**: solo PNG, con dimensiones y tamaño máximos, decodificado con `NativeImage` de vanilla y validado antes de subirlo a la GPU. |
| T-LUA-08 | **Alteración de datapacks en el hosting** (subida parcial) | AT-06 | Alto | Media | Firma de scripts (RS-SIG-01) | Cubierto si el atacante no puede escribir en `trusted/` ni en el `.env`. |
| T-LUA-09 | **Con escritura en `trusted/` o en el `.env`**: el atacante agrega su clave o activa el modo dev | AT-06 | **Crítico** para los jugadores | Baja | El modo dev nunca envía scripts sin firma al cliente (RS-SIG-03) | Agregando su propia clave, sus scripts llegan firmados a los clientes. Para los jugadores, la protección es la sandbox (T-LUA-01). **RN-30**: un cambio en el trust store se avisa a los admins en el juego y en la consola, y queda en la auditoría. **→ Decisión**: además, una clave nueva no se activa hasta que un admin la confirma desde la consola. |
| T-LUA-10 | Envenenamiento de la caché de scripts del cliente | Local | Medio | Baja | Caché por hash (RF-LUA-05) | **RN-31**: verificar la firma **en cada carga**, no solo al descargar. |
| T-LUA-11 | Robo de la clave de firma de scripts | AT-08, robo de la PC del operador | Alto | Baja | Firma offline (RS-SIG-06), revocación (RS-SIG-05) | **RN-32**: `sam-signer` cifra las claves con passphrase (formato estándar) y documenta su almacenamiento en un gestor de contraseñas o un token de hardware. |
| T-LUA-12 | Un script interfiere con otro (lee su estado o se hace pasar por él en la mensajería) | AT-05 | Bajo | Baja | Aislamiento (RS-LUA-06) | Bajo |

### 5.5 Datos y configuración (DATA)

| ID | Amenaza | Actor | Impacto | Prob. | Mitigaciones | Residual |
|---|---|---|---|---|---|---|
| T-DAT-01 | **Robo de la base de datos** (backups, dumps) | AT-06 | Alto | **Alta** (los backups se filtran a menudo) | Argon2id, TOTP y correos cifrados (RS-AUTH-03, RS-AUTH-07) | El cifrado **solo protege si el `.env` no se filtra junto con la base**: la clave de cifrado vive en el mismo disco. **RN-33**: la documentación indica excluir el `.env` de los backups de datos y advierte de esta limitación. RN-09 obliga además a crackear el Argon2 del cliente. **→ Decisión**: los secretos maestros (`SAM_DATA_KEY`, `SAM_IDENTITY_PASSPHRASE`) vienen solo de variables de entorno, nunca del `.env`. |
| T-DAT-02 | **Filtración del `.env`**: subido a GitHub en un repo de configuración, visible en el navegador de archivos del panel o metido dentro de un datapack | AT-06, error humano | **Crítico** | **Alta** (muchos servidores públicos versionan su configuración) | Enmascarado (RF-CFG-06) | **RN-34**: se genera un `.gitignore` junto al `.env`; SAM rechaza arrancar si el `.env` está dentro de la carpeta del mundo o de un datapack, y advierte de permisos abiertos. |
| T-DAT-03 | Secretos o datos personales en los logs (incluidos los logs vanilla de comandos) | AT-06 | Alto | Media | RF-CFG-06, RS-AUTH-07 | Cubierto con RN-15. |
| T-DAT-04 | Inyección SQL | AT-02 | **Crítico** | Baja | — | **RN-35**: solo consultas parametrizadas; prohibido concatenar SQL (regla de lint en CI). |
| T-DAT-05 | **Inyección en los correos** (cabeceras, plantillas con el nick o datos del jugador) | AT-02 | Medio | Media | — | **RN-36**: validación del correo según RFC 5322, escape HTML de las variables en las plantillas y sin cabeceras derivadas de datos del usuario. |
| T-DAT-06 | Uso del servidor para enviar spam | AT-01 | Medio | Media | RS-AUTH-08 | Bajo |
| T-DAT-07 | **Derechos sobre los datos personales (GDPR)** en servidores públicos | Regulatorio | Medio | Media | Minimización (RS-OAUTH-02) | **RN-37**: el jugador puede exportar y borrar sus datos (desde la GUI de cuenta o pidiéndolo a un admin), y se incluye una plantilla de aviso de privacidad para el operador. |

### 5.6 Transporte WebSocket (WS)

Origen: [TRANSPORTE_WEBSOCKET.md](TRANSPORTE_WEBSOCKET.md), sección 6. Requerimientos en REQUERIMIENTOS.md 6.4.

| ID | Amenaza | Actor | Impacto | Prob. | Mitigaciones | Residual |
|---|---|---|---|---|---|---|
| T-WS-01 | **IP falsificada** con `X-Forwarded-For` o `CF-Connecting-IP` para evadir bans y rate limits, o para culpar a otra IP | AT-01, AT-02 | Alto | **Alta** si se confía en la cabecera sin más | Cabeceras aceptadas solo desde proxies de confianza (RS-WS-02) | Bajo |
| T-WS-02 | **Saltarse el CDN**: el atacante descubre la IP real del servidor y lo ataca directo | AT-01 | Alto | Media | `SAM_TCP_ENABLED=false` + firewall solo para los rangos de Cloudflare (RF-WS-03, RF-WS-07) | Depende de la configuración del operador; se documenta |
| T-WS-03 | **DoS en el handshake HTTP**: conexiones lentas (*slowloris*), cabeceras gigantes, mensajes WebSocket enormes | AT-01 | Alto | Alta | Límites y timeouts (RS-WS-03) | Bajo |
| T-WS-04 | **Downgrade dentro del túnel**: hablar en claro dentro del WebSocket para evitar el TLS de SAM | AT-02, AT-03 | Alto | Baja | Solo TLS dentro del WebSocket (RS-WS-01) y abort en el cliente (RS-NET-10) | Bajo |
| T-WS-05 | **El CDN como MITM**: Cloudflare termina el TLS de `wss://` | Proveedor | Medio | Baja | El TLS de SAM va extremo a extremo por dentro | Bajo: el CDN conoce metadatos (IPs, tiempos, volumen). Aceptado (R-ACC-05) |
| T-WS-06 | **Orden incorrecto del pipeline** (el WebSocket queda dentro del TLS, o el TLS no se aplica en algún camino) | Bug | **Crítico** | Media | SAM es el único dueño del pipeline + tests de integración por cada camino de conexión (RNF-03) | Bajo |
| T-WS-07 | **Escaneo de endpoints**: se descubre que el servidor es de Minecraft por la ruta | AT-01 | Bajo | Media | Ruta aleatoria (RF-WS-02) y `404` genérico | Bajo |
| T-WS-08 | **WebSocket desde un navegador**: una página web abre conexiones al servidor desde los navegadores de sus visitantes (para DoS distribuido o para que las IPs de víctimas queden baneadas) | AT-01 | Medio | Baja | Se rechazan las peticiones con cabecera `Origin`, que los navegadores siempre envían y `sam-client` nunca (RS-WS-05) | Bajo |

### 5.7 Cadena de suministro y actualizaciones (SUP)

| ID | Amenaza | Actor | Impacto | Prob. | Mitigaciones | Residual |
|---|---|---|---|---|---|---|
| T-SUP-01 | **Releases falsas** (repos clonados, typosquatting) de `sam-client` con malware | AT-08 | **Crítico** | Media | Distribución solo por GitHub Releases | **RN-38**: releases con checksums SHA-256 y **firma** (Sigstore/cosign o GPG) y build reproducible. El kick por falta de cliente muestra el **repositorio oficial** por defecto. |
| T-SUP-02 | **Dependencia comprometida** (Cobalt, BouncyCastle, Argon2, JWT) | AT-08 | **Crítico** | Baja | — | **RN-39**: dependency verification de Gradle (checksums fijos), mínimo de dependencias, Dependabot y revisión de cada actualización. |
| T-SUP-03 | **Cuenta de GitHub del maintainer comprometida** (release maliciosa "oficial") | AT-08 | **Crítico** | Baja | — | **RN-40**: 2FA obligatorio, rama principal protegida, tags firmados y releases **solo desde CI**, con atestación de procedencia (SLSA). |
| T-SUP-04 | **Respuesta falsa del aviso de actualizaciones** | AT-03 | Bajo | Baja | Solo informativo y sin descargas (RF-UPD-03) | **RN-41**: HTTPS con validación de certificado y links solo hacia el repositorio oficial. |

---

## 6. Escenarios de ataque prioritarios

Son las cadenas más probables contra un servidor público típico, en orden de gravedad.

1. **Robo de contraseñas con un servidor falso (T-AUTH-09)**: el atacante clona el nombre y el MOTD de un servidor conocido, instala SAM y difunde la IP. Los jugadores escriben la misma contraseña que usan en el servidor real (y en otros sitios). → **RN-09** es imprescindible antes de la v1.
2. **Comandos de admin por "consola falsa" (T-AUTH-16)**: un script Lua o una función de datapack ejecuta `sam admin add atacante`. → **RN-14**.
3. **Secuestro de la sesión de un admin en una red compartida (T-NET-04)**: el admin juega desde una Wi-Fi pública, se autentica correctamente y un MITM le inyecta `/op atacante`. → **TLS 1.3 en toda la conexión** (7.2).
7. **Ataque directo saltándose el CDN o falsificando la IP (T-WS-01, T-WS-02)**: el atacante encuentra la IP real del servidor, o envía `CF-Connecting-IP` falso para evadir un ban. → RS-WS-02 y `SAM_TCP_ENABLED=false` con firewall.
4. **Expulsión y molestia a admins (T-AUTH-03 + T-AUTH-02)**: un bot entra con el nick del admin, lo expulsa y le bloquea la cuenta con intentos fallidos. → **RN-04** y **RN-03**.
5. **De admin sin TOTP a permisos de LuckPerms (T-AUTH-15)**. → **RN-13**.
6. **Servidor comprometido que ataca a sus jugadores (T-LUA-09 → T-LUA-01)**: el atacante agrega su clave de firma y envía un script que busca un escape de la sandbox. → La calidad de la sandbox (**RN-24**) protege a todos los jugadores de todos los servidores que usan SAM.

---

## 7. Detalle de las mitigaciones críticas

### 7.1 RN-09: derivación de la contraseña ligada al servidor

```
server_id   = identificador aleatorio de 128 bits, generado una vez y estable;
              va dentro del certificado TLS del servidor (RS-NET-01)
salt_c      = SHA-256("SAM-pw-v1" ‖ server_id ‖ lower(usuario))
K           = Argon2id(password, salt_c, m=64 MiB, t=3, p=1)   ← en el CLIENTE
se envía    = K   (dentro del TLS 1.3 de SAM)
se almacena = Argon2id(K, salt_aleatorio, parámetros del servidor)   ← en el SERVIDOR
```

- Un servidor falso solo obtiene `K` con **su propio** `server_id`, que no sirve en el servidor real. Para obtener la contraseña real tendría que crackear un Argon2 costoso; esto frena el ataque, aunque no lo impide con contraseñas débiles.
- **Defensa contra la suplantación del `server_id`**: el cliente guarda pares (`server_id` → clave de identidad). Si otro servidor afirma tener un `server_id` ya fijado con otra clave (y sin certificado de la CA), el cliente **bloquea** la conexión.
- Los cambios de contraseña, la recuperación y el registro usan la misma derivación.
- El `server_id` no cambia al rotar la clave de identidad, así que las contraseñas siguen funcionando.
- Mejora futura (fuera de la v1): OPAQUE, un PAKE asimétrico estandarizado en el RFC 9807. Con él el servidor nunca obtiene un valor equivalente a la contraseña.

**Certificado del servidor y por qué solo no alcanza**

En el primer arranque, el servidor genera su **certificado de identidad**: el par de claves Ed25519 y un certificado autofirmado que contiene el `server_id` (RS-NET-01). Ese certificado es lo que:

- ancla el `server_id` que usa la derivación de arriba;
- permite fijar la identidad del servidor en el cliente y detectar un MITM o un servidor que reclama un `server_id` ajeno;
- con CA propia (RS-NET-04), permite rotar la clave sin alertas.

**Pero el certificado no frena por sí solo al servidor falso.** El servidor falso también genera el suyo, perfectamente válido *para sí mismo*. El jugador no está siendo interceptado: escribió la dirección equivocada. Es lo mismo que pasa con HTTPS, donde un sitio de phishing tiene su propio certificado válido. Lo que neutraliza el ataque es que la contraseña que recibe el falso no sirve en otro lado (RN-09), y que el cliente avise que ese servidor es desconocido (RN-42).

**RN-42: identidad visible en la AuthScreen**
- El cliente muestra en la AuthScreen una **huella visual** derivada del certificado (un identicon con una frase corta de 3 palabras), siempre igual para el mismo servidor. El jugador se acostumbra a verla, y si un día es distinta, sospecha.
- Si es la **primera vez** que ese equipo ve ese certificado y el servidor muestra la pantalla de *login* (no la de registro), el cliente agrega una advertencia destacada: "Nunca te conectaste a este servidor desde este equipo. Si ya tenías una cuenta, verifica la dirección: podría ser una imitación."
- Ninguna de estas señales la puede falsificar el servidor, porque las genera el cliente a partir del certificado y de sus propios pins.

### 7.2 T-NET-04: TLS 1.3 en toda la conexión

> Reemplaza a la propuesta original RN-19 (cifrado vanilla AES-CFB8 + channel binding), descartada en la revisión.

```
cliente                                     servidor
  TCP ──────────── (o WebSocket vía CDN) ─────────► detector de protocolo (primeros bytes)
  TLS 1.3 ClientHello ─────────────────────────────► TLS 1.3 con el certificado de identidad
  valida el certificado contra su pin (RS-NET-07)
  ◄══════════ todo el protocolo de Minecraft + mensajes SAM, cifrado ══════════►
```

- **Todo** el tráfico (chat, comandos, movimientos, mensajes SAM) va cifrado y con integridad (AEAD), con *forward secrecy* y protección contra replay. Esto cierra T-NET-04, T-NET-05 y T-NET-06.
- Un MITM no puede presentar el certificado fijado del servidor, así que el cliente aborta. En la primera conexión (TOFU) queda el riesgo R-ACC-04.
- Se elimina el handshake X25519 propio de SAM: menos criptografía propia que mantener. La prueba de posesión de la clave del dispositivo se liga a la conexión con el *TLS exporter* o, si la implementación TLS de JDK 21 no lo expone, con el hash del certificado del servidor y un nonce (RS-NET-12).
- El servidor sigue aceptando conexiones vanilla en claro **solo** para el ping de la lista de servidores y para expulsar con el mensaje de descarga.
- Se valida en la fase 0: soporte de certificados Ed25519 en TLS 1.3 con JSSE (alternativa ECDSA P-256), inserción del `SslHandler` en el pipeline del cliente y del servidor de 1.21.1, TLS dentro del WebSocket, y compatibilidad con otros mods de red.

### 7.3 RN-14: origen de los comandos sensibles

| Origen | Comandos de SAM sensibles* | Otros comandos de SAM |
|---|---|---|
| Consola del servidor (stdin) | ✅ | ✅ |
| Admin verificado en el juego | ✅ (salvo los reservados a la consola, como la restauración de RF-ADM-08) | ✅ |
| RCON | ❌ por defecto (configurable) | ✅ |
| Bloques de comando, funciones de datapacks | ❌ siempre | según el permiso |
| Lua ("ejecutar como consola") | ❌ siempre | solo los de la lista blanca del `.env` |

\* `sam admin *`, `sam auth reset|devices|email`, `sam scripts trust`, `sam reload`, `sam audit *`, y vanilla `op`, `deop`, `ban-ip` y `whitelist` cuando SAM está activo.

---

## 8. Riesgos aceptados

| ID | Riesgo | Por qué se acepta |
|---|---|---|
| R-ACC-01 | Robo de nick (primero en registrarse) | Inherente al modo offline; mitigado parcialmente con nicks reservados (RN-06) |
| R-ACC-02 | Se puede saber si un nick está registrado | Inherente al flujo de registro y login; el escaneo masivo se limita por IP |
| R-ACC-03 | Un admin con acceso a la consola tiene control total | Es el modelo de confianza del operador |
| R-ACC-04 | MITM en la primera conexión sin CA | Modelo TOFU, como SSH. La huella se muestra para compararla con la que publica el servidor, y la CA está disponible para quien la necesite |
| R-ACC-05 | El CDN (si se usa) conoce metadatos: IPs, horarios y volumen de tráfico | No puede leer ni alterar el contenido, que va dentro del TLS de SAM; es el precio de la protección anti-DDoS |
| R-ACC-06 | Las cuentas sin 2FA caen si cae su Google o su correo | Así funcionan esos métodos; el 2FA está disponible |
| R-ACC-07 | **Con escritura total en el servidor (S-03), el servidor está comprometido** | Ningún mod puede protegerse de un reemplazo de su propio jar. Hacia los jugadores, la contención es la sandbox. |
| R-ACC-08 | Malware en la PC del jugador | Fuera del alcance (S-04) |

---

## 9. Requerimientos nuevos derivados

> **Aprobados e incorporados** a REQUERIMIENTOS.md v1.1 (la columna "Requerimiento" de allí manda). Prioridad: **P0** bloquea la v1, **P1** debe estar en la v1, **P2** puede ir después. Prioridades y textos actualizados según las decisiones de la sección 10.

| ID | Requerimiento | Amenazas | Prioridad | Fase |
|---|---|---|---|---|
| RN-01 | Bloqueo **exponencial** por cuenta (15 min, 30 min, 1 h…) | T-AUTH-01, T-AUTH-07 | P0 | 1 |
| RN-02 | Aviso por correo tras N intentos fallidos | T-AUTH-01 | P1 | 1 |
| RN-03 | Bloqueo por (cuenta, IP); los dispositivos de confianza quedan exentos del bloqueo global | T-AUTH-02 | P0 | 1 |
| RN-04 | **No expulsar a la sesión existente** hasta que la nueva se autentique | T-AUTH-03 | **P0** | 0 |
| RN-05 | Fail-closed en runtime durante la tarea de autenticación | T-AUTH-04 | **P0** | 0 |
| RN-06 | Nicks reservados por el admin, con código de invitación | T-AUTH-05 | P1 | 2 |
| RN-07 | Validación de nicks configurable, con mínimo no desactivable | T-AUTH-06 | P0 | 1 |
| RN-08 | `totp` sin contraseña deshabilitado para admins por defecto | T-AUTH-07 | P0 | 1 |
| RN-09 | **Derivación de la contraseña ligada al servidor** (7.1) | T-AUTH-09 | **P0** | 0–1 |
| RN-10 | Cambio de correo protegido, con aviso al correo anterior y periodo de espera | T-AUTH-11 | P1 | 1 |
| RN-11 | Los correos no verificados no cuentan ni sirven para recuperar; se quita `VERIFY=off` | T-AUTH-12 | P1 | 1 |
| RN-12 | Límites de concurrencia y de recursos de Argon2 durante el login + carril prioritario para dispositivos conocidos | T-AUTH-14 | P0 | 1 |
| RN-13 | Contexto de LuckPerms `sam:verified` + mixins de nivel de permiso | T-AUTH-15 | P0 | 1 |
| RN-14 | **Origen de los comandos sensibles** (7.3) | T-AUTH-16 | **P0** | 1 |
| RN-15 | Operaciones con secretos solo desde la GUI, nunca por comando | T-AUTH-17 | P0 | 1 |
| RN-16 | Auditoría encadenada por hash, `/sam audit verify` y exportación | T-AUTH-19 | P1 | 1 |
| RN-17 | Aceptar el cambio de clave exige confirmación fuerte; si la cuenta es de un admin, está prohibido | T-NET-02 | P1 | 1 |
| RN-18 | Detección de downgrade en servidores fijados | T-NET-03 | P0 | 0 |
| RN-19 | ~~Cifrado vanilla en offline + channel binding~~ → **TLS 1.3 en toda la conexión** (7.2) | T-NET-04, T-NET-05, T-NET-06 | **P0** | 0 |
| RN-20 | Passphrase de la clave del servidor desde variable de entorno + rotación firmada por el certificado anterior | T-NET-07 | P1 | 1 |
| RN-21 | Límites y fuzzing de los payloads | T-NET-09 | P0 | 1 |
| RN-22 | `state` de OAuth ligado a la conexión y a la cuenta | T-OAU-02 | P0 | 1.5 |
| RN-23 | Librería JWT mantenida, lista blanca de algoritmos, tests negativos | T-OAU-03 | P0 | 1.5 |
| RN-24 | La API de Lua nunca expone objetos Java; revisión obligatoria de la API; fuzzing | T-LUA-01 | **P0** | 3 |
| RN-25 | Contabilidad de memoria en Cobalt y presupuesto por frame | T-LUA-03 | P0 | 0/3 |
| RN-26 | Marca no removible en las GUI de scripts y aviso anti-phishing en la AuthScreen | T-LUA-04 | P0 | 4 |
| RN-27 | Sin eventos para los scripts mientras hay una pantalla protegida abierta | T-LUA-05 | P0 | 4 |
| RN-28 | Lista cerrada de datos legibles por Lua | T-LUA-06 | P0 | 4 |
| RN-29 | Validación estricta de imágenes | T-LUA-07 | P1 | 4 |
| RN-30 | Alerta y auditoría de cambios en el trust store; una clave nueva se activa solo tras confirmarla desde la consola | T-LUA-08, T-LUA-09 | P0 | 3 |
| RN-31 | Verificar la firma en cada carga desde la caché | T-LUA-10 | P0 | 3 |
| RN-32 | Claves de `sam-signer` cifradas con passphrase | T-LUA-11 | P1 | 3 |
| RN-33 | Secretos maestros (`SAM_DATA_KEY`, `SAM_IDENTITY_PASSPHRASE`) solo desde variables de entorno, nunca en el `.env` | T-DAT-01, T-NET-07 | P0 | 1 |
| RN-34 | `.gitignore` automático y rechazo de un `.env` en ubicaciones peligrosas | T-DAT-02 | P0 | 1 |
| RN-35 | Solo SQL parametrizado (lint en CI) | T-DAT-04 | P0 | 1 |
| RN-36 | Validación y escape en los correos | T-DAT-05 | P0 | 1 |
| RN-37 | Exportación y borrado de datos (GDPR) + plantilla de privacidad | T-DAT-07 | P1 | 2 |
| RN-38 | Releases firmadas, con checksums y build reproducible | T-SUP-01 | P0 | 1 |
| RN-39 | Gradle dependency verification y política de dependencias | T-SUP-02 | P0 | 0 |
| RN-40 | Endurecimiento del repositorio y releases solo desde CI con procedencia | T-SUP-03 | P0 | 0 |
| RN-41 | El aviso de actualizaciones solo enlaza al repositorio oficial | T-SUP-04 | P1 | 2 |
| RN-42 | Huella visual del certificado del servidor en la AuthScreen + aviso de "servidor nunca visto" al pedir login | T-AUTH-09, T-NET-01 | P1 | 1 |
| RN-43 | Recuperación desde un dispositivo desconocido: espera configurable (24 h) y aviso a los dispositivos de confianza, que pueden cancelarla | T-AUTH-10 | P1 | 1 |
| RN-44 | Clave del dispositivo en el almacén seguro del sistema operativo, con respaldo en un archivo cifrado | T-AUTH-18 | P1 | 1 |
| RN-45 | Rechazo de contraseñas comunes con una lista offline incluida (chequeo en el cliente). Implementado (H-06): la lista "100k most used passwords" del NCSC del Reino Unido (vía SecLists, MIT), normalizada a minúsculas (~96.000 de 4 a 64 caracteres), más el rechazo de contraseñas que contienen el nick | T-AUTH-01 | P1 | 1 |
| RN-46 | Rechazo de peticiones WebSocket con cabecera `Origin` | T-WS-08 | P1 | 0 |

---

## 10. Decisiones por amenaza

> Registro de la revisión amenaza por amenaza (2026-11-04). **Consolidado** en las secciones 5 a 9 y en REQUERIMIENTOS.md v1.1.

| Amenaza | Decisión | Impacto en el diseño |
|---|---|---|
| T-AUTH-09 Servidor falso | Contraseña ligada al servidor (RN-09) + huella visual y aviso de servidor nunca visto (RN-42) | Se confirma 7.1 |
| T-AUTH-16 Consola falsa | Solo la consola real y admins verificados. RCON bloqueado por defecto (habilitable en el `.env`); bloques de comando, funciones y Lua, nunca | Se confirma 7.3 (RN-14) |
| T-NET-04 Secuestro de sesión | **TLS 1.3 en toda la conexión** desde el primer byte. El certificado que genera el servidor al arrancar es el certificado TLS y el cliente lo valida con pinning. El servidor detecta TLS o texto plano para seguir respondiendo pings y expulsar a clientes vanilla | **Reemplaza** a RN-19 y al cifrado vanilla de 7.2. El handshake X25519 propio de SAM (RS-NET-02) **se elimina**: el canal SAM viaja dentro de TLS y usa el *TLS exporter* (RFC 8446 §7.5) para ligar la clave del dispositivo a la conexión. Resuelve también T-NET-05 y T-NET-06. |
| T-AUTH-03 Nick duplicado | La nueva conexión solo reemplaza a la sesión existente si se autentica completamente | Se confirma RN-04 |
| T-AUTH-15 LuckPerms antes del 2FA | Contexto de LuckPerms `sam:verified=true` + mixins sobre el nivel de OP vanilla | Se confirma RN-13 |
| T-LUA-01 Escape de la sandbox | Defensa en capas: lista blanca, API sin objetos Java, fuzzing, batería de scripts maliciosos en CI, Cobalt con versión fija y revisión de cada función de la API | Se confirma RN-24 |
| T-AUTH-07 Fuerza bruta de TOTP | Bloqueo exponencial por cuenta + `totp` sin contraseña deshabilitado por defecto para admins | Se confirman RN-01 y RN-08 |
| T-AUTH-02 Bloqueo abusivo | Bloqueo fuerte por (cuenta, IP), bloqueo global más suave, y los dispositivos de confianza quedan exentos | Se confirma RN-03 |
| T-AUTH-14 DoS del login | Límites por IP y globales + cola de Argon2 acotada + **carril prioritario para jugadores recurrentes**: quien presenta una clave de dispositivo conocida con un token de sesión válido (una verificación Ed25519, que es barata, sin Argon2) entra a una cola de acceso separada que no se satura con conexiones desconocidas. El nick o la IP solos **no** dan prioridad porque se pueden falsificar | Se amplía RN-12 |
| T-AUTH-17 Credenciales en el chat | Ningún comando acepta secretos: todo se hace desde la GUI de SAM | Se confirma RN-15 |
| T-NET-02 Cambio de certificado | Para aceptar, el jugador escribe el nombre del servidor; si la cuenta es de un admin, no se puede aceptar desde el juego | Se confirma RN-17 |
| T-AUTH-04 Bypass del login | Fail-closed ante cualquier excepción, timeout o estado inesperado + suite de GameTests | Se confirma RN-05 |
| T-AUTH-05 Robo de nick | Nicks reservados por el admin desde la consola; un nick reservado solo se registra con un código de invitación del admin | Se confirma RN-06 (sube a P1) |
| T-AUTH-06 Nicks raros | **Configurable en el `.env`**: `SAM_NICK_VALIDATION=off\|strict\|strict_similarity` (por defecto `strict`). Siempre se rechazan, sin poder desactivarlo, los caracteres de control y los nicks de más de 16 caracteres, porque rompen el protocolo y los logs | Se modifica RN-07 |
| T-AUTH-10 Toma de cuenta por correo | Recuperación desde un dispositivo desconocido: la nueva contraseña se activa tras una espera configurable (24 h por defecto) y se avisa a los dispositivos de confianza, que pueden cancelarla. Desde un dispositivo conocido es inmediata | **RN-43** (nuevo) |
| T-AUTH-11 Cambio de correo | Reingresar la contraseña (+TOTP) y confirmar el correo nuevo con un código; aviso al correo anterior con opción de revertir; durante 7 días el correo nuevo no sirve para recuperar la cuenta | Se confirma RN-10 |
| T-AUTH-12 Ocupar un correo ajeno | Se quita `SAM_REGISTER_EMAIL_VERIFY=off` (quedan `before_play` y `later`); un correo no verificado no cuenta para el límite ni sirve para recuperar, y se libera a las 24 h | Se confirma RN-11 |
| T-AUTH-13 Enumeración | Riesgo aceptado (R-ACC-02) + límite de conexiones por IP contra el escaneo masivo | Ajusta R-ACC-02 |
| T-AUTH-18 Robo de token | La clave del dispositivo se guarda en el almacén seguro del sistema operativo (DPAPI/Credential Manager, Keychain, Secret Service), con respaldo en un archivo cifrado | **RN-44** (nuevo) |
| T-AUTH-01 Contraseñas débiles | Lista offline incluida con las ~100.000 contraseñas más comunes, además de la longitud mínima. **Nota**: con RN-09 el servidor nunca ve la contraseña en claro, así que el chequeo lo hace **el cliente** antes de derivarla. Un cliente modificado puede saltearlo, pero eso solo debilita su propia cuenta | **RN-45** (nuevo) |
| T-AUTH-19 Insider | Log de auditoría encadenado por hash, `/sam audit verify` y exportación | Se confirma RN-16 (sube a P1) |
| T-NET-01 Primera conexión | TOFU + huella publicable: la pantalla de primera conexión muestra la huella (y la frase de 3 palabras de RN-42) para que el jugador la compare con la que publica el servidor; la CA propia sigue disponible | Ajusta R-ACC-04 |
| T-NET-03 Downgrade | Si un servidor fijado responde sin TLS o sin SAM, el cliente aborta siempre; para volver a conectarse hay que borrar el pin a mano | Se confirma RN-18 |
| T-NET-07 Robo de la clave del servidor | La clave privada se guarda cifrada con una passphrase que viene de una **variable de entorno** (no del `.env`) + rotación documentada en la que el certificado nuevo va firmado por el anterior, para que los clientes migren sin alertas | Se amplía RN-20 (sube a P1, fase 1) |
| T-NET-09 Paquetes malformados | Tamaño máximo por tipo de mensaje, parsing estricto, desconexión ante cualquier error y fuzzing con Jazzer en CI | Se confirma RN-21 |
| T-OAU-02 Vinculación forzada | `state` de un solo uso, con vencimiento corto y atado a la conexión TLS y a la cuenta que inició el flujo | Se confirma RN-22 |
| T-OAU-03 Validación del ID token | nimbus-jose-jwt, solo RS256, validación de iss, aud, exp y nonce, JWKS con caché y rotación, tests negativos | Se confirma RN-23 |
| T-OAU-01 Intercepción en loopback | Alcanza con PKCE con canje en el servidor; el servidor local acepta un solo request, verifica el `state` y se cierra | Sin cambios |
| T-OAU-04 Cuenta de Google comprometida | Riesgo aceptado + aviso al correo de la cuenta cuando se entra con Google desde un dispositivo nuevo, con un link para revocar la sesión y desvincular | Ajusta R-ACC-06 |
| T-OAU-06 Filtración del `client_secret` | Enmascarado + documentación de la rotación + `/sam oauth test` | Sin cambios de diseño |
| T-OAU-07 Puerto fijo de Discord | Puerto fijo configurable + PKCE + canje en el servidor; si el puerto está ocupado, se avisa y se sugiere otro método. Se valida en la fase 0 | Se confirma RF-OAUTH-07 |
| T-OAU-05 Consentimiento engañoso | Riesgo aceptado: impacto bajo, y RN-42 ya alerta sobre servidores desconocidos | Sin cambios |
| T-LUA-02 Escape de la sandbox en el servidor | La misma sandbox y la misma defensa en capas que en el cliente: un solo modelo de seguridad | Se amplía RN-24 a ambos lados |
| T-LUA-03 DoS por script | Límite de instrucciones, contabilidad de memoria por script y presupuesto por tick y por frame; el script que se excede se suspende, se reporta a los admins y la GUI vuelve a vanilla | Se confirma RN-25 |
| T-LUA-04 Phishing con la GUI | Marca pequeña no removible "Interfaz del servidor" en toda pantalla creada o reemplazada por scripts + aviso en la AuthScreen | Se confirma RN-26 (sube a P0) |
| T-LUA-05 Keylogging | Con una pantalla protegida abierta, los scripts no reciben ningún evento; fuera de ellas, solo las teclas de sus keybinds y los eventos de sus propias pantallas | Se confirma RN-27 |
| T-LUA-06 Recolección de datos | Lista cerrada de datos de partida (vida, posición, dimensión, inventario visible, tab, escala de la GUI y tamaño de ventana); nada sobre mods, archivos, opciones ni hardware | Se confirma RN-28 (sube a P0) |
| T-LUA-07 Imágenes maliciosas | Solo PNG con tamaño y dimensiones máximas, firmado con el script, decodificado con `NativeImage` y validado antes de la GPU | Se confirma RN-29 |
| T-LUA-08/09 Alteración en el hosting | Todo cambio en las claves de confianza se avisa a los admins (juego y consola) y queda en la auditoría; **una clave nueva no se activa hasta que un admin la confirma desde la consola** | Se amplía RN-30 (sube a P0) |
| T-LUA-10 Caché del cliente | Firma y hash verificados en cada carga desde la caché; si no coinciden, se descarta y se pide de nuevo | Se confirma RN-31 |
| T-LUA-11 Robo de la clave de firma | `sam-signer` guarda la clave cifrada con passphrase; se recomienda un gestor de contraseñas; revocación desde la consola | Se confirma RN-32 |
| T-LUA-12 Interferencia entre scripts | Entornos globales y canales de mensajes separados; comunicación solo por servicios o eventos declarados | Se confirma RS-LUA-06 |
| T-DAT-01 Robo de la base de datos | **La clave de cifrado de datos viene de una variable de entorno real del proceso, no del `.env`** (igual que la passphrase del certificado). Un backup de la base junto con el `.env` no expone los secretos | Se amplía RN-33 (sube a P0). **Excepción a RF-CFG-01**: los dos secretos maestros (la clave de datos y la passphrase de identidad) no se escriben en el `.env` |
| T-DAT-02 Filtración del `.env` | `.gitignore` generado, negativa a arrancar si el `.env` está dentro del mundo o de un datapack, y advertencia de permisos abiertos | Se confirma RN-34 |
| T-DAT-03 Secretos en logs | Ya resuelto con la decisión de T-AUTH-17 (secretos solo desde la GUI) y con el enmascarado | Sin cambios |
| T-DAT-04 Inyección SQL | Solo consultas parametrizadas + regla de análisis estático en CI | Se confirma RN-35 |
| T-DAT-05 Inyección en correos | Validación RFC 5322, escape HTML de las variables de las plantillas, ninguna cabecera construida con datos del jugador | Se confirma RN-36 |
| T-DAT-06 Spam | Límites por cuenta, por IP y tope global por hora; si se alcanza el tope global, se pausan los envíos y se avisa a los admins | Se amplía RS-AUTH-08 |
| T-DAT-07 Datos personales (GDPR) | El jugador exporta sus datos y pide el borrado de su cuenta desde la GUI (con reautenticación); los admins pueden hacerlo desde la consola; plantilla de aviso de privacidad; retención configurable de IPs en la auditoría | Se confirma RN-37 |
| T-SUP-01 Releases falsas | Checksums SHA-256 + firma con Sigstore/cosign + build reproducible; el kick apunta al repositorio oficial por defecto | Se confirma RN-38 |
| T-SUP-02 Dependencias comprometidas | Gradle dependency verification, dependencias mínimas, Dependabot y revisión manual de cada actualización | Se confirma RN-39 |
| T-SUP-03 Cuenta del maintainer comprometida | 2FA obligatorio, rama protegida (solo PR revisados), tags firmados, releases solo desde CI con atestación SLSA | Se confirma RN-40 |
| T-NET-05 / T-NET-06 | Resueltas con la decisión de usar TLS 1.3 (integridad AEAD y anti-replay nativos) | Se cierran |
| T-AUTH-08 Reutilización de un código TOTP | Anti-replay + ventana de ±1 paso (estándar) | Sin cambios |
| T-NET-08 Cliente que finge tener SAM | Riesgo aceptado: no hay atestación confiable posible; todas las decisiones de seguridad se toman en el servidor | Se confirma RS-AUTH-04 |
| T-SUP-04 Aviso de actualización falso | HTTPS con validación de certificado y solo links hacia el repositorio oficial; nunca se descarga nada | Se confirma RN-41 |

| T-WS-01 a T-WS-07 | Aceptadas las mitigaciones de TRANSPORTE_WEBSOCKET.md (decisión de diseño ya tomada) | Incorporadas como RF-WS y RS-WS |
| T-WS-08 WebSocket desde un navegador | Detectada en la consolidación: se rechazan las peticiones con cabecera `Origin` | **RN-46** (nuevo), RS-WS-05 |

**Revisión completa y consolidada.**

## 11. Verificación

| Área | Cómo se verifica |
|---|---|
| Bypass del login (T-AUTH-04, RN-04, RN-05) | GameTests: desconexiones, excepciones, `/reload` y logins duplicados a mitad del flujo |
| Criptografía y TLS (RN-09, RN-19, RS-NET, RS-WS) | Vectores de prueba conocidos, tests de MITM simulado (proxy en la suite de tests) y especificación en `PROTOCOLO.md` |
| Sandbox (RN-24, RS-LUA-02c) | Batería de scripts maliciosos en CI, en servidor y cliente; fuzzing de la API |
| Comandos sensibles (RN-14) | Tests que ejecutan cada comando sensible desde cada origen de la tabla 7.3 |
| Parsers (RN-21, RN-29) | Fuzzing de payloads e imágenes (Jazzer) |
| Dependencias (RN-39) | Gradle verification + Dependabot en CI |
| Revisión antes de cada release (RNF-04) | Checklist basado en la sección 9; este documento se actualiza ante cualquier cambio de protocolo o de API |
