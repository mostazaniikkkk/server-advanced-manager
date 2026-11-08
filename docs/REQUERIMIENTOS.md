# Server Advanced Manager (SAM): planteamiento de requerimientos

> Estado: **v1.1**, 2026-11-04. Alcance cerrado. Incorpora las decisiones de la revisión de amenazas ([AMENAZAS.md](AMENAZAS.md), sección 10) y el transporte WebSocket ([TRANSPORTE_WEBSOCKET.md](TRANSPORTE_WEBSOCKET.md)). Licencia: **CC0 1.0** (dominio público).
> Las referencias `RN-xx` y `T-xxx` apuntan a AMENAZAS.md.

## 1. Visión

SAM es un mod nativo de **Fabric** que reemplaza a EssentialsX (plugin de Bukkit/Paper) en servidores Fabric. Además de los comandos de administración y de utilidad, aporta:

1. **Login reforzado**, con una pantalla de autenticación dedicada en el cliente y segundo factor (TOTP, compatible con Google Authenticator, Aegis, etc.).
2. **Conexión cifrada de extremo a extremo con TLS 1.3**, con la identidad del servidor fijada en el cliente, y opción de transporte por **WebSocket** para operar detrás de Cloudflare u otro CDN.
3. **Scripting en Lua orientado a GUI**: los scripts **firmados** se distribuyen dentro de datapacks. Sirven principalmente para **construir y controlar interfaces en el cliente** (HUD, menús, pantallas), con lógica de apoyo en el servidor. Funcionalidades como la economía se implementan como conectores en Lua.

**Fuera de alcance**: registrar ítems, bloques, entidades u otro contenido nuevo. Eso lo cubrirá otro mod, **"Datapack Plus"**.

## 2. Decisiones tomadas

| Tema | Decisión |
|---|---|
| Versión | **Solo Minecraft 1.21.1** (Fabric Loader y Fabric API, Java 21), al menos hasta que salga "The Sift". No se mantienen varias versiones en paralelo. |
| Distribución | **Dos jars**: `sam-server.jar` y `sam-client.jar`. El código compartido (`sam-common`) va embebido en ambos (jar-in-jar o shading). |
| Distribución del cliente | **GitHub Releases**, con releases firmadas (RNF-06). El servidor revisa si hay versiones nuevas y **avisa a los admins** (RF-UPD). |
| Clientes sin el mod | **Kick** con un mensaje que indica dónde descargar el cliente (por defecto, el repositorio oficial) |
| Modo del servidor | **Offline** como objetivo principal. El modo online queda fuera de la v1. |
| Público objetivo | **Open source y genérico**: cualquier operador debe poder instalarlo y configurarlo sin tocar código, con valores por defecto seguros y documentación para admins. |
| Transporte | **TLS 1.3 en toda la conexión**, desde el primer byte, con el certificado que genera el servidor (sección 6). Opcionalmente, **WebSocket** en el mismo puerto para usar Cloudflare (6.4). |
| Proxies | Los **CDN** (Cloudflare) se soportan vía WebSocket. Los proxies de Minecraft (Velocity, BungeeCord) y las redes de varios servidores quedan fuera de alcance; la arquitectura no debe impedirlos a futuro. |
| Registro | **Siempre con usuario/contraseña + correo (obligatorio, no configurable).** Google y TOTP se agregan después a una cuenta existente; nunca se registra una cuenta desde cero con ellos. |
| Métodos de login | `password` (el más débil y el que viene por defecto), `google` y, opcionalmente, `discord` (5.0); el 2FA es un segundo paso sobre cualquiera de ellos. El **administrador** define en el `.env` cuáles están disponibles y si el 2FA se exige para cada grupo de permisos (8.2). |
| 2FA | Opcional para jugadores y **obligatorio para administradores** (5.4) |
| Google ↔ MC | **1 cuenta de Google = 1 cuenta de Minecraft** por servidor (fijo) |
| Cambio de nick de un admin | **Pierde el rol.** Solo se restaura manualmente desde la **consola del servidor** (RF-ADM-08). |
| Economía | **Fuera del alcance nativo.** Se puede implementar con conectores Lua (RF-LUA-04). |
| Lua | **Principalmente control de GUI.** Ítems, bloques y entidades → mod "Datapack Plus" (fuera de alcance). |
| Autor de scripts | **El operador del servidor** escribe los scripts de cliente y de servidor. No hay scripts de terceros en el modelo de confianza. |
| Rechazo de scripts | Lo define la configuración de SAM (RS-LUA-05) |
| Configuración | Archivo **`.env` solo en el servidor** (sección 8), **excepto los dos secretos maestros** (la clave de cifrado de datos y la passphrase del certificado), que vienen de variables de entorno reales del proceso (RF-CFG-08) |
| Licencia | **CC0 1.0 Universal** (dominio público). Las dependencias embebidas en los jars conservan sus propias licencias (BouncyCastle: MIT; Netty: Apache 2.0) |

## 3. Arquitectura general

| Componente | Lado | Responsabilidad |
|---|---|---|
| `sam-common` | ambos (embebido) | Protocolo de mensajes SAM, transporte (TLS, WebSocket), verificación de firmas, modelos y API de scripting compartida |
| `sam-server` | servidor dedicado | Comandos, permisos, persistencia, autenticación, runtime de Lua (servidor), distribución de scripts de cliente y único dueño del pipeline de red del servidor |
| `sam-client` | cliente | Pantalla de login y 2FA, *pinning* de la identidad del servidor, derivación de la contraseña, runtime de Lua (cliente) y consentimiento |
| `sam-signer` | CLI aparte | Generación de claves, firma de scripts y emisión de certificados, todo **fuera del servidor** |

- Permisos: **SAM trae su propio sistema de grupos y nodos** y se registra como proveedor de `fabric-permissions-api` (Lucko), así que los demás mods también le preguntan a SAM. Si está instalado LuckPerms, SAM le cede el control. Lo indefinido cae en el nivel de OP. Detalle en `docs/PERMISOS.md` (RF-PERM).
- Build: Gradle multi-proyecto con Fabric Loom y mappings oficiales de Mojang.

## 4. Módulo Essentials (paridad con EssentialsX)

**Se implementa como plugins Lua** (datapacks firmados que entrega el servidor, uno por función), no como código nativo, salvo que el dueño del proyecto autorice lo nativo para una pieza (hasta ahora, solo los permisos, 4.1). Lo nativo se limita a las capacidades de la API Lua que esos plugins necesitan. Cada plugin documenta su diseño en `docs/plugins/`. Cada comando tiene un nodo de permiso `sam.command.<nombre>` y es configurable (se puede activar o desactivar y tiene cooldown y warmup).

| ID | Grupo | Funcionalidades | Prioridad |
|---|---|---|---|
| RF-ESS-01 | Teletransporte | `/tpa`, `/tpahere`, `/tpaccept`, `/tpdeny`, `/tp*` de admin, `/back`, `/top`, warmup que se cancela al moverse o recibir daño | Alta |
| RF-ESS-02 | Homes | `/sethome`, `/home`, `/delhome`, `/homes`, límite de homes por permiso | Alta |
| RF-ESS-03 | Warps y spawn | `/warp`, `/setwarp`, `/delwarp`, `/spawn`, `/setspawn`, spawn al primer ingreso | Alta |
| RF-ESS-04 | Moderación | `/ban`, `/tempban`, `/ipban`, `/mute`, `/tempmute`, `/kick`, `/warn`, `/jail`, historial de sanciones. `/ipban` usa la IP real resuelta (6.4) | Alta |
| RF-ESS-05 | Mensajería | `/msg`, `/r`, `/ignore`, `/socialspy`, `/broadcast`, `/mail` | Media |
| RF-ESS-06 | Jugador | `/nick`, `/afk` con auto-AFK, `/seen`, `/whois`, `/god`, `/fly`, `/heal`, `/feed`, `/gamemode`, `/speed`, `/vanish`, `/invsee`, `/enderchest` | Media |
| RF-ESS-07 | Kits | Kits definidos en configuración, con cooldown y permiso por kit | Media |
| RF-ESS-08 | Chat | Formato con placeholders, colores por permiso, MOTD y reglas | Media |
| RF-ESS-09 | Utilidades | `/sam reload`, `/sam info`, importador de datos de EssentialsX (userdata, warps, homes) | Media |

### 4.1 Permisos (RF-PERM, detalle en `docs/PERMISOS.md`)

| ID | Requisito |
|---|---|
| RF-PERM-01 | Grupos con peso y herencia, nodos con comodín (`a.*`, `*`) y negación, metas de texto (límites, prefijos) y vencimientos para nodos, metas y pertenencia a grupos. El grupo `default` aplica a todos. |
| RF-PERM-02 | Resolución determinista: primero el jugador y después sus grupos de mayor a menor peso; en cada fuente gana la entrada más específica; la primera fuente con coincidencia decide; si ninguna, indefinido (el que pregunta usa su valor por defecto). |
| RF-PERM-03 | Proveedor de `fabric-permissions-api` (permisos y metas). Si está LuckPerms, SAM le cede el control y lo avisa. |
| RF-PERM-04 | Archivo `config/sam/permissions.json`, editable a mano, con lectura estricta; `/sam perms reload`. Inválido al arrancar: ningún permiso propio (OP como vanilla). Inválido al recargar: se mantiene lo anterior. |
| RF-PERM-05 | Comandos `/sam perms` (grupos, usuarios, metas, check), sensibles según RS-ADM-01 y auditados (RF-ADM-06). |
| RF-PERM-06 | Nodos que exigen sesión verificada (2FA completado en esa sesión): así se dan los permisos de staff (RF-ADM-04). |
| RF-PERM-07 | Lua (capacidad `permissions`): `sam.has` y `sam.meta`, solo lectura; los comandos de scripts pueden exigir un nodo. |

## 5. Módulo de autenticación

### 5.0 Métodos de login

| Método (`.env`) | Descripción | Nivel de seguridad | Por defecto |
|---|---|---|---|
| `password` | Usuario y contraseña | 1 (el más débil) | **Sí**: habilitado en una instalación limpia |
| `google` | "Entrar con Google" (OAuth/OIDC) | 2 | No (requiere configurar credenciales) |
| `discord` | "Entrar con Discord" (OAuth 2.0), opcional | 2 | No (requiere configurar credenciales) |

**El 2FA (TOTP) no es un método más: refuerza a todos** (decisión del 2026-11-07). Si la cuenta lo tiene activo, después de la contraseña **o** de Google se pide el código como segundo paso, siempre. No existe entrar solo con el código. Los códigos de respaldo valen en lugar del código.

- El administrador decide en el `.env` qué métodos están **disponibles** y si el 2FA se **exige** para cada grupo (8.2).
- **Toda cuenta tiene siempre usuario/contraseña**, porque el registro pasa por ahí (RF-AUTH-01). TOTP y Google se **vinculan** después. Si el admin deshabilita Google, los jugadores afectados vuelven a `password` sin quedar fuera.
- Con el 2FA activo, toda operación sensible de la cuenta (cambiar el correo, desvincular Google, desactivar el 2FA) pide la contraseña **y** el código.
- `google` sin 2FA es suficiente para jugadores normales. Los admins siempre necesitan 2FA.

### 5.1 Requerimientos funcionales

| ID | Requerimiento |
|---|---|
| RF-AUTH-01 | **Registro** en la AuthScreen la primera vez que el jugador entra: usuario (su nick), contraseña y **correo electrónico**. Es el único camino para crear una cuenta. La contraseña cumple la longitud mínima del `.env` y no puede estar en la **lista de contraseñas comunes** incluida en el mod (~100.000); como el servidor nunca ve la contraseña en claro (RS-AUTH-01), ese chequeo lo hace el cliente (RN-45). |
| RF-AUTH-01b | **Verificación del correo** con un código enviado por mail. Modos: `before_play` (hay que verificar para entrar al mundo) o `later`. **No existe la opción de no verificar.** Un correo no verificado no cuenta para el límite de cuentas por correo (por defecto 1) ni sirve para recuperar la cuenta, y se libera si no se verifica en 24 h (RN-11). |
| RF-AUTH-01c | **Recuperación por correo**: "¿Olvidaste tu contraseña?" envía un código de un solo uso (expiración corta, rate limit) al correo verificado. Desde un **dispositivo conocido**, la nueva contraseña se activa de inmediato; desde uno **desconocido**, se activa tras una espera configurable (24 h por defecto) y se avisa a los dispositivos de confianza, que pueden cancelarla (RN-43). Si la cuenta tiene TOTP o es admin, **el TOTP sigue siendo obligatorio** después de la recuperación. |
| RF-AUTH-01d | **Gestión de correos por el admin**: configuración SMTP en el `.env`; plantillas editables (`config/sam/mail/*.html` y `.txt`) para verificación, recuperación, cambio de contraseña, cambio de correo, intentos fallidos y login desde un dispositivo nuevo (los avisos se pueden desactivar); comandos `/sam mail test|status` y `/sam auth email <jugador>` para ver el correo (enmascarado) de una cuenta. |
| RF-AUTH-01e | **Nicks**: la validación es configurable (`SAM_NICK_VALIDATION=off\|strict\|strict_similarity`, por defecto `strict` = `[A-Za-z0-9_]{3,16}` sin distinguir mayúsculas; `strict_similarity` además bloquea nicks parecidos a los de admins). Siempre, sin poder desactivarlo, se rechazan los caracteres de control y los nicks de más de 16 caracteres (RN-07). |
| RF-AUTH-01f | **Nicks reservados**: el admin reserva nicks desde la consola; un nick reservado solo se registra con un código de invitación que genera el admin (RN-06). |
| RF-AUTH-02 | Login obligatorio antes de entrar al mundo. El jugador no llega a la fase *play* hasta autenticarse. **Fail-closed**: cualquier excepción, timeout o estado inesperado durante la autenticación desconecta al jugador (RN-05). |
| RF-AUTH-03 | **Pantalla dedicada en el cliente** (Screen propia) que se muestra durante la fase de *configuration*. Muestra la **huella visual** del certificado del servidor y, si es la primera vez que el equipo ve ese servidor y se pide login, un aviso de posible imitación (RN-42). Recuerda que SAM nunca pide la contraseña de Google dentro del juego (RN-26). |
| RF-AUTH-04 | **2FA con TOTP** (RFC 6238): se activa desde "Opciones de cuenta" (con la contraseña) mostrando un código QR y la clave en texto, y se confirma con un primer código; se entregan 10 códigos de respaldo de un solo uso, que se muestran una sola vez. Ventana de ±1 paso y un código ya usado no se acepta de nuevo. Es un **segundo paso** después de la contraseña o de Google (5.0). Desactivarlo pide contraseña y código. Es opcional para jugadores y obligatorio para administradores (5.4). Sin `SAM_DATA_KEY` no se puede activar (RS-AUTH-03). |
| RF-AUTH-05 | "Recordar sesión": un token ligado al UUID y a la clave de dispositivo del cliente (RS-NET-07), con TTL configurable por política. Se invalida al cambiar la contraseña o desde un comando de admin. La clave del dispositivo se guarda en el **almacén seguro del sistema operativo** (DPAPI/Credential Manager, Keychain, Secret Service), con respaldo en un archivo cifrado (RN-44). |
| RF-AUTH-06 | **Protección contra fuerza bruta** (RN-01, RN-03): bloqueo **exponencial** (15 min, 30 min, 1 h…); el bloqueo fuerte aplica al par (cuenta, IP) y el global de la cuenta es más suave; los dispositivos de confianza quedan exentos del bloqueo global. Tras N fallos se avisa por correo (RN-02). Timeout para completar el login. |
| RF-AUTH-06a | **Cómo se cuenta** (H-03 de `docs/HARDENING.md`): cada `SAM_AUTH_MAX_ATTEMPTS` fallos del par (cuenta, IP) lo bloquean `SAM_AUTH_LOCKOUT_BASE`, y cada bloqueo repetido dobla el anterior (tope 24 h). El bloqueo global de la cuenta es más suave: salta con 4 veces ese número de fallos desde cualquier IP. Los contadores sobreviven a la reconexión; un login correcto limpia los del par y los de la cuenta, y 24 h sin fallos olvidan los niveles. Durante un bloqueo la conexión se rechaza **antes** de Argon2 con `SAM-K004` y los minutos que faltan. Logins pendientes: `SAM_AUTH_PENDING_PER_IP` por IP y `SAM_AUTH_PENDING_GLOBAL` en total; al pasarse, `SAM-K005`. La cola de Argon2 tiene tamaño fijo: si se llena, `SAM-K005`. Los contadores viven en memoria (un reinicio los borra). |
| RF-AUTH-06b | **Protección del login contra DoS** (RN-12): límites de logins pendientes por IP y globales; cola de Argon2 de tamaño fijo (si se llena, se rechaza la conexión); parámetros de Argon2 que acotan la RAM; verificaciones baratas antes de hashear. **Carril prioritario**: quien presenta una clave de dispositivo conocida con un token de sesión válido (una verificación Ed25519, sin Argon2) entra por una cola separada que no se satura con conexiones desconocidas. El nick o la IP solos no dan prioridad. |
| RF-AUTH-06c | **Login duplicado** (RN-04): si entra una conexión con un nick que ya está conectado, la sesión existente **no se expulsa**. La nueva queda en la AuthScreen y solo reemplaza a la anterior si se autentica completamente. |
| RF-AUTH-07 | **Gestión de la cuenta desde la GUI**: cambio de contraseña, cambio de correo, enrolamiento y revocación de TOTP, vinculación de Google y Discord, dispositivos y sesiones. **Ningún comando acepta secretos como argumento**: los comandos solo abren la pantalla de cuenta de SAM (RN-15). Un admin puede resetear desde la consola (`sam auth reset <jugador>`): **borra la cuenta** (contraseña, correo, 2FA y Google); al volver a entrar, el jugador la crea de nuevo como la primera vez. Si está conectado, se lo expulsa. Solo desde la consola real (RF-ADM-07) y queda en la auditoría. |
| RF-AUTH-07b | **Cambio de correo** (RN-10): exige reingresar la contraseña (y el TOTP si está activo), confirmar el correo nuevo con un código y avisar al anterior con opción de revertir. Durante 7 días el correo nuevo no sirve para recuperar la cuenta. **Nunca exige acceso al correo anterior**: el caso típico es que el jugador lo perdió; al anterior solo le llega un aviso. Mientras no exista el envío de correos (SMTP), el cambio se hace solo con la contraseña y el correo nuevo queda sin verificar. |
| RF-AUTH-07d | **Opciones de cuenta en el inventario**: en un servidor con SAM, el inventario muestra un botón en la esquina inferior derecha de la pantalla con una tuerca y la cara de la skin del jugador; su tooltip dice "Opciones de cuenta" y abre la GUI de cuenta (RF-AUTH-07). Primera versión: correo actual (enmascarado), cambio de correo (RF-AUTH-07b) y vincular o desvincular Google (RF-OAUTH-02). |
| RF-AUTH-07c | **Datos personales** (RN-37): el jugador exporta sus datos y pide el borrado de su cuenta desde la GUI (con reautenticación); los admins pueden hacerlo desde la consola. Se incluye una plantilla de aviso de privacidad para el operador y la retención de IPs en la auditoría es configurable. |
| RF-AUTH-08 | **Auditoría**: intentos exitosos y fallidos con IP real, timestamp y motivo, consultable por un admin. El log está **encadenado por hash** (cada entrada incluye el hash de la anterior), se verifica con `/sam audit verify` y se puede exportar (RN-16). |
| RF-AUTH-08a | **Formato** (H-08 de `docs/HARDENING.md`): `config/sam/audit.jsonl`, solo del dueño, una línea JSON por evento con `seq` (desde 1), `t` (UTC, ISO-8601), `type`, `actor`, `ip`, `detail`, `prev` (el `hash` de la línea anterior; 64 ceros en la primera) y al final `hash` = SHA-256 en hex de la línea hasta antes de `,"hash"`. Comandos sensibles (RS-ADM-01): `/sam audit verify` (recorre la cadena y dice la primera línea rota), `/sam audit last [n]` (las últimas n, hasta 20) y `/sam audit export` (copia solo del dueño en `config/sam/audit-export-<fecha>.jsonl`). Al arrancar, el log del servidor muestra la cabeza de la cadena (`seq` y `hash`) como ancla externa: una cadena truncada al final se detecta comparando con un ancla anterior. Los eventos también siguen yendo al log del servidor con `[auditoría]`. |
| RF-AUTH-09 | Modo offline: SAM es la única autoridad de autenticación. El soporte para servidores en modo online queda fuera de la v1. |
| RF-AUTH-10 | **Un cliente sin `sam-client`** (llega sin TLS o no completa el handshake de SAM) **es expulsado** con un mensaje configurable. También se expulsa si la versión de protocolo de SAM es incompatible. Un cliente que finge tener SAM no gana nada: toda decisión de seguridad se toma en el servidor (RS-AUTH-04). |

### 5.2 Requerimientos de seguridad

| ID | Requerimiento |
|---|---|
| RS-AUTH-01 | **Contraseña ligada al servidor** (RN-09): el cliente nunca envía la contraseña real. Envía `K = Argon2id(contraseña, SHA-256("SAM-pw-v1" ‖ server_id ‖ usuario))`, calculado en el cliente con el `server_id` del certificado del servidor. El servidor guarda `Argon2id(K, salt aleatorio)`. Lo que recibe un servidor falso no sirve en el real. Ni la contraseña ni `K` se escriben en logs. Detalle en AMENAZAS.md 7.1. |
| RS-AUTH-02 | Las credenciales solo viajan dentro del TLS 1.3 de SAM (sección 6). |
| RS-AUTH-03 | Los secretos TOTP se cifran en reposo con la **clave de cifrado de datos**, que viene de una variable de entorno y no del `.env` (RF-CFG-08). |
| RS-AUTH-04 | Que el mod cliente esté presente **no es prueba de confianza**: un cliente modificado puede falsificar cualquier mensaje, así que toda validación ocurre en el servidor. |
| RS-AUTH-05 | Comparaciones en tiempo constante y mensajes de error genéricos. La existencia de un nick es visible por el flujo de registro y login (riesgo aceptado); el escaneo masivo se limita con el límite de conexiones por IP. |
| RS-AUTH-06 | La cuenta queda ligada al nick normalizado (sin distinguir mayúsculas y minúsculas) según RF-AUTH-01e. |
| RS-AUTH-07 | Los correos se almacenan **cifrados en reposo** (con la clave de RS-AUTH-03), con un hash aparte para comprobar que no se repitan, y nunca aparecen completos en logs ni en comandos (`j***@g***.com`). Las respuestas del flujo de recuperación son idénticas exista o no la cuenta. |
| RS-AUTH-08 | Los envíos de correo se hacen fuera del hilo principal, con límite por cuenta, por IP y un **tope global por hora**; si se alcanza el tope global, se pausan los envíos y se avisa a los admins. |
| RS-AUTH-09 | Correos seguros (RN-36): validación de direcciones según RFC 5322 (sin saltos de línea ni caracteres de control), escape HTML de todas las variables en las plantillas y ninguna cabecera construida con datos del jugador. |

### 5.3 Flujo de conexión

```
TCP (o WebSocket, 6.4)
 └─ TLS 1.3 de SAM: el cliente valida el certificado del servidor contra su pin (6.2)
     └─ handshake → login (vanilla) → configuration:
          1. SAM_HELLO     versión de protocolo; sin SAM → kick
          2. SAM_DEVICE    el cliente prueba la posesión de su clave de dispositivo (RS-NET-07)
          3. SAM_AUTH      AuthScreen: [contraseña] / [Entrar con Google] / token de sesión
                           → segundo paso: código 2FA si la cuenta lo tiene activo o es admin
          4. SAM_SCRIPTS   scripts de cliente firmados + consentimiento (7.3)
          → play
```

Se valida en la fase 0: los timeouts de keep-alive mientras el jugador escribe o completa OAuth en el navegador, y el comportamiento al cancelar la pantalla.

### 5.4 Administradores y 2FA obligatorio

| ID | Requerimiento |
|---|---|
| RF-ADM-01 | **Lista de administradores** en dos niveles: (a) **estática**, en `SAM_ADMINS` del `.env`, que no se puede quitar desde el juego; (b) **dinámica**, en la base de datos, gestionada con `/sam admin add|remove|list` (origen permitido según RS-ADM-01). |
| RF-ADM-02 | Además de la lista, se considera admin a quien tenga nivel de OP ≥ N (configurable, por defecto 2) o el permiso `sam.admin`. |
| RF-ADM-03 | Un admin **no puede entrar** sin TOTP. Si todavía no lo tiene configurado, se lo obliga a enrolarlo en la AuthScreen antes de entrar al mundo. |
| RF-ADM-03a | **Cómo se obliga** (H-02 de `docs/HARDENING.md`): es admin quien está en `ops.json` con nivel ≥ `SAM_ADMIN_OP_LEVEL` (2 por defecto). Si un admin sin TOTP pasa la contraseña (o Google), el servidor responde `NEED_ENROLL` y manda `sam:totp_enroll` (el QR y los 10 códigos de respaldo) por la fase de configuración; el cliente muestra la pantalla "Activar 2FA" con el aviso de que es obligatorio para entrar, y el primer código válido (`sam:totp_confirm`) activa el 2FA y completa el login con la sesión verificada. Los códigos malos cuentan para el bloqueo (RF-AUTH-06a). Salir de esa pantalla desconecta. Si el servidor no tiene `SAM_DATA_KEY` (no puede guardar el 2FA), el admin entra sin poderes de OP (RF-ADM-04) y queda en la auditoría. |
| RF-ADM-04 | **Privilegios condicionados** (RN-13): los permisos de OP y admin solo se activan cuando el 2FA se completó en esa sesión. SAM aplica mixins sobre el nivel de permiso vanilla y registra en LuckPerms el contexto **`sam:verified=true`**; la documentación indica asignar los permisos de staff solo bajo ese contexto. |
| RF-ADM-05 | El "recordar sesión" de los admins tiene un TTL más corto (configurable) y siempre exige TOTP al entrar desde un dispositivo nuevo. |
| RF-ADM-05a | **Caducidad de la sesión en juego** (H-04 de `docs/HARDENING.md`): la sesión verificada con 2FA de un admin dura `SAM_POLICY_ADMIN_SESSION_TTL` (12 h por defecto) desde el login; al vencer, sus poderes de OP y de admin se apagan (RF-ADM-04), se le avisa una vez y queda en la auditoría; para recuperarlos vuelve a entrar. Cualquier sesión de juego dura como mucho `SAM_POLICY_DEFAULT_SESSION_TTL` (7 d): al vencer se lo desconecta con un aviso para que vuelva a iniciar sesión. Formato de las duraciones: número y `s`, `m`, `h` o `d`. |
| RF-ADM-06 | Auditoría reforzada: cada login de admin, cada cambio en la lista de admins y cada uso de comandos sensibles (ban, op, gamemode, permisos y otros configurables). |
| RF-ADM-06a | **Implementación** (H-09 de `docs/HARDENING.md`): cada comando cuya raíz está en `SAM_AUDIT_COMMANDS` (también tras `execute ... run`) va a la auditoría con quién lo ejecutó y el texto completo, sea de un jugador, la consola o RCON. Cada cambio de `/sam perms` guarda el JSON de la entidad antes y después ("grupo x: antes -> después"). |
| RF-ADM-07 | Recuperación: los códigos de respaldo son obligatorios al enrolar. Un admin que pierde todo solo puede recuperarse desde la **consola del servidor** (`sam auth reset <jugador>`). |
| RF-ADM-08 | **Cambio de nick**: un admin que se cambia el nick **pierde el rol**, sin migración automática. Para restaurarlo hay que ejecutar `sam admin add <nuevo_nick>` **desde la consola del servidor** o editar `SAM_ADMINS`. La auditoría registra los intentos de entrada con nicks parecidos al de un admin. |

| ID | Seguridad |
|---|---|
| RS-ADM-01 | **Origen de los comandos sensibles** (RN-14). Comandos sensibles: `sam admin *`, `sam auth reset\|devices\|email`, `sam scripts *` (H-05), `sam perms *`, `sam reload`, `sam audit *` y, con SAM activo, los vanilla `op`, `deop`, `ban-ip` y `whitelist`. Se aceptan desde la **consola real del servidor (stdin)** y desde admins verificados en el juego (salvo los reservados a la consola, como RF-ADM-07 y RF-ADM-08). **RCON**: bloqueado por defecto, habilitable con `SAM_RCON_SENSITIVE_COMMANDS=true`. **Bloques de comando, funciones de datapacks y Lua: nunca.** |

### 5.5 "Entrar con Google" y Discord (OAuth 2.0 / OpenID Connect)

**Modelo**: como el mod es open source, **cada operador registra su propio cliente OAuth** en Google Cloud (y en Discord, si lo usa) y pone el `client_id` y el `client_secret` en el `.env`. El mod no trae credenciales incluidas. Si un proveedor no está habilitado o no tiene credenciales, su botón no aparece.

Flujo: **Authorization Code + PKCE con redirect a loopback** (RFC 8252), con el **canje del código hecho por el servidor**:

```
1. Jugador pulsa "Entrar con Google" en la AuthScreen
2. Servidor genera state + nonce + PKCE (code_verifier queda SOLO en el servidor)
   y envía la URL de autorización por el TLS de SAM
3. Cliente abre un servidor HTTP efímero en 127.0.0.1:<puerto aleatorio>
   y abre el navegador del sistema con la URL
4. Google redirige a 127.0.0.1 con el code; el cliente verifica el state
   y reenvía el code al servidor
5. Servidor canjea code + code_verifier en Google y valida el ID token:
   firma (JWKS de Google), iss, aud = su client_id, exp, nonce
6. Servidor asocia el claim `sub` de Google a la cuenta → autenticado
```

| ID | Requerimiento |
|---|---|
| RF-OAUTH-01 | **No hay registro con Google.** La cuenta se crea siempre con usuario/contraseña + correo (RF-AUTH-01). |
| RF-OAUTH-02 | **Vinculación** desde la GUI de cuenta; se puede desvincular cuando se quiera, porque la contraseña siempre existe. |
| RF-OAUTH-03 | Una cuenta de Google (o de Discord) se vincula a **una sola** cuenta de Minecraft por servidor, y una cuenta de Minecraft tiene como máximo una cuenta vinculada por proveedor. Regla fija. |
| RF-OAUTH-04 | Login con Google para un admin: **igual exige TOTP de SAM**. |
| RF-OAUTH-05 | Fallback con **Device Authorization Grant** (RFC 8628) para Google: código y QR para aprobar desde el celular. |
| RF-OAUTH-06 | **Proveedores genéricos** con una interfaz común. En la v1: **Google** (OIDC) y **Discord** (opcional; OAuth 2.0 sin OIDC, identidad desde `/users/@me` con el scope `identify`). |
| RF-OAUTH-07 | **Discord**: puerto loopback **fijo** y configurable (Discord exige el redirect exacto y no tiene device flow), con PKCE y canje en el servidor. Si el puerto está ocupado, se avisa y se sugiere otro método. Se valida en la fase 0. |
| RF-OAUTH-08 | Un login con Google o Discord desde un **dispositivo nuevo** envía un aviso al correo de la cuenta, con un link para revocar la sesión y desvincular. |
| RF-OAUTH-09 | `/sam oauth test` verifica las credenciales configuradas; la documentación explica cómo rotar el `client_secret`. |

| ID | Seguridad y privacidad |
|---|---|
| RS-OAUTH-01 | Solo se piden los scopes `openid` (Google) e `identify` (Discord); nunca scopes de acceso a datos. |
| RS-OAUTH-02 | De Google o Discord se almacena solo el `sub` (identificador estable), nunca su email. |
| RS-OAUTH-03 | `state` y `nonce` son de un solo uso, expiran en pocos minutos y el `state` queda **atado a la conexión TLS y a la cuenta** que inició el flujo (RN-22). El servidor HTTP loopback del cliente acepta un solo request y se cierra. |
| RS-OAUTH-04 | Los `client_secret` nunca se envían al cliente y se enmascaran en logs y en `/sam info`. |
| RS-OAUTH-05 | Validación del ID token con **nimbus-jose-jwt**: solo RS256, iss, aud, exp y nonce obligatorios, JWKS con caché y rotación, y tests negativos para cada ataque conocido (`alg=none`, `aud` ajeno, token vencido…) (RN-23). |
| RS-OAUTH-06 | La documentación para operadores explica cómo crear el cliente OAuth, la pantalla de consentimiento y su publicación (en modo "Testing" Google limita a 100 usuarios). |

## 6. Comunicación segura

### 6.1 Certificado del servidor

| ID | Requerimiento |
|---|---|
| RS-NET-01 | En el primer arranque, el servidor genera su **certificado de identidad**: un certificado X.509 autofirmado con una clave **Ed25519** (alternativa ECDSA P-256 si la fase 0 muestra problemas de soporte en TLS) que incluye un **`server_id`** aleatorio de 128 bits y estable. También se puede importar uno existente. |
| RS-NET-02 | La clave privada se guarda cifrada con una **passphrase que viene de una variable de entorno** (`SAM_IDENTITY_PASSPHRASE`), nunca del `.env` (RF-CFG-08), y con permisos de archivo restringidos (RN-20). |
| RS-NET-03 | **Rotación**: el certificado nuevo se firma con el anterior, así los clientes que tenían fijado el viejo migran sin alertas. El `server_id` no cambia al rotar. Si la clave vieja está comprometida, se usa la CA propia (RS-NET-04) o se acepta que los jugadores vean la advertencia de cambio. Procedimiento documentado (RN-20). |
| RS-NET-04 | **CA propia opcional**: `sam-signer` emite el certificado del servidor firmado por una CA raíz del operador o comunidad. Si el cliente trae la CA preinstalada (por ejemplo, en un modpack), valida contra ella en lugar de usar TOFU. |

### 6.2 TLS 1.3 y pinning

| ID | Requerimiento |
|---|---|
| RS-NET-05 | **Toda la conexión va dentro de TLS 1.3**, desde el primer byte (Netty `SslHandler`), con el certificado de RS-NET-01. Da confidencialidad, integridad, *forward secrecy* y protección contra replay en todo el tráfico, incluido el gameplay vanilla. Se usa la implementación estándar (JSSE o BouncyCastle JSSE): **no hay criptografía de canal propia**. |
| RS-NET-06 | **Detección del tipo de conexión** en el servidor por los primeros bytes: ClientHello de TLS → TLS de SAM; `GET ` → WebSocket (6.4); otra cosa → vanilla en claro, **solo** para el ping de la lista de servidores y para expulsar con el mensaje de descarga. |
| RS-NET-07 | **Pinning en el cliente (TOFU, como SSH)**: el cliente guarda los pares `server_id → clave` y `dirección → server_id`. Si la clave de un servidor conocido cambia (sin rotación firmada ni CA), el cliente **bloquea la conexión**. Si otro servidor reclama un `server_id` ya fijado con otra clave, también se bloquea. |
| RS-NET-08 | **Aceptar un cambio de clave** (RN-17): el jugador debe escribir el nombre del servidor tras leer la advertencia. Si la cuenta es de un admin, **no se puede aceptar desde el juego**: hay que borrar el pin a mano en la configuración del cliente. |
| RS-NET-09 | **Primera conexión**: la pantalla muestra la huella del certificado (y la frase de 3 palabras de RN-42) para que el jugador la compare con la que publica el servidor (web, Discord). |
| RS-NET-10 | **Downgrade** (RN-18): si un servidor fijado responde sin TLS o sin SAM, el cliente aborta siempre. Para volver a conectarse hay que borrar el pin a mano. |
| RS-NET-11 | **Mensajes SAM** (RN-21): tamaño máximo por tipo de mensaje, parsing estricto que rechaza campos desconocidos, desconexión ante cualquier error de formato y fuzzing con Jazzer en CI. El protocolo se documenta en `docs/PROTOCOLO.md`. |

### 6.3 Identidad del dispositivo del cliente

| ID | Requerimiento |
|---|---|
| RS-NET-12 | El cliente genera una semilla por instalación (guardada según RF-AUTH-05) y deriva de ella **una clave Ed25519 distinta por servidor** (HKDF con el `server_id`), para que dos servidores no puedan reconocer al mismo jugador. Detalle en PROTOCOLO.md 7. El token de "recordar sesión" queda ligado a esa clave: el cliente demuestra que la posee firmando un desafío del servidor **ligado a la conexión**: el *TLS exporter* (RFC 8446 §7.5) si la implementación de TLS lo expone, o en su defecto el hash del certificado del servidor junto con un nonce fresco. Un token robado no sirve sin la clave, y una firma no se puede reenviar a otro servidor. |
| RS-NET-13 | El admin y el jugador pueden listar y revocar dispositivos (desde la GUI de cuenta o, el admin, con `sam auth devices`). |

> Nota técnica para la fase 0: JSSE de JDK 21 no expone una API pública de *TLS exporter* (se agrega en versiones posteriores del JDK). Las opciones son BouncyCastle JSSE, que sí lo expone, o la alternativa de RS-NET-12 (hash del certificado + nonce), que es suficiente porque el pinning ya autentica al servidor.

### 6.4 Transporte WebSocket (Cloudflare / CDN)

Diseño y justificación en [TRANSPORTE_WEBSOCKET.md](TRANSPORTE_WEBSOCKET.md). El WebSocket es **solo un transporte**: por dentro viaja exactamente lo mismo que por TCP, incluido el TLS 1.3 de SAM, de extremo a extremo. El CDN solo ve bytes cifrados.

| ID | Requerimiento |
|---|---|
| RF-WS-01 | El servidor acepta WebSocket en el **mismo puerto** que TCP, con detección automática (RS-NET-06). Se activa con `SAM_WS_ENABLED`. |
| RF-WS-02 | `SAM_WS_PATH`: ruta obligatoria del endpoint (por defecto, una ruta aleatoria generada en el primer arranque). Otra ruta → `404`. |
| RF-WS-03 | `SAM_TCP_ENABLED=false` permite apagar el TCP directo y aceptar solo WebSocket, para que el servidor no sea alcanzable sin pasar por el CDN. |
| RF-WS-04 | El cliente acepta direcciones `ws://` y `wss://` en la lista de servidores, incluido el ping de estado. El mixin sobre `ServerAddress` solo valida la sintaxis, sin efectos secundarios ni bloqueos del hilo de render. |
| RF-WS-05 | El pin se asocia a la identidad del servidor, no a la dirección: un servidor accesible por TCP y por WebSocket es el mismo servidor para el cliente. |
| RF-WS-06 | `/sam info` muestra el estado del transporte: si está activo, la ruta (enmascarada), los proxies de confianza y cuántas conexiones entraron por cada transporte. |
| RF-WS-07 | La documentación para operadores incluye una guía para Cloudflare: registro DNS con proxy, puertos que acepta Cloudflare, `SAM_TCP_ENABLED=false` y firewall que solo permita los rangos de Cloudflare. |

| ID | Seguridad |
|---|---|
| RS-WS-01 | Dentro del WebSocket **solo se acepta TLS 1.3 de SAM**. El WebSocket no reemplaza ni debilita ninguna garantía de la sección 6. |
| RS-WS-02 | **IP real**: las cabeceras `CF-Connecting-IP` o `X-Forwarded-For` (último salto) solo se aceptan si la IP del socket está en `SAM_WS_TRUSTED_PROXIES` (por defecto, los rangos publicados de Cloudflare, actualizados con cada release). En cualquier otro caso se ignoran y se audita el intento. La IP resuelta es la que usa todo SAM: bans, rate limits, límites de conexiones y auditoría. |
| RS-WS-03 | Límites: tamaño máximo de la petición HTTP (cabeceras incluidas), tamaño máximo de mensaje WebSocket, timeout del handshake HTTP (por defecto 5 s), límite de conexiones en estado "handshake" por IP y global. Al excederlos, cierre inmediato. |
| RS-WS-04 | Solo mensajes binarios. Mensajes de texto, fragmentación inválida, frames de control mal formados o un subprotocolo desconocido → cierre sin respuesta detallada. |
| RS-WS-05 | Se rechazan las peticiones con cabecera **`Origin`**: `sam-client` nunca la envía y los navegadores siempre lo hacen. Así una página web no puede abrir conexiones al servidor desde el navegador de una víctima (T-WS-08). |
| RS-WS-06 | Fuzzing del detector de protocolo y del handshake HTTP (Jazzer, igual que RS-NET-11). |

## 7. Módulo de scripting en Lua

### 7.1 Requerimientos funcionales

| ID | Requerimiento |
|---|---|
| RF-LUA-01 | Los scripts viven en datapacks: `data/<namespace>/sam_scripts/<script>/`, con `main.lua`, otros módulos y un `manifest.json` que declara el id, la versión, el lado (`server`, `client` o `both`), las dependencias, las **capacidades solicitadas**, si es `required` y la firma. |
| RF-LUA-02 | Carga y recarga con `/reload` y `/sam scripts reload`, con errores aislados por script. |
| RF-LUA-03 | **API de servidor (de apoyo a la GUI)**: abrir y cerrar pantallas en el cliente, enviar y recibir datos de la UI, eventos básicos de jugador (join, quit, chat, comando), registro de comandos con nodos de permiso, scheduler, almacenamiento persistente por script y lectura de la API de SAM (homes, warps, permisos, jugadores). Las acciones de juego se limitan a las que expone SAM (teletransportar, dar un kit, ejecutar un comando como el jugador o como consola). Ejecutar como consola solo permite los comandos de la lista blanca `SAM_SCRIPTS_CONSOLE_COMMANDS` y **nunca** los comandos sensibles de RS-ADM-01. |
| RF-LUA-04 | **Sistema de servicios y conectores** (dentro del juego; un conector no puede hablar con sistemas externos, ver RS-LUA-00): SAM define contratos estándar (por ejemplo, `sam:economy` con `balance`, `deposit`, `withdraw`, `transfer` y `top`). Un script puede **proveer** un servicio y otros scripts lo **consumen**. SAM puede exponer comandos genéricos (`/balance`, `/pay`) que solo se activan si hay un proveedor registrado. |
| RF-LUA-05 | **Scripts de cliente**: el servidor los entrega por el TLS de SAM durante la configuration, y el cliente los guarda en caché por hash. La firma y el hash se verifican **en cada carga** desde la caché; si no coinciden, se descarta y se pide de nuevo (RN-31). |
| RF-LUA-06 | **API de GUI del cliente (núcleo del módulo)**: (a) **HUD/overlays**: texto, barras, íconos y posiciones relativas a la pantalla; (b) **pantallas propias**: botones, campos de texto, listas con scroll, pestañas, sliders, checkboxes, imágenes y tooltips; (c) **layout** declarativo (filas, columnas, anclas, márgenes) adaptable a la escala de la GUI; (d) **eventos de UI** (click, cambio, hover, cierre); (e) **keybinds** declarados por el script y configurables por el jugador; (f) mensajería cliente↔servidor del propio script; (g) lectura de estado del juego según RS-LUA-10. |
| RF-LUA-07 | Administración: `/sam scripts list|enable|disable|info|errors|trust`. |
| RF-LUA-08 | **Recursos de la GUI**: las texturas e íconos que use un script viajan con el script (firmados) o salen del resource pack del servidor. Solo PNG, con tamaño y dimensiones máximas, decodificado con `NativeImage` y validado antes de subirlo a la GPU (RN-29). |
| RF-LUA-09 | **Mapeo completo de la GUI vanilla**: Lua puede inspeccionar, modificar (agregar, ocultar o mover elementos) y **reemplazar** cualquier pantalla y menú del juego disponible durante la sesión: pausa, inventario, contenedores, chat, lista de jugadores (tab), HUD vanilla, opciones in-game, avances, etc. Como el objetivo es solo 1.21.1, el mapeo se implementa con mixins sobre las clases de pantalla de esa versión y se expone como una API estable en Lua. |
| RF-LUA-09b | Los scripts solo existen **mientras el jugador está conectado** al servidor que los envió. Al desconectarse se descargan y la GUI vuelve a vanilla. Las pantallas previas a la conexión (menú principal, lista de servidores) no se pueden scriptear. |
| RF-LUA-10 | Fuera de alcance: registrar ítems, bloques, entidades, recetas, dimensiones o renderizado de mundo. Eso queda para "Datapack Plus". |

### 7.2 Firma de scripts

Como **el autor de los scripts es el operador**, el modelo de confianza es simple: el operador tiene una o varias **claves de firma**, por ejemplo una por miembro del equipo que escribe scripts. Aun así la firma es necesaria, porque protege contra datapacks alterados en disco (por un panel de hosting comprometido o un FTP filtrado) y contra la inyección de scripts en tránsito hacia los clientes.

| ID | Requerimiento |
|---|---|
| RS-SIG-01 | Cada script se firma con una **clave de firma Ed25519 del operador** usando `sam-signer`. La firma cubre el manifest y el hash SHA-256 de **todos** los archivos del script, de modo que ningún archivo se puede agregar, quitar ni modificar sin invalidarla. |
| RS-SIG-02 | El servidor tiene un **trust store** con las claves públicas autorizadas (`SAM_SCRIPTS_TRUSTED_KEYS`). Solo carga scripts firmados por una clave de confianza. |
| RS-SIG-03 | **Cambios en el trust store** (RN-30): cualquier alta, baja o modificación se avisa a los admins (juego y consola) y queda en la auditoría. **Una clave nueva no se activa hasta que un admin la confirma desde la consola** (`sam scripts trust confirm <huella>`). |
| RS-SIG-04 | **Modo desarrollo**: permite scripts sin firma, pero solo del lado servidor. Muestra un aviso visible en el log y en `/sam info`, y **nunca** envía scripts sin firma a los clientes. |
| RS-SIG-05 | **Doble verificación en el cliente**: (a) la firma del operador sobre el script, y (b) que esa clave de firma esté autorizada por el servidor, mediante una lista de claves firmada por la **clave de identidad del servidor**, que el cliente ya tiene fijada (6.2). |
| RS-SIG-06 | Revocación: quitar una clave del trust store invalida sus scripts en el próximo reload. El cliente borra de su caché los scripts firmados con claves que ya no están autorizadas. |
| RS-SIG-07 | Las claves privadas de firma **nunca** se guardan en el servidor; la firma ocurre offline. `sam-signer` las guarda **cifradas con passphrase** (formato estándar) y la documentación recomienda un gestor de contraseñas (RN-32). |

### 7.3 Sandbox, privacidad y consentimiento

| ID | Requerimiento |
|---|---|
| RS-LUA-00 | **Principio rector: Lua solo controla el comportamiento del juego.** Ni en el servidor ni en el cliente puede tocar algo fuera de Minecraft: **sin red** (sockets, HTTP, DNS), **sin IO** (archivos, directorios, consola del sistema), **sin servicios ni procesos del OS** (ejecutar programas, variables de entorno, hilos nativos, librerías nativas) y **sin acceso a Java** (reflexión, carga de clases, otros mods salvo por la API de SAM). Cualquier funcionalidad nueva de la API se evalúa contra este principio. |
| RS-LUA-01 | Runtime: **Cobalt** (Lua 5.2 en Java puro, que soporta interrupción, usado por CC:Tweaked), con versión fija y seguimiento de sus avisos de seguridad. **La misma sandbox en el servidor y en el cliente.** |
| RS-LUA-02 | Implementación de la sandbox por **lista blanca**: no se cargan las librerías `io`, `os`, `debug` ni `package`, ni ningún binding Java de Cobalt. Solo se exponen `string`, `table`, `math` y `utf8` (con `string.rep` acotado), un `time()` propio de SAM en lugar de `os.time`, y la API de SAM. `load` solo acepta texto, sin bytecode y con el entorno del propio script, y `require` solo resuelve módulos dentro del mismo script. |
| RS-LUA-02b | La persistencia de los scripts pasa **exclusivamente por la API de SAM** (almacenamiento clave-valor en la base de datos del mod, con cuota por script), nunca por archivos. |
| RS-LUA-02c | **La API nunca expone objetos Java**: solo tablas y valores primitivos copiados. Cada función nueva de la API pasa por una revisión de seguridad obligatoria (RN-24). |
| RS-LUA-02d | Tests de seguridad obligatorios en CI: una batería de scripts maliciosos (que intentan abrir archivos o sockets, usar reflexión, hacer loops infinitos o agotar memoria) debe fallar de forma controlada en el servidor y en el cliente, más fuzzing de la API. |
| RS-LUA-03 | **Límites por script** (RN-25): instrucciones por invocación, contabilidad aproximada de memoria y presupuesto de tiempo por tick (servidor) y por frame (cliente). Un script que se excede se suspende, se reporta a los admins y la GUI vuelve a vanilla. |
| RS-LUA-04 | **Capacidades explícitas**: un script solo accede a las APIs que declara en su manifest (por ejemplo, `hud`, `keybinds` o `provide:sam:economy`), y la firma cubre esa declaración. |
| RS-LUA-05 | **Consentimiento**: el jugador da su consentimiento por servidor viendo la lista de scripts y sus capacidades, y puede desactivarlos globalmente en la configuración local del cliente. **El consentimiento se recuerda** por servidor (su identidad fijada): si el servidor ofrece exactamente los mismos scripts que el jugador aceptó todos la última vez (mismo id y mismo hash del paquete, que cubre código y capacidades), se aceptan sin volver a preguntar. Un script nuevo o cambiado, o un rechazo parcial, vuelve a mostrar la pantalla. Si los rechaza, `SAM_SCRIPTS_CLIENT_ON_REJECT` define qué pasa: `kick`, `allow` (entra sin scripts) o `per_script` (solo expulsa si rechaza un script `"required": true`). |
| RS-LUA-06 | **Aislamiento entre scripts**: cada uno tiene su propio entorno global y su propio canal de mensajes; solo se comunican por servicios o eventos declarados en el manifest. |
| RS-LUA-07 | **Pantallas protegidas**: ningún script puede abrir, imitar el título de, superponerse a, modificar ni leer las pantallas de seguridad de SAM: AuthScreen, consentimiento de scripts, advertencia de cambio de identidad del servidor, configuración de SAM del cliente y pantalla de desconexión o kick. Las pantallas de SAM llevan un indicador visual que un script no puede dibujar. |
| RS-LUA-08 | **Sin eventos con pantalla protegida** (RN-27): mientras hay una pantalla protegida abierta, los scripts no reciben ningún evento (teclado, ratón, render ni tick de UI). Fuera de ellas, solo reciben las teclas de sus keybinds y los eventos de sus propias pantallas. |
| RS-LUA-09 | **Marca de interfaz del servidor** (RN-26): toda pantalla creada o reemplazada por un script lleva una marca pequeña no removible ("Interfaz del servidor"). |
| RS-LUA-10 | **Datos legibles por Lua** (RN-28): solo una lista cerrada de datos de la partida (vida, posición, dimensión, inventario visible, jugadores en tab, escala de la GUI y tamaño de la ventana para el layout). Nada sobre mods instalados, archivos, opciones ni hardware. |
| RS-LUA-11 | Un script no puede abrir URLs, interactuar con el portapapeles, cambiar de servidor ni cerrar el juego. Sí puede desconectar al jugador del servidor actual. |

## 8. Configuración (`.env`) y persistencia

### 8.1 Requerimientos

| ID | Requerimiento |
|---|---|
| RF-CFG-01 | La configuración del servidor vive en un archivo **`.env` solo del lado servidor** (por defecto `config/sam/.env`, con la ruta configurable vía `SAM_ENV_FILE`). El `sam-client` nunca lo recibe; el cliente solo conoce lo que el servidor le comunica (por ejemplo, qué botones de login mostrar). |
| RF-CFG-02 | Las **variables de entorno reales** del proceso tienen prioridad sobre el archivo, lo que facilita Docker y los paneles de hosting. |
| RF-CFG-03 | El mod incluye un **`.env.example`** documentado. En el primer arranque, si no existe un `.env`, lo genera con valores por defecto seguros. |
| RF-CFG-04 | **Validación al arrancar**: si el `.env` es inválido o inconsistente (por ejemplo, un método obligatorio que no está habilitado, Google habilitado sin `client_id`, o faltan los secretos maestros), el módulo de auth **falla cerrado**: no deja entrar a nadie y explica el error en consola. |
| RF-CFG-05 | Recarga en caliente con `/sam reload` (según RS-ADM-01), excepto las claves que exigen reinicio, que se marcan como tales en el ejemplo. |
| RF-CFG-06 | Los valores secretos (`*_SECRET`, `*_KEY`, `*_PASSWORD`, `*_PASSPHRASE`) **se enmascaran** en logs, en `/sam info` y en los reportes de error. |
| RF-CFG-07 | Los datos estructurados que no caben bien en un `.env` (kits, formato de chat, mensajes) van en archivos auxiliares del servidor, referenciados desde el `.env`. |
| RF-CFG-08 | **Secretos maestros fuera del `.env`** (RN-33): `SAM_DATA_KEY` (cifra TOTP y correos en reposo) y `SAM_IDENTITY_PASSPHRASE` (protege la clave del certificado) **solo** se aceptan como variables de entorno reales del proceso. Si están escritos en el `.env`, SAM se niega a arrancar. En el primer arranque, si faltan, SAM genera valores aleatorios y los escribe en `config/sam/secretos-sugeridos.txt`, legible solo por el dueño, con instrucciones para definirlos (el operador lo borra después). **Nunca se escriben en el log** (H-10 de `docs/HARDENING.md`): la consola solo dice dónde está el archivo. Hasta que estén configurados no se habilita el login. Así, un backup de la base de datos junto con el `.env` no expone los secretos. |
| RF-CFG-09 | **Protección del `.env`** (RN-34): SAM genera un `.gitignore` junto al `.env`, se niega a arrancar si el `.env` está dentro de la carpeta del mundo o de un datapack, y advierte si el archivo tiene permisos abiertos. |
| RF-CFG-10 | **Archivos sensibles solo para el dueño** (H-12 de `docs/HARDENING.md`): todo archivo con secretos, datos de jugadores o configuración de seguridad se escribe de forma atómica y con permisos solo para el dueño **desde que se crea** (el temporal ya nace restringido). En el servidor: `accounts.json`, `identity.p12`, `permissions.json`, los datos de scripts, el trust store de claves y `secretos-sugeridos.txt`. En el cliente: los pins de servidores y los consentimientos de scripts. |
| RF-CFG-11 | **Respaldos cifrados** (H-16 de `docs/HARDENING.md`): `tools/ops/backup.ps1` arma el .zip en una carpeta temporal solo del dueño y lo cifra con `sam-signer backup-seal` usando `SAM_BACKUP_KEY` (32 bytes aleatorios en base64, **solo como variable de entorno**, distinta de `SAM_DATA_KEY`; `sam-signer backup-key` genera una). El zip en claro nunca queda en el destino. Formato `.sambk`: cabecera `SAMBK1`, nonce base de 12 bytes y bloques de hasta 1 MiB, cada uno AES-256-GCM con nonce = base XOR número de bloque y AAD = cabecera + número de bloque + marca de último bloque (así no se pueden reordenar, quitar ni truncar bloques). Junto a cada respaldo va su `.sha256`. `tools/ops/restore.ps1` verifica el hash, descifra con `sam-signer backup-open` y extrae en una carpeta nueva (nunca encima del servidor). |
| RF-CFG-12 | **Datos personales cifrados y rotación de la clave de datos** (H-13 y H-14 de `docs/HARDENING.md`): con `SAM_DATA_KEY`, el correo y el `sub` de Google se guardan en `accounts.json` cifrados con AES-256-GCM (`enc1:<id de clave>:<base64>`, AAD con el campo y la cuenta); los valores viejos en claro se leen y se cifran al guardar. Un archivo con campos cifrados sin la clave no abre (el login queda cerrado). Rotación: se define la clave nueva en `SAM_DATA_KEY` y la anterior en `SAM_DATA_KEY_PREVIOUS` (también solo como variable de entorno); SAM lee con cualquiera de las dos y escribe con la nueva; `sam datakey rotate` (solo la consola real) vuelve a cifrar todo con la nueva, y después la anterior se puede quitar. |

### 8.2 Políticas de login por permisos

El administrador define **métodos disponibles** y **políticas**. Una política agrupa a ciertos jugadores (por permiso, nivel de OP o lista) y define qué métodos pueden usar y qué factores son obligatorios. Si un jugador encaja en varias políticas, gana la de **mayor prioridad**; `DEFAULT` aplica al resto.

### 8.3 Ejemplo de `.env`

```dotenv
# ===== General =====
SAM_LANG=es_es
SAM_DB_URL=sqlite:config/sam/sam.db
SAM_SERVER_CERT_FILE=config/sam/keys/identity.p12   # certificado + clave del servidor (cifrada)
# Secretos maestros: SOLO como variables de entorno del proceso, nunca aquí:
#   SAM_DATA_KEY             cifra TOTP y correos en reposo
#   SAM_IDENTITY_PASSPHRASE  descifra la clave del certificado

# ===== Red y transporte =====
SAM_TCP_ENABLED=true                        # false = solo WebSocket (recomendado detrás de un CDN)
SAM_WS_ENABLED=false
SAM_WS_PATH=/<aleatoria>                    # generada en el primer arranque
SAM_WS_TRUSTED_PROXIES=cloudflare           # cloudflare | lista de CIDR | vacío
SAM_WS_REAL_IP_HEADER=CF-Connecting-IP      # o X-Forwarded-For
SAM_WS_MAX_MESSAGE=1MiB
SAM_WS_HANDSHAKE_TIMEOUT=5s
SAM_NET_UNCLASSIFIED_PER_IP=8               # conexiones sin clasificar (incluye handshake WebSocket)
SAM_NET_UNCLASSIFIED_GLOBAL=256
SAM_RCON_SENSITIVE_COMMANDS=false           # comandos sensibles de SAM desde RCON

# ===== Métodos de login disponibles =====
# password (por defecto, el más débil) | google | discord   (el 2FA se suma a cualquiera)
SAM_AUTH_METHODS=password,google
SAM_AUTH_TIMEOUT=120s
SAM_AUTH_MAX_ATTEMPTS=5
SAM_AUTH_LOCKOUT_BASE=15m                   # se duplica en cada bloqueo repetido
SAM_AUTH_PENDING_PER_IP=3
SAM_AUTH_PENDING_GLOBAL=50
SAM_AUTH_NOTIFY_FAILED_AFTER=10             # aviso por correo tras N fallos
SAM_PASSWORD_MIN_LENGTH=8   # mínimo NIST SP 800-63B; el cliente además rechaza las ~96.000 contraseñas más comunes y las que contienen el nick (RN-45)
SAM_NICK_VALIDATION=strict                  # off | strict | strict_similarity

# ===== Proveedores OAuth =====
SAM_OAUTH_GOOGLE_CLIENT_ID=
SAM_OAUTH_GOOGLE_CLIENT_SECRET=
SAM_OAUTH_DISCORD_CLIENT_ID=
SAM_OAUTH_DISCORD_CLIENT_SECRET=
SAM_OAUTH_DISCORD_REDIRECT_PORT=53682

# ===== Registro y correo =====
# El correo es SIEMPRE obligatorio en el registro (no configurable)
SAM_REGISTER_EMAIL_VERIFY=before_play       # before_play | later
SAM_REGISTER_MAX_ACCOUNTS_PER_EMAIL=1
SAM_RECOVERY_CODE_TTL=15m
SAM_RECOVERY_UNKNOWN_DEVICE_DELAY=24h
SAM_MAIL_SMTP_HOST=smtp.example.com
SAM_MAIL_SMTP_PORT=587
SAM_MAIL_SMTP_SECURITY=starttls             # starttls | tls | none
SAM_MAIL_SMTP_USER=
SAM_MAIL_SMTP_PASSWORD=
SAM_MAIL_FROM="Mi Servidor <no-reply@example.com>"
SAM_MAIL_TEMPLATES_DIR=config/sam/mail/
SAM_MAIL_MAX_PER_HOUR=200                   # tope global
SAM_MAIL_NOTIFY_NEW_DEVICE=true
SAM_MAIL_NOTIFY_PASSWORD_CHANGE=true

# ===== Administradores =====
SAM_ADMINS=Notch,069a79f4-44e9-4726-a5be-fca90e38aaf5   # nombres o UUID
SAM_ADMIN_OP_LEVEL=2

# ===== Políticas (mayor PRIORITY gana) =====
SAM_POLICIES=ADMIN,STAFF,DEFAULT

SAM_POLICY_ADMIN_MATCH=list:admins,op:2,permission:sam.admin
SAM_POLICY_ADMIN_PRIORITY=100
SAM_POLICY_ADMIN_METHODS=password,google
SAM_POLICY_ADMIN_REQUIRE=totp                 # factores obligatorios además del método (google + TOTP)
SAM_POLICY_ADMIN_SESSION_TTL=12h

SAM_POLICY_STAFF_MATCH=permission:sam.staff
SAM_POLICY_STAFF_PRIORITY=50
SAM_POLICY_STAFF_METHODS=password,google
SAM_POLICY_STAFF_REQUIRE=totp
SAM_POLICY_STAFF_SESSION_TTL=24h

SAM_POLICY_DEFAULT_METHODS=password,google
SAM_POLICY_DEFAULT_REQUIRE=                   # vacío = 2FA opcional
SAM_POLICY_DEFAULT_SESSION_TTL=7d

# ===== Auditoría y privacidad =====
SAM_AUDIT_IP_RETENTION=90d
SAM_AUDIT_COMMANDS=op,deop,ban,ban-ip,pardon,pardon-ip,kick,whitelist,gamemode,give,effect,tp,teleport,kill,clear,stop,save-off   # se auditan (RF-ADM-06), también dentro de execute ... run

# ===== Scripts Lua =====
SAM_SCRIPTS_ENABLED=true
SAM_SCRIPTS_TRUSTED_KEYS=config/sam/keys/trusted/   # claves públicas (se confirman desde la consola)
SAM_SCRIPTS_DEV_MODE=false                          # permite scripts sin firmar SOLO del lado servidor
SAM_SCRIPTS_CLIENT_ON_REJECT=per_script             # kick | allow | per_script
SAM_SCRIPTS_CONSOLE_COMMANDS=give,effect,title      # lista blanca para "ejecutar como consola"
SAM_SCRIPTS_MAX_CALL_MS=50                          # tope de tiempo por llamada a un script (se interrumpe y se suspende)
SAM_SCRIPTS_MAX_MEMORY=32MB                         # memoria aproximada que puede asignar en una llamada

# ===== Actualizaciones =====
SAM_UPDATE_CHECK=true                       # consulta GitHub Releases
SAM_UPDATE_CHECK_INTERVAL=24h
SAM_UPDATE_CHANNEL=stable                   # stable | prerelease

# ===== Módulos Essentials =====
SAM_MODULE_TELEPORT=true
SAM_MODULE_HOMES=true
SAM_HOMES_DEFAULT_LIMIT=3
SAM_TPA_WARMUP=3s
SAM_KITS_FILE=config/sam/kits.json5
```

> La sintaxis exacta de las claves y de `MATCH` se cierra en la fase 0. Este ejemplo fija la forma, no los nombres definitivos.

### 8.4 Aviso de actualizaciones (RF-UPD)

| ID | Requerimiento |
|---|---|
| RF-UPD-01 | El **servidor** consulta la API pública de GitHub Releases del proyecto al arrancar y luego cada `SAM_UPDATE_CHECK_INTERVAL`, en un hilo aparte, sin bloquear el arranque y tolerando fallos de red. Revisa tanto `sam-server` como `sam-client`. |
| RF-UPD-02 | Si hay una versión nueva, el aviso **llega solo a los admins**: un mensaje en la consola y otro en el juego cuando un admin verificado entra, con la versión, el link al release y si es una **actualización de seguridad** (según una etiqueta en el release). |
| RF-UPD-03 | El aviso es solo informativo: **nunca descarga ni instala nada** automáticamente. La consulta va por HTTPS con validación de certificado y el aviso solo muestra links hacia el repositorio oficial (RN-41). |
| RF-UPD-04 | El cliente **no** consulta GitHub por su cuenta. Si su versión es incompatible con el servidor, recibe un kick con el mensaje y el link de descarga (RF-AUTH-10). |
| RF-UPD-05 | Se puede desactivar con `SAM_UPDATE_CHECK=false`. |

### 8.5 Persistencia

- RF-DATA-01: SQLite embebido con migraciones versionadas, tras una capa de repositorios que permita sumar MySQL más adelante. **Solo consultas parametrizadas**; una regla de análisis estático en CI rompe el build si encuentra SQL concatenado (RN-35).
- RF-DATA-02: Mensajes localizables (`es_es`, `en_us`) y personalizables.
- RF-DATA-03: La configuración local del cliente (pins de servidores, consentimientos, preferencias, caché de scripts) vive en `config/sam-client/` del lado cliente. Es independiente del `.env` y nunca contiene secretos del servidor; la clave del dispositivo va al almacén seguro del sistema operativo (RF-AUTH-05).

## 9. Requerimientos no funcionales

| ID | Requerimiento |
|---|---|
| RNF-01 | Rendimiento: la base de datos, el hashing Argon2, el TLS y el envío de correos van **fuera del hilo principal**. El impacto en el MSPT debe ser despreciable con 100 jugadores. La derivación de la contraseña en el cliente (RS-AUTH-01) no debe pasar de ~1 s en una PC modesta. |
| RNF-02 | Compatibilidad: 1.21.1, servidor dedicado. En single-player el cliente funciona sin interferir. SAM es el único dueño del pipeline de red; se prueba la convivencia con mods de red comunes. |
| RNF-03 | Calidad: tests unitarios de la criptografía (vectores de prueba), del parser de manifest y de la sandbox; GameTests de Fabric para el flujo de login (desconexiones, `/reload`, logins duplicados a mitad del flujo); tests de integración por cada camino de conexión (TCP, TLS, WebSocket); tests de origen por cada comando sensible; fuzzing con Jazzer de los decoders, del detector de protocolo y de las imágenes. |
| RNF-04 | Seguridad: modelo de amenazas documentado ([AMENAZAS.md](AMENAZAS.md)) y revisión antes de cada release, con un checklist basado en sus requerimientos derivados. |
| RNF-05 | Observabilidad: logs estructurados, un comando de diagnóstico y auditoría de eventos de seguridad. |
| RNF-06 | **Cadena de suministro** (RN-38 a RN-40): releases con checksums SHA-256, firma con Sigstore/cosign y build reproducible; Gradle dependency verification, dependencias mínimas, Dependabot y revisión manual de cada actualización; 2FA obligatorio para los maintainers, rama protegida (solo PR revisados), tags firmados y releases solo desde CI con atestación de procedencia (SLSA). |

## 10. Fases

| Fase | Contenido | Entregable |
|---|---|---|
| 0 | POC: proyecto Gradle con los dos jars y endurecimiento del repositorio (RNF-06); **TLS 1.3 en el pipeline** con certificado Ed25519 y pinning; detector de protocolo y **WebSocket** detrás de Cloudflare; tarea de configuration que retiene al cliente y AuthScreen; login duplicado y fail-closed; derivación de la contraseña en el cliente; kick sin mod; "hola mundo" en Cobalt con sandbox y contabilidad de memoria | Factibilidad |
| 1 | Auth completo: registro, login, Argon2, TOTP, política de admins y origen de comandos, LuckPerms `sam:verified`, sesiones por dispositivo y almacén del SO, bloqueos y límites, correo y recuperación, auditoría encadenada, persistencia, configuración y secretos maestros | MVP seguro |
| 1.5 | "Entrar con Google" y Discord: loopback + PKCE, vinculación de cuentas, fallback con device flow y documentación para operadores | Login social |
| 2 | Paridad con Essentials (sección 4), importador desde EssentialsX, nicks reservados y herramientas de privacidad | Reemplazo funcional |
| 3 | Base de Lua: carga desde datapacks, `sam-signer`, trust store con confirmación por consola, sandbox, entrega segura al cliente, doble verificación y consentimiento | Infraestructura de scripts |
| 4 | **API de GUI**: HUD, pantallas, widgets, layout, keybinds, mapeo de la GUI vanilla, pantallas protegidas y marca de interfaz, puente cliente↔servidor y servicios/conectores (economía de ejemplo con su GUI) | Scripting de GUI |
| 5 | Certificados con CA propia, procedimiento de rotación, endurecimiento y documentación | v1.0 |

## 11. Próximos documentos

1. ~~`docs/PROTOCOLO.md`~~ Hecho: [PROTOCOLO.md](PROTOCOLO.md) v1.0.
2. Especificación de la API de GUI en Lua (fase 4), que se escribe a partir de la POC de la fase 0.
