# Scripts Lua de SAM: guía para operadores

Los scripts de SAM viven en datapacks y corren en el servidor dentro de una sandbox: no pueden tocar archivos, la red, el sistema ni Java (REQUERIMIENTOS.md 7). El servidor solo carga scripts **firmados con una clave que tú confirmaste desde la consola**.

## 1. Un script

```
<datapack>/data/<namespace>/sam_scripts/<script>/
  manifest.json
  main.lua
  (otros .lua, que se cargan con require)
  signature.json      ← lo genera sam-signer
```

`manifest.json` (PROTOCOLO.md 8.3):

```json
{"id": "saludo", "version": "1.0", "side": "server", "capabilities": ["events", "chat"]}
```

El `id` es el nombre de la carpeta. Cada capacidad habilita una parte de la API; una función de una capacidad no declarada **no existe** para el script:

| Capacidad | Funciones |
|---|---|
| (siempre) | `sam.log(texto)` |
| `events` | `sam.on('join' \| 'quit' \| 'chat', fn)`: `fn(jugador)` con `{name, uuid}`; en `chat`, `fn(jugador, texto)` |
| `scheduler` | `sam.after(ticks, fn)`, `sam.every(ticks, fn)` (20 ticks = 1 s) y `sam.cancel(id)` |
| `players` | `sam.players()`: lista de `{name, uuid}` |
| `chat` | `sam.tell(nombre, texto)` y `sam.broadcast(texto)` (texto plano, hasta 256 caracteres) |
| `commands` | `sam.command(nombre, fn, {permission = 0..4})` registra `/nombre`: `fn(jugador, texto, args)` recibe al jugador (`nil` si es la consola), el texto después del nombre y sus palabras; lo que devuelve es la respuesta |

Sobre los comandos: el permiso por defecto es 0 (cualquier jugador); con 2 o más solo lo ven y usan los operadores. Como mucho 16 por script. No se puede pisar un comando que ya existe (vanilla, otros mods, `sam` u otro script): se informa en el log y no se registra.

```lua
sam.command('hola', function(p, texto, args)
  return '¡Hola, ' .. (p and p.name or 'consola') .. '!'
end)
sam.command('anuncio', function(p, texto) sam.broadcast('[Anuncio] ' .. texto) end, {permission = 2})
```

Ejemplo completo: [ejemplos/sam_scripts/saludo](ejemplos/sam_scripts/saludo).

Lua disponible: `string`, `table`, `math`, `utf8`, `time()`, `load` (solo texto) y `require` (solo módulos del mismo script). Cada llamada tiene un tope de tiempo (`SAM_SCRIPTS_MAX_CALL_MS`, 50 ms) y de memoria (`SAM_SCRIPTS_MAX_MEMORY`, 32 MB): un script que se pasa queda **suspendido** hasta el próximo `/reload`.

## 2. Firmar (en tu PC, nunca en el servidor)

```
java -jar sam-signer.jar keygen mi_clave          # crea mi_clave.key (cifrada) y mi_clave.pub
java -jar sam-signer.jar sign <carpeta del script> --key mi_clave.key
java -jar sam-signer.jar verify <carpeta del script> --pub mi_clave.pub
```

`mi_clave.key` va cifrada con tu passphrase (PKCS#8 estándar; OpenSSL la abre). Guárdala en un gestor de contraseñas. Cualquier cambio en el script después de firmar invalida la firma: vuelve a firmar.

## 3. Confiar en tu clave (una vez, en el servidor)

1. Copia `mi_clave.pub` a `config/sam/keys/trusted/`.
2. Al arrancar o en `/reload`, el log avisa: `Clave de firma <key_id> (mi_clave.pub) pendiente`.
3. En la **consola del servidor** (no desde el juego ni por RCON): `sam scripts trust confirm <key_id>`.

Para revocar una clave, borra su `.pub`.

## 4. Administración

| Comando | Qué hace |
|---|---|
| `/sam scripts list` | Scripts y su estado (corriendo, suspendido, no cargó) |
| `/sam scripts errors <script>` | Los últimos errores del script |
| `/sam scripts reload` | Relee las claves y recarga los scripts (también lo hace `/reload`) |
| `/sam scripts trust list` | Claves activas y pendientes |

## 5. Modo desarrollo

`SAM_SCRIPTS_DEV_MODE=true` (variable de entorno) permite scripts **sin firma**, solo del lado servidor, con un aviso en el log. Úsalo solo mientras escribes un script; nunca en producción.

## 6. Scripts de cliente

Un script con `"side": "client"` (o `"both"`) **no corre en el servidor**: se envía a cada jugador al entrar, después del login. El jugador ve una pantalla con cada script, quién lo firmó (el nombre de su `.pub`) y qué capacidades pide, y elige cuáles acepta. Lo aceptado corre solo mientras está conectado a tu servidor.

- Siempre van **firmados**: el modo desarrollo nunca envía scripts sin firma a los clientes.
- El cliente comprueba dos firmas: la de tu clave sobre el script, y la del servidor sobre la lista de claves que autorizas (la identidad del servidor, que el jugador ya tiene fijada). Un script que no pasa no se puede aceptar.
- `"required": true` marca los imprescindibles. Qué pasa si el jugador rechaza algo lo decide `SAM_SCRIPTS_CLIENT_ON_REJECT`:

| Valor | Si rechaza… |
|---|---|
| `per_script` (por defecto) | un script requerido: se le expulsa con `SAM-K010`. Los opcionales puede rechazarlos. |
| `kick` | cualquier script: se le expulsa. |
| `allow` | lo que sea: entra sin esos scripts. |

El cliente **recuerda** lo que el jugador aceptó en cada servidor (`config/sam-client/script-consents.properties`). Si al volver a entrar los scripts son exactamente los mismos y los había aceptado todos, entra sin ver la pantalla. Cualquier script nuevo o modificado (otro hash) vuelve a preguntar, y si el jugador rechazó alguno se le pregunta siempre.

Un cliente de SAM sin soporte de scripts cuenta como si los rechazara todos. El jugador puede rechazarlos siempre con `enabled=false` en `config/sam-client/scripts.properties`.

Topes por conexión: 128 scripts y 16 MiB en total (4 MiB por script). El cliente guarda cada script en `sam-client/script-cache/` por su hash y lo vuelve a verificar cada vez que lo usa: si cambias el script, se descarga de nuevo.

### Qué puede hacer un script de cliente

La lista completa está en `docs/PROTOCOLO.md` (8.3, "API de cliente v0"). En resumen, según las capacidades del manifest:

- `hud`: textos e imágenes PNG del propio script en la pantalla del jugador.
- `screens`: ventanas propias (botones, campos de texto, casillas, imágenes). Siempre llevan la marca **"Interfaz del servidor"** y nunca se abren encima de otra pantalla.
- `keybinds`: teclas (a-z, 0-9, f1-f12). Si la tecla ya la usa el juego u otro mod, no se asigna; el jugador puede cambiarla desde el menú de pausa → "Teclas de scripts".
- `game`: leer datos de la partida del jugador (vida, posición, dimensión, barra rápida, jugadores en tab, tamaño de la GUI). Es una lista cerrada: nada sobre sus mods, archivos ni su PC.
- `messages`: un script `"side": "both"` habla con su propia parte de servidor (`sam.send` / `sam.receive`). Con `sam.side` cada lado sabe dónde corre.

Las imágenes van dentro de la carpeta del script (por ejemplo `assets/icono.png`), así quedan firmadas: solo PNG, hasta 64 KiB y 256×256.

Mientras el jugador tiene abierta una pantalla de SAM (inicio de sesión, cuenta, 2FA, consentimiento), los scripts de cliente no reciben nada.

### Borrado de datos de un jugador (servidor)

Cuando un jugador borra su cuenta (o la consola usa `sam auth reset`), los scripts de servidor con la capacidad `events` reciben `sam.on("erase", function(nick) ... end)`: cada plugin borra lo que guardó de ese jugador (RF-AUTH-07e).

### Guardar datos (servidor)

Con la capacidad `storage`, un script de servidor guarda datos que sobreviven a reinicios: `sam.store.set("puntos:steve", 10)`, `sam.store.get("puntos:steve")`, `sam.store.keys()`. Hasta 1024 claves y 256 KiB por script. SAM los guarda en `<mundo>/sam/scripts/<id>.dat`; hazle copia de seguridad junto con el mundo.
