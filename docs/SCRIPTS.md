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
