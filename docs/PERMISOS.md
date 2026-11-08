# Permisos de SAM (RF-PERM)

SAM trae su propio sistema de permisos con grupos y nodos. Se registra como **proveedor de `fabric-permissions-api`** (Lucko): cuando cualquier mod pregunta un permiso, responde SAM. Si el operador instala **LuckPerms**, SAM le cede el control: sus grupos quedan inactivos y lo avisa en el log al arrancar.

## 1. Conceptos

- **Nodo**: un permiso con nombre, como `sam.command.home`. Segmentos `[a-z0-9_-]` separados por `.`, hasta 128 caracteres. El último segmento puede ser `*` (comodín): `sam.command.*` vale para todo lo que empieza con `sam.command.`, y `*` solo vale para todo.
- **Valor**: `true` (concedido) o `false` (negado). Negar sirve para quitar algo puntual que un comodín o un grupo concede.
- **Grupo**: un conjunto de nodos y metas, con un **peso** (entero) y **padres** de los que hereda. El grupo `default` existe siempre, se aplica a todos los jugadores y no se puede borrar.
- **Meta**: un valor de texto con nombre (hasta 256 caracteres), para límites y textos: `sam.homes.limit = 5`, `sam.chat.prefix = [VIP]`. Mismos nombres que los nodos, sin comodines.
- **Temporal**: un nodo, una meta o la pertenencia a un grupo puede tener **vencimiento**. Al vencer deja de valer en el acto y SAM lo borra del archivo (con una línea en la auditoría).
- **Verificado**: un nodo puede exigir **sesión verificada** (`verified: true`): solo vale si el jugador completó el 2FA en esa sesión (RF-ADM-04, contexto `sam:verified=true`). Así se dan los permisos de staff.

Los jugadores se identifican por **nick** (el servidor es offline, como las cuentas de SAM). Si alguien se cambia el nick, pierde sus permisos y grupos, igual que un admin pierde el rol (RF-ADM-08).

## 2. Cómo se resuelve un permiso

Para saber si un jugador tiene el nodo `N`:

1. **Fuentes, en orden**: primero el propio jugador; después todos sus grupos, que son los directos más todos los heredados (sin repetir) más `default`, ordenados por **peso de mayor a menor** (a igual peso, por nombre). Se ignora lo vencido y, si la sesión no está verificada, lo que exige verificación.
2. **En cada fuente** se busca la entrada más específica que coincida con `N`: primero el nodo exacto; si no está, el comodín más largo (`a.b.*` gana a `a.*`, que gana a `*`).
3. **La primera fuente que tenga una coincidencia decide** (`true` o `false`).
4. Si ninguna tiene nada, el permiso es **indefinido**: quien preguntó usa su valor por defecto. Para `fabric-permissions-api`, eso es el nivel de OP que pidió el mod.

Las metas se resuelven igual (pasos 1 y 3, sin comodines). Una herencia circular hace que el archivo sea inválido.

## 3. El archivo `config/sam/permissions.json`

```json
{
  "version": 1,
  "groups": {
    "default": {
      "weight": 0,
      "permissions": { "sam.command.home": true, "sam.command.spawn": true },
      "meta": { "sam.homes.limit": "1" }
    },
    "vip": {
      "weight": 10,
      "parents": ["default"],
      "permissions": { "sam.command.fly": true, "sam.command.fly.others": false },
      "meta": { "sam.homes.limit": "5", "sam.chat.prefix": "[VIP]" }
    },
    "admin": {
      "weight": 100,
      "parents": ["vip"],
      "permissions": { "*": { "value": true, "verified": true } }
    }
  },
  "users": {
    "steve": {
      "groups": { "vip": { "expires": 1767225600 } },
      "permissions": { "sam.command.nick": { "value": true, "expires": 1765000000 } },
      "meta": { "sam.homes.limit": "8" }
    }
  }
}
```

- Las claves de `users` son nicks en minúsculas.
- Un nodo vale `true`, `false` o un objeto `{value, expires?, verified?}`. Una meta vale un texto o `{value, expires?}`. `expires` es una fecha Unix en segundos.
- En un grupo, `weight`, `parents`, `permissions` y `meta` son opcionales (por defecto 0 y vacíos). En un usuario, `groups` es un mapa de grupo a `{}` o `{expires}`.
- **Lectura estricta**: una clave desconocida, un tipo equivocado, un nodo mal escrito, un padre o grupo que no existe, o una herencia circular invalidan el archivo.
- **Topes**: 256 grupos, 1024 nodos y 256 metas por grupo o usuario, 16 padres por grupo y 1 MiB de archivo.

El archivo se puede editar a mano y recargar con `/sam perms reload`. **Si al arrancar es inválido**, SAM no aplica ningún permiso propio: todo queda indefinido, es decir, nivel de OP como en vanilla. Lo dice en el log y no toca el archivo. **Si es inválido en un reload**, se mantiene lo que había. Los comandos lo reescriben entero, ordenado y con escritura atómica.

## 4. Comandos (`/sam perms`)

| Comando | Qué hace |
|---|---|
| `/sam perms reload` | Relee el archivo |
| `/sam perms check <nick> <nodo>` | Dice si lo tiene, por qué fuente y qué entrada decidió |
| `/sam perms group list` | Los grupos con su peso |
| `/sam perms group info <grupo>` | Peso, padres, nodos y metas |
| `/sam perms group create <grupo> [peso]` / `delete <grupo>` | Crea o borra un grupo (`default` no se borra; un grupo que es padre de otro tampoco) |
| `/sam perms group weight <grupo> <peso>` | Cambia el peso |
| `/sam perms group parent add\|remove <grupo> <padre>` | Herencia |
| `/sam perms group set <grupo> <nodo> [true\|false] [duración] [verified]` | Da o niega un nodo (por defecto `true`) |
| `/sam perms group unset <grupo> <nodo>` | Lo quita |
| `/sam perms group meta set <grupo> <clave> <valor> [duración]` / `meta unset <grupo> <clave>` | Metas |
| `/sam perms user info <nick>` | Grupos, nodos y metas propios del jugador |
| `/sam perms user group add <nick> <grupo> [duración]` / `group remove <nick> <grupo>` | Pertenencia a grupos |
| `/sam perms user set\|unset <nick> ...` y `user meta set\|unset <nick> ...` | Igual que en los grupos |

- Una **duración** es como `30d`, `12h`, `45m`, `90s` o una combinación (`1d12h`).
- Nombres de grupo: `[a-z0-9_-]{1,32}`.
- `/sam perms` es un **comando sensible** (RS-ADM-01): se acepta desde la consola real del servidor y de un **admin con sesión verificada** en el juego. Admin es quien tenga nivel de OP ≥ `SAM_ADMIN_OP_LEVEL` (por defecto 2) o el permiso `sam.admin`, como dice RF-ADM-02. RCON solo con `SAM_RCON_SENSITIVE_COMMANDS=true`. Bloques de comando, funciones y Lua, nunca.
- Cada cambio va a la auditoría: quién, qué y el valor anterior.

## 5. Desde Lua (capacidad `permissions`, solo servidor)

- `sam.has(jugador, nodo)` → `true` o `false` (lo indefinido es `false`).
- `sam.meta(jugador, clave)` → texto o `nil`.

Ambas solo leen y valen para jugadores en línea (por nick); para uno desconectado devuelven `false` o `nil`. Un comando de script puede exigir un nodo: `sam.command(nombre, fn, {node = "miscript.usar"})`. Si el permiso queda **indefinido** para quien lo ejecuta, decide el nivel de OP `permission`, que **con `node` vale 2 por defecto** (operadores; la consola siempre puede). Así un nodo que nadie concedió no deja entrar a todos. Para que lo indefinido sea "todos", se pasa `permission = 0` a propósito. Sin `node`, manda `permission` como antes (por defecto 0).
