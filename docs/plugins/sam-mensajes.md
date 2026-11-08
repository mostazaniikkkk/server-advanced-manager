# Plugin `sam-mensajes` (mensajería privada)

Plugin Lua oficial de SAM: un datapack firmado que entrega el servidor (como todo lo de EssentialsX, ver `REQUERIMIENTOS.md`, sección 4). Es **aparte del `/msg` de vanilla**, que sigue igual. Lo que agrega es una mensajería privada con conversaciones, que además de texto puede llevar:

- **links**: se abren con la confirmación de vanilla;
- **la posición del jugador** al enviar: solo si la comparte, con un botón;
- **imágenes**: una captura del juego o un archivo del PC.

## Para el jugador

- **Abrirla**: en el inventario, el botón de **Opciones de cuenta** pasa a ser un menú desplegable con "Opciones de cuenta" y "Mensajes" (API de menús, abajo). También se abre con `/pm` sin argumentos.
- **Conversaciones**: a la izquierda, la lista de conversaciones (la más reciente arriba, con un aviso de no leídos). A la derecha, la conversación elegida, el campo de texto y los botones:
  - **Enviar**;
  - **📍 Posición**: agrega tus coordenadas y dimensión al mensaje;
  - **📷 Captura**: toma lo que se ve en el juego, sin la interfaz;
  - **🖼 Imagen**: elige una imagen de tu PC.
- **Imágenes recibidas**: aparecen como "🖼 Imagen de Steve — ver". Solo se descargan y se muestran si haces clic.
- **Links**: un texto que empieza con `http://` o `https://` se muestra como link. Al hacer clic, vanilla pregunta si quieres abrirlo.
- **Comandos**: `/pm <jugador> <texto>` envía; `/r <texto>` responde al último que te escribió.
- **Memoria**: las conversaciones viven **solo en la memoria del servidor**. Se borran al reiniciarlo, y cada una guarda los últimos 50 mensajes y las últimas 20 imágenes. Nada queda en disco.

## Piezas nuevas de la API (nativas, PROTOCOLO.md 8.3)

| Capacidad | Lado | Qué agrega |
|---|---|---|
| `menu` | cliente | `sam.menu.add(id, texto, fn[, {icon, order}])` agrega una entrada al botón de Opciones de cuenta. Con al menos una entrada de algún plugin, el botón pasa a ser un menú desplegable: primero "Opciones de cuenta" y después las de los plugins, por `order` (por defecto 100) y texto. Hasta 4 entradas por script. `sam.menu.remove(id)` la quita |
| `links` | cliente | `sam.open_url(url)` abre la confirmación de vanilla para un link `http(s)://` (≤ 512). Nunca abre nada sin que el jugador confirme |
| `media` | cliente | `sam.media.capture(fn)` y `sam.media.pick(fn)` sacan una captura o eligen un archivo, la suben y llaman `fn(id)` (o `fn(nil, motivo)`). `sam.media.fetch(id, fn)` la descarga. En las pantallas, el widget `{type = "media", id, w, h}` la muestra |
| `media` | servidor | `sam.media.share(id, de, para)` deja que `para` descargue una imagen que subió `de`. Solo vale si `de` es el dueño de la imagen |

Reglas de las imágenes (RN-29):

- **Captura**: cierra un momento la pantalla y la interfaz, toma un cuadro del juego y vuelve.
- **Archivo**: se elige con el selector de archivos del sistema, que abre SAM y no el script. Acepta solo PNG o JPG de hasta 8 MiB. Lua nunca ve la ruta ni el archivo, solo un id.
- **Proceso en el cliente**: se decodifica con `NativeImage` de vanilla, se reduce a 512×512 como mucho y se recodifica como PNG de hasta 256 KiB. Si no entra, se reduce más.
- **Topes**: 5 imágenes por minuto por jugador. El servidor las guarda **en memoria**, con un total de 64 MiB (las más viejas salen primero) y hasta 1 hora. Cada imagen solo la descarga quien la subió o a quien se le compartió.
- **Al recibirla**: el cliente vuelve a validar la firma PNG, el IHDR y los topes antes de decodificar. Se libera de la GPU al salir del servidor.

Mensajes nuevos de la fase play (5.7):

```
C → S  sam:media_up        upload: VarInt, index: VarInt, total: VarInt, data: bytes ≤ 32 KiB     (≤ 256 KiB en total)
S → C  sam:media_ready     upload: VarInt, media: bytes[16]                (o media_failed con el motivo)
C → S  sam:media_get       media: bytes[16]
S → C  sam:media_down      media: bytes[16], index, total, data ≤ 32 KiB   (o media_failed)
S → C  sam:media_failed    upload_or_media: bytes ≤ 16, reason: String ≤ 128
```

El id de una imagen son 16 bytes aleatorios, no un contador. Un `media_get` de algo que no existe o que no se te compartió recibe `media_failed`, el mismo para los dos casos, para no revelar si existe.

## Orden de trabajo

1. API `menu` (el menú desplegable en el inventario). **Hecho** (PROTOCOLO.md 8.3).
2. API `links`. **Hecho** (PROTOCOLO.md 8.3).
3. API `media`: protocolo, almacén en memoria con topes, captura, selector de archivos, widget.
4. El plugin en Lua (servidor y cliente) y sus pruebas de punta a punta.
