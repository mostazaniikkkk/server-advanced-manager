package dev.sam.client.scripts;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.function.Consumer;

import org.lwjgl.system.MemoryStack;
import org.lwjgl.util.tinyfd.TinyFileDialogs;
import org.slf4j.Logger;

import com.mojang.blaze3d.platform.NativeImage;

import dev.sam.client.net.SamPayload;
import dev.sam.common.lua.PngInfo;
import dev.sam.common.media.MediaMessages;
import dev.sam.common.media.MediaStore;
import dev.sam.common.proto.ProtocolException;
import dev.sam.common.proto.SamReader;
import dev.sam.common.proto.SamWriter;
import io.netty.buffer.ByteBufUtil;
import io.netty.buffer.Unpooled;
import net.fabricmc.fabric.api.client.networking.v1.ClientPlayNetworking;
import net.fabricmc.fabric.api.networking.v1.PayloadTypeRegistry;
import net.minecraft.client.Minecraft;
import net.minecraft.client.Screenshot;
import net.minecraft.network.chat.Component;
import net.minecraft.network.protocol.common.custom.CustomPacketPayload;

/**
 * Las imágenes de los scripts en el cliente (capacidad {@code media}, docs/plugins/sam-mensajes.md): captura
 * del juego sin la interfaz o archivo elegido con el selector del sistema; se reduce a 512×512 y PNG de hasta
 * 256 KiB, se sube y el script recibe el id. Las descargas son a pedido y se validan antes de decodificar
 * (RN-29). Lua nunca ve rutas ni bytes.
 */
final class MediaClient {

    static final CustomPacketPayload.Type<SamPayload> UP = SamPayload.type(MediaMessages.Up.ID_NAME);
    static final CustomPacketPayload.Type<SamPayload> READY = SamPayload.type(MediaMessages.Ready.ID_NAME);
    static final CustomPacketPayload.Type<SamPayload> GET = SamPayload.type(MediaMessages.Get.ID_NAME);
    static final CustomPacketPayload.Type<SamPayload> DOWN = SamPayload.type(MediaMessages.Down.ID_NAME);
    static final CustomPacketPayload.Type<SamPayload> FAILED = SamPayload.type(MediaMessages.Failed.ID_NAME);
    private static final long MAX_FILE = 8L * 1024 * 1024;

    /** Quién espera una subida o una descarga: el script y su número de pedido. */
    private record Waiter(String script, int request) {
    }

    /** Lo que se hace con un resultado: (script, pedido, id, motivo). */
    interface Results {
        void deliver(String script, int request, Optional<String> id, Optional<String> error);
    }

    private final Logger log;
    private final Results results;
    private final Map<Integer, Waiter> uploads = new HashMap<>();
    private final Map<String, List<Waiter>> downloads = new HashMap<>();
    private final Map<String, MediaMessages.Assembly> incoming = new HashMap<>();
    /** Las imágenes ya disponibles en esta conexión (las propias y las descargadas), por id. */
    private final Map<String, byte[]> cache = new HashMap<>();
    private int nextUpload = 1;

    MediaClient(Logger log, Results results) {
        this.log = log;
        this.results = results;
    }

    void install() {
        PayloadTypeRegistry.playC2S().register(UP, SamPayload.codec(UP, MediaMessages.Up.MAX_BYTES));
        PayloadTypeRegistry.playC2S().register(GET, SamPayload.codec(GET, MediaMessages.Get.MAX_BYTES));
        PayloadTypeRegistry.playS2C().register(READY, SamPayload.codec(READY, 64));
        PayloadTypeRegistry.playS2C().register(DOWN, SamPayload.codec(DOWN, MediaMessages.Down.MAX_BYTES));
        PayloadTypeRegistry.playS2C().register(FAILED, SamPayload.codec(FAILED, 512));
        ClientPlayNetworking.registerGlobalReceiver(READY, (payload, context) -> context.client().execute(() -> guarded(() ->
            onReady(SamReader.decode(Unpooled.wrappedBuffer(payload.data()), 64, MediaMessages.Ready::read)))));
        ClientPlayNetworking.registerGlobalReceiver(DOWN, (payload, context) -> context.client().execute(() -> guarded(() ->
            onDown(SamReader.decode(Unpooled.wrappedBuffer(payload.data()), MediaMessages.Down.MAX_BYTES, MediaMessages.Down::read)))));
        ClientPlayNetworking.registerGlobalReceiver(FAILED, (payload, context) -> context.client().execute(() -> guarded(() ->
            onFailed(SamReader.decode(Unpooled.wrappedBuffer(payload.data()), 512, MediaMessages.Failed::read)))));
    }

    /** Al salir del servidor: nada queda. */
    void clear() {
        delayed.clear();
        pendingPng.clear();
        uploads.clear();
        downloads.clear();
        incoming.clear();
        cache.clear();
    }

    Optional<byte[]> cached(String id) {
        return Optional.ofNullable(cache.get(id));
    }

    // ===== Subir =====

    /** Una captura del juego: cierra un momento la pantalla y la interfaz, toma un cuadro y vuelve. */
    void capture(String script, int request) {
        var minecraft = Minecraft.getInstance();
        var previous = minecraft.screen;
        if (previous instanceof ScriptScreen own) {
            own.coveredByChild();
        }
        var hidden = minecraft.options.hideGui;
        minecraft.setScreen(null);
        minecraft.options.hideGui = true;
        // Dos ticks para que se dibuje al menos un cuadro sin la interfaz
        later(minecraft, 2, () -> {
            NativeImage frame;
            try {
                frame = Screenshot.takeScreenshot(minecraft.getMainRenderTarget());
            } finally {
                minecraft.options.hideGui = hidden;
                minecraft.setScreen(previous);
            }
            upload(script, request, frame);
        });
    }

    /** Un archivo elegido con el selector del sistema (solo PNG o JPG); el script nunca ve la ruta. */
    void pick(String script, int request) {
        var minecraft = Minecraft.getInstance();
        var thread = new Thread(() -> {
            String chosen;
            try (var stack = MemoryStack.stackPush()) {
                var filters = stack.mallocPointer(3);
                filters.put(stack.UTF8("*.png")).put(stack.UTF8("*.jpg")).put(stack.UTF8("*.jpeg")).flip();
                chosen = TinyFileDialogs.tinyfd_openFileDialog("Elige una imagen para enviar", "", filters, "Imágenes (PNG o JPG)", false);
            }
            if (chosen == null) {
                minecraft.execute(() -> results.deliver(script, request, Optional.empty(), Optional.of("cancelado")));
                return;
            }
            try {
                var path = Path.of(chosen);
                if (Files.size(path) > MAX_FILE) {
                    throw new IOException("el archivo supera los 8 MiB");
                }
                var bytes = Files.readAllBytes(path);
                minecraft.execute(() -> {
                    try {
                        upload(script, request, NativeImage.read(new java.io.ByteArrayInputStream(bytes)));
                    } catch (IOException e) {
                        results.deliver(script, request, Optional.empty(), Optional.of("no es una imagen PNG o JPG válida"));
                    }
                });
            } catch (IOException | RuntimeException e) {
                minecraft.execute(() -> results.deliver(script, request, Optional.empty(), Optional.of("no se pudo leer: " + e.getMessage())));
            }
        }, "SAM elegir imagen");
        thread.setDaemon(true);
        thread.start();
    }

    /** Reduce a 512×512 como mucho, re-codifica como PNG de hasta 256 KiB (achicando si hace falta) y la sube. */
    private void upload(String script, int request, NativeImage image) {
        byte[] png;
        try (image) {
            png = shrink(image);
        } catch (IOException | IllegalArgumentException e) {
            results.deliver(script, request, Optional.empty(), Optional.of("no se pudo preparar la imagen: " + e.getMessage()));
            return;
        }
        var upload = nextUpload++;
        uploads.put(upload, new Waiter(script, request));
        pendingPng.put(upload, png);
        var chunks = MediaMessages.chunks(png);
        for (var i = 0; i < chunks.size(); i++) {
            send(UP, new MediaMessages.Up(upload, i, chunks.size(), chunks.get(i))::write);
        }
    }

    /** Lo que se subió, para tenerlo sin descargarlo cuando llegue su id. */
    private final Map<Integer, byte[]> pendingPng = new HashMap<>();

    static byte[] shrink(NativeImage image) throws IOException {
        var side = MediaStore.MAX_SIDE;
        while (true) {
            var scale = Math.min(1.0, (double) side / Math.max(image.getWidth(), image.getHeight()));
            var width = Math.max(1, (int) Math.round(image.getWidth() * scale));
            var height = Math.max(1, (int) Math.round(image.getHeight() * scale));
            byte[] png;
            try (var resized = new NativeImage(width, height, false)) {
                image.resizeSubRectTo(0, 0, image.getWidth(), image.getHeight(), resized);
                png = resized.asByteArray();
            }
            if (png.length <= MediaStore.MAX_BYTES) {
                return png;
            }
            if (side <= 32) {
                throw new IllegalArgumentException("la imagen no entra en 256 KiB");
            }
            side = side * 3 / 4;
        }
    }

    private void onReady(MediaMessages.Ready ready) {
        var waiter = uploads.remove(ready.upload());
        var png = pendingPng.remove(ready.upload());
        if (waiter == null) {
            throw new ProtocolException(ProtocolException.OUT_OF_STATE, "media_ready de una subida que no existe");
        }
        var id = HexFormat.of().formatHex(ready.media());
        cache.put(id, png);
        results.deliver(waiter.script(), waiter.request(), Optional.of(id), Optional.empty());
    }

    // ===== Descargar =====

    /** Descarga a pedido; si ya está, responde en el próximo paso. */
    void fetch(String script, int request, String id) {
        var minecraft = Minecraft.getInstance();
        if (cache.containsKey(id)) {
            minecraft.tell(() -> results.deliver(script, request, Optional.of(id), Optional.empty()));
            return;
        }
        var waiting = downloads.computeIfAbsent(id, k -> new ArrayList<>());
        waiting.add(new Waiter(script, request));
        if (waiting.size() == 1) {
            send(GET, new MediaMessages.Get(HexFormat.of().parseHex(id))::write);
        }
    }

    private void onDown(MediaMessages.Down down) {
        var id = HexFormat.of().formatHex(down.media());
        if (!downloads.containsKey(id)) {
            throw new ProtocolException(ProtocolException.OUT_OF_STATE, "media_down de una imagen que no se pidió");
        }
        var complete = incoming.computeIfAbsent(id, k -> new MediaMessages.Assembly()).accept(down.index(), down.total(), down.data());
        if (complete.isEmpty()) {
            return;
        }
        incoming.remove(id);
        var waiting = downloads.remove(id);
        try {
            // RN-29: firma, IHDR y topes antes de que NativeImage la decodifique al dibujarla
            PngInfo.check(complete.get(), MediaStore.MAX_BYTES, MediaStore.MAX_SIDE);
            cache.put(id, complete.get());
            waiting.forEach(w -> results.deliver(w.script(), w.request(), Optional.of(id), Optional.empty()));
        } catch (IllegalArgumentException e) {
            log.warn("Imagen {} inválida del servidor: {}", id, e.getMessage());
            waiting.forEach(w -> results.deliver(w.script(), w.request(), Optional.empty(), Optional.of("imagen inválida")));
        }
    }

    private void onFailed(MediaMessages.Failed failed) {
        var ref = failed.ref();
        if (ref.length == 16) {
            var id = HexFormat.of().formatHex(ref);
            incoming.remove(id);
            var waiting = downloads.remove(id);
            if (waiting != null) {
                waiting.forEach(w -> results.deliver(w.script(), w.request(), Optional.empty(), Optional.of(failed.reason())));
            }
            return;
        }
        var upload = ref.length == 4 ? ByteBuffer.wrap(ref).getInt() : -1;
        var waiter = uploads.remove(upload);
        pendingPng.remove(upload);
        if (waiter != null) {
            results.deliver(waiter.script(), waiter.request(), Optional.empty(), Optional.of(failed.reason()));
        }
    }

    // ===== Utilidades =====

    private void guarded(Runnable action) {
        try {
            action.run();
        } catch (ProtocolException e) {
            log.error("Mensaje de imágenes inválido del servidor: {}", e.getMessage());
            var connection = Minecraft.getInstance().getConnection();
            if (connection != null) {
                connection.getConnection().disconnect(Component.literal("Error de protocolo. [" + e.code() + "]"));
            }
        }
    }

    private static void send(CustomPacketPayload.Type<SamPayload> type, Consumer<SamWriter> message) {
        var buf = Unpooled.buffer();
        message.accept(new SamWriter(buf));
        ClientPlayNetworking.send(new SamPayload(type, ByteBufUtil.getBytes(buf)));
    }

    /** Lo que espera ticks del cliente (entre tick y tick se dibujan cuadros). */
    private final List<Object[]> delayed = new ArrayList<>();

    /** Ejecuta {@code action} en el hilo del juego después de {@code ticks} ticks del cliente. */
    private void later(Minecraft minecraft, int ticks, Runnable action) {
        delayed.add(new Object[] {ticks, action});
    }

    /** Lo llama el runtime en cada tick del cliente (aunque haya una pantalla de SAM abierta). */
    void tick() {
        var due = new ArrayList<Runnable>();
        var it = delayed.iterator();
        while (it.hasNext()) {
            var entry = it.next();
            var left = (int) entry[0] - 1;
            if (left <= 0) {
                it.remove();
                due.add((Runnable) entry[1]);
            } else {
                entry[0] = left;
            }
        }
        due.forEach(Runnable::run);
    }
}
