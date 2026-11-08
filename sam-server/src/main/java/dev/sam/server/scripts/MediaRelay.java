package dev.sam.server.scripts;

import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.HashMap;
import java.util.HexFormat;
import java.util.Map;
import java.util.UUID;
import java.util.function.Consumer;

import org.slf4j.Logger;

import dev.sam.common.media.MediaMessages;
import dev.sam.common.media.MediaStore;
import dev.sam.common.proto.ProtocolException;
import dev.sam.common.proto.SamReader;
import dev.sam.common.proto.SamWriter;
import dev.sam.server.auth.SamPayload;
import io.netty.buffer.ByteBufUtil;
import io.netty.buffer.Unpooled;
import net.fabricmc.fabric.api.networking.v1.PayloadTypeRegistry;
import net.fabricmc.fabric.api.networking.v1.ServerPlayConnectionEvents;
import net.fabricmc.fabric.api.networking.v1.ServerPlayNetworking;
import net.minecraft.network.chat.Component;
import net.minecraft.network.protocol.common.custom.CustomPacketPayload;
import net.minecraft.server.level.ServerPlayer;

/**
 * Las imágenes de los jugadores en el servidor (capacidad {@code media}, docs/plugins/sam-mensajes.md):
 * recibe las subidas en fragmentos, las guarda en memoria ({@link MediaStore}) y las entrega solo a quien
 * puede verlas. Todo corre en el hilo del servidor.
 */
final class MediaRelay {

    static final CustomPacketPayload.Type<SamPayload> UP = SamPayload.type(MediaMessages.Up.ID_NAME);
    static final CustomPacketPayload.Type<SamPayload> READY = SamPayload.type(MediaMessages.Ready.ID_NAME);
    static final CustomPacketPayload.Type<SamPayload> GET = SamPayload.type(MediaMessages.Get.ID_NAME);
    static final CustomPacketPayload.Type<SamPayload> DOWN = SamPayload.type(MediaMessages.Down.ID_NAME);
    static final CustomPacketPayload.Type<SamPayload> FAILED = SamPayload.type(MediaMessages.Failed.ID_NAME);
    /** Para una descarga, el mismo motivo exista o no la imagen. */
    static final String NOT_AVAILABLE = "imagen no disponible";
    private static final int MAX_UPLOADS = 2;

    private final Logger log;
    private final MediaStore store = new MediaStore(new SecureRandom(), MediaStore.CAPACITY);
    private final Map<UUID, Map<Integer, MediaMessages.Assembly>> uploads = new HashMap<>();

    MediaRelay(Logger log) {
        this.log = log;
    }

    void install() {
        PayloadTypeRegistry.playC2S().register(UP, SamPayload.codec(UP, MediaMessages.Up.MAX_BYTES));
        PayloadTypeRegistry.playC2S().register(GET, SamPayload.codec(GET, MediaMessages.Get.MAX_BYTES));
        PayloadTypeRegistry.playS2C().register(READY, SamPayload.codec(READY, 64));
        PayloadTypeRegistry.playS2C().register(DOWN, SamPayload.codec(DOWN, MediaMessages.Down.MAX_BYTES));
        PayloadTypeRegistry.playS2C().register(FAILED, SamPayload.codec(FAILED, 512));
        ServerPlayNetworking.registerGlobalReceiver(UP, (payload, context) -> {
            var player = context.player();
            player.server.execute(() -> guarded(player, () -> onUp(player,
                SamReader.decode(Unpooled.wrappedBuffer(payload.data()), MediaMessages.Up.MAX_BYTES, MediaMessages.Up::read))));
        });
        ServerPlayNetworking.registerGlobalReceiver(GET, (payload, context) -> {
            var player = context.player();
            player.server.execute(() -> guarded(player, () -> onGet(player,
                SamReader.decode(Unpooled.wrappedBuffer(payload.data()), MediaMessages.Get.MAX_BYTES, MediaMessages.Get::read))));
        });
        ServerPlayConnectionEvents.DISCONNECT.register((handler, server) -> {
            var id = handler.getPlayer().getUUID();
            server.execute(() -> uploads.remove(id));
        });
    }

    /** {@code sam.media.share}: solo si {@code from} es el dueño. */
    boolean share(String id, String from, String to) {
        return store.share(HexFormat.of().parseHex(id), from, to, Instant.now().getEpochSecond());
    }

    private void onUp(ServerPlayer player, MediaMessages.Up up) {
        var mine = uploads.computeIfAbsent(player.getUUID(), k -> new HashMap<>());
        if (!mine.containsKey(up.upload()) && mine.size() >= MAX_UPLOADS) {
            send(player, FAILED, new MediaMessages.Failed(upload(up.upload()), "demasiadas imágenes subiendo a la vez")::write);
            return;
        }
        var assembly = mine.computeIfAbsent(up.upload(), k -> new MediaMessages.Assembly());
        var complete = assembly.accept(up.index(), up.total(), up.data());
        if (complete.isEmpty()) {
            return;
        }
        mine.remove(up.upload());
        var nick = player.getGameProfile().getName();
        try {
            var id = store.put(nick, complete.get(), Instant.now().getEpochSecond());
            log.info("{} subió una imagen de {} KiB", nick, complete.get().length / 1024);
            send(player, READY, new MediaMessages.Ready(up.upload(), id)::write);
        } catch (IllegalArgumentException e) {
            send(player, FAILED, new MediaMessages.Failed(upload(up.upload()), e.getMessage())::write);
        }
    }

    private void onGet(ServerPlayer player, MediaMessages.Get get) {
        var png = store.get(get.media(), player.getGameProfile().getName(), Instant.now().getEpochSecond());
        if (png.isEmpty()) {
            send(player, FAILED, new MediaMessages.Failed(get.media(), NOT_AVAILABLE)::write);
            return;
        }
        var chunks = MediaMessages.chunks(png.get());
        for (var i = 0; i < chunks.size(); i++) {
            send(player, DOWN, new MediaMessages.Down(get.media(), i, chunks.size(), chunks.get(i))::write);
        }
    }

    /** El número de una subida en {@code media_failed}: 4 bytes big-endian (un id de imagen mide 16). */
    static byte[] upload(int upload) {
        return ByteBuffer.allocate(4).putInt(upload).array();
    }

    private void guarded(ServerPlayer player, Runnable action) {
        try {
            action.run();
        } catch (ProtocolException e) {
            dev.sam.server.SamAudit.event("protocolo.error", player.getGameProfile().getName(), "", "imágenes: " + e.code() + " (" + e.getMessage() + ")");
            uploads.remove(player.getUUID());
            player.connection.disconnect(Component.literal("Error de protocolo. [" + e.code() + "]"));
        }
    }

    private static void send(ServerPlayer player, CustomPacketPayload.Type<SamPayload> type, Consumer<SamWriter> message) {
        var buf = Unpooled.buffer();
        message.accept(new SamWriter(buf));
        ServerPlayNetworking.send(player, new SamPayload(type, ByteBufUtil.getBytes(buf)));
    }
}
