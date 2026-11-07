package dev.sam.client.scripts;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Properties;
import java.util.function.Consumer;

import org.slf4j.Logger;

import dev.sam.client.mixin.ClientCommonPacketListenerAccessor;
import dev.sam.client.net.SamClientNet;
import dev.sam.client.net.SamPayload;
import dev.sam.common.proto.ProtocolException;
import dev.sam.common.proto.SamReader;
import dev.sam.common.proto.SamWriter;
import dev.sam.common.proto.scripts.ScriptChunk;
import dev.sam.common.proto.scripts.ScriptsConsent;
import dev.sam.common.proto.scripts.ScriptsOffer;
import dev.sam.common.proto.scripts.ScriptsWant;
import dev.sam.common.scripts.ClientDelivery;
import dev.sam.common.scripts.ScriptCache;
import io.netty.buffer.ByteBufUtil;
import io.netty.buffer.Unpooled;
import net.fabricmc.fabric.api.client.networking.v1.ClientConfigurationNetworking;
import net.fabricmc.fabric.api.client.networking.v1.ClientPlayConnectionEvents;
import net.fabricmc.fabric.api.networking.v1.PacketSender;
import net.fabricmc.fabric.api.networking.v1.PayloadTypeRegistry;
import net.minecraft.client.Minecraft;
import net.minecraft.network.Connection;
import net.minecraft.network.chat.Component;
import net.minecraft.network.protocol.common.custom.CustomPacketPayload;

/**
 * Los scripts de cliente (PROTOCOLO.md 5.5, RF-LUA-05): recibe la oferta en la configuration, verifica la
 * keylist con la identidad fijada, descarga lo que no está en caché y abre la pantalla de consentimiento.
 * Lo aceptado vive solo mientras dura la conexión (RF-LUA-09b).
 */
public final class SamClientScripts {

    public static final CustomPacketPayload.Type<SamPayload> OFFER = SamPayload.type(ScriptsOffer.ID);
    public static final CustomPacketPayload.Type<SamPayload> CHUNK = SamPayload.type(ScriptChunk.ID);
    public static final CustomPacketPayload.Type<SamPayload> WANT = SamPayload.type(ScriptsWant.ID);
    public static final CustomPacketPayload.Type<SamPayload> CONSENT = SamPayload.type(ScriptsConsent.ID);

    private static Logger log;
    private static ScriptCache cache;
    private static boolean enabled;
    private static ClientDelivery delivery;
    private static Connection connection;
    /** Lo que el jugador aceptó en esta conexión. */
    private static volatile List<ClientDelivery.Ready> accepted = List.of();

    private SamClientScripts() {
    }

    /** @param settings {@code config/sam-client/scripts.properties}: {@code enabled=false} los rechaza todos (RS-LUA-05) */
    public static void install(Logger logger, Path cacheDir, Path settings) {
        log = logger;
        cache = new ScriptCache(cacheDir);
        enabled = enabled(settings);
        PayloadTypeRegistry.configurationS2C().register(OFFER, SamPayload.codec(OFFER, ScriptsOffer.MAX_BYTES));
        PayloadTypeRegistry.configurationS2C().register(CHUNK, SamPayload.codec(CHUNK, ScriptChunk.MAX_BYTES));
        PayloadTypeRegistry.configurationC2S().register(WANT, SamPayload.codec(WANT, ScriptsWant.MAX_BYTES));
        PayloadTypeRegistry.configurationC2S().register(CONSENT, SamPayload.codec(CONSENT, ScriptsConsent.MAX_BYTES));
        // Los receptores corren en el hilo de red; la entrega se atiende entera en el hilo del juego
        ClientConfigurationNetworking.registerGlobalReceiver(OFFER, (payload, context) -> context.client().execute(() -> {
            var sender = context.responseSender();
            try {
                var offer = SamReader.decode(Unpooled.wrappedBuffer(payload.data()), ScriptsOffer.MAX_BYTES, ScriptsOffer::read);
                var pinned = SamClientNet.lastVerifiedKey()
                    .orElseThrow(() -> new ProtocolException(ProtocolException.OUT_OF_STATE, "oferta de scripts sin servidor verificado"));
                accepted = List.of();
                connection = ((ClientCommonPacketListenerAccessor) context.networkHandler()).sam$connection();
                delivery = ClientDelivery.open(offer, pinned, cache);
                log.info("Scripts del servidor: {} ofrecidos, {} en caché", offer.scripts().size(), delivery.ready().size());
                sender.sendPacket(new SamPayload(WANT, encode(delivery.want()::write)));
                whenComplete(context.client(), sender);
            } catch (ProtocolException e) {
                protocolError(sender, e);
            }
        }));
        ClientConfigurationNetworking.registerGlobalReceiver(CHUNK, (payload, context) -> context.client().execute(() -> {
            var sender = context.responseSender();
            try {
                if (delivery == null) {
                    throw new ProtocolException(ProtocolException.OUT_OF_STATE, "fragmento sin oferta de scripts");
                }
                delivery.chunk(SamReader.decode(Unpooled.wrappedBuffer(payload.data()), ScriptChunk.MAX_BYTES, ScriptChunk::read));
                whenComplete(context.client(), sender);
            } catch (ProtocolException e) {
                protocolError(sender, e);
            }
        }));
        new ClientScriptRuntime(logger).install();
        ClientPlayConnectionEvents.DISCONNECT.register((handler, client) -> forget());
        net.fabricmc.fabric.api.client.networking.v1.ClientConfigurationConnectionEvents.DISCONNECT
            .register((handler, client) -> forget());
    }

    /** Los scripts aceptados en la conexión actual. */
    public static List<ClientDelivery.Ready> accepted() {
        return accepted;
    }

    /** Con todo descargado y verificado, el consentimiento (o el rechazo directo si el jugador los desactivó). */
    private static void whenComplete(Minecraft client, PacketSender sender) {
        if (delivery == null || !delivery.complete()) {
            return;
        }
        var done = delivery;
        delivery = null;
        done.failed().forEach(f -> log.warn("Script {} del servidor rechazado: {}", f.id(), f.reason()));
        if (!enabled) {
            log.info("Scripts de servidor desactivados en scripts.properties: se rechazan todos");
            consent(sender, List.of());
            return;
        }
        client.setScreen(new ScriptConsentScreen(done.ready(), done.failed(), sender, connection));
    }

    /** La respuesta del jugador (la manda la pantalla de consentimiento). */
    static void consent(PacketSender sender, List<ClientDelivery.Ready> chosen) {
        accepted = List.copyOf(chosen);
        var ids = chosen.stream().map(r -> r.script().manifest().id()).toList();
        log.info("Scripts del servidor aceptados: {}", ids);
        sender.sendPacket(new SamPayload(CONSENT, encode(new ScriptsConsent(ids)::write)));
    }

    private static void forget() {
        delivery = null;
        connection = null;
        accepted = List.of();
    }

    private static void protocolError(PacketSender sender, ProtocolException e) {
        log.error("Entrega de scripts inválida del servidor: {} ({})", e.code(), e.getMessage());
        forget();
        sender.disconnect(Component.literal("Error de protocolo. [" + e.code() + "]"));
    }

    private static boolean enabled(Path settings) {
        var properties = new Properties();
        try {
            if (!Files.exists(settings)) {
                Files.createDirectories(settings.getParent());
                Files.writeString(settings, "# Scripts que envían los servidores con SAM (RS-LUA-05).\n"
                    + "# false: se rechazan todos sin preguntar (en algunos servidores no podrás entrar).\nenabled=true\n");
            }
            try (var in = Files.newBufferedReader(settings)) {
                properties.load(in);
            }
        } catch (IOException e) {
            log.warn("No se pudo leer {}: {}. Los scripts quedan activos (con consentimiento).", settings, e.getMessage());
        }
        return !properties.getProperty("enabled", "true").strip().equalsIgnoreCase("false");
    }

    private static byte[] encode(Consumer<SamWriter> message) {
        var buf = Unpooled.buffer();
        message.accept(new SamWriter(buf));
        return ByteBufUtil.getBytes(buf);
    }
}
