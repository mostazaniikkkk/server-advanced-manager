package dev.sam.server.scripts;

import java.security.PrivateKey;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.function.Consumer;
import java.util.function.Function;

import org.slf4j.Logger;

import dev.sam.common.proto.ProtocolException;
import dev.sam.common.proto.SamReader;
import dev.sam.common.proto.SamWriter;
import dev.sam.common.proto.scripts.ScriptChunk;
import dev.sam.common.proto.scripts.ScriptsConsent;
import dev.sam.common.proto.scripts.ScriptsOffer;
import dev.sam.common.proto.scripts.ScriptsWant;
import dev.sam.common.scripts.KeyList;
import dev.sam.common.scripts.ScriptCatalog;
import dev.sam.common.scripts.ServerDelivery;
import dev.sam.server.auth.SamAuth;
import dev.sam.server.auth.SamPayload;
import io.netty.buffer.ByteBufUtil;
import io.netty.buffer.Unpooled;
import net.fabricmc.fabric.api.networking.v1.PayloadTypeRegistry;
import net.fabricmc.fabric.api.networking.v1.ServerConfigurationConnectionEvents;
import net.fabricmc.fabric.api.networking.v1.ServerConfigurationNetworking;
import net.minecraft.network.chat.Component;
import net.minecraft.network.protocol.Packet;
import net.minecraft.network.protocol.common.custom.CustomPacketPayload;
import net.minecraft.server.MinecraftServer;
import net.minecraft.server.network.ConfigurationTask;
import net.minecraft.server.network.ServerConfigurationPacketListenerImpl;

/**
 * La tarea de configuration {@code sam:scripts} (PROTOCOLO.md 5.5, RF-LUA-05): después del login, ofrece los
 * scripts de cliente con la keylist firmada por la identidad del servidor, manda lo que el cliente pide y
 * aplica {@code SAM_SCRIPTS_CLIENT_ON_REJECT} al consentimiento. Sin scripts de cliente no hay tarea.
 */
final class ClientScriptsDelivery {

    static final CustomPacketPayload.Type<SamPayload> OFFER = SamPayload.type(ScriptsOffer.ID);
    static final CustomPacketPayload.Type<SamPayload> CHUNK = SamPayload.type(ScriptChunk.ID);
    static final CustomPacketPayload.Type<SamPayload> WANT = SamPayload.type(ScriptsWant.ID);
    static final CustomPacketPayload.Type<SamPayload> CONSENT = SamPayload.type(ScriptsConsent.ID);
    static final ConfigurationTask.Type TASK = new ConfigurationTask.Type("sam:scripts");
    /** El jugador está leyendo la pantalla de consentimiento. */
    static final int TIMEOUT_SECONDS = 300;

    private final Logger log;
    private final ServerDelivery.OnReject policy;
    private final Map<ServerConfigurationPacketListenerImpl, ServerDelivery> sessions = new ConcurrentHashMap<>();
    /** Los scripts que aceptó cada jugador conectado (por nick): solo con ellos hay {@code sam:lua_msg}. */
    private final Map<String, java.util.Set<String>> accepted = new ConcurrentHashMap<>();
    private final ScheduledExecutorService timer = Executors.newSingleThreadScheduledExecutor(runnable -> {
        var thread = new Thread(runnable, "SAM scripts timeout");
        thread.setDaemon(true);
        return thread;
    });
    private volatile PrivateKey identity;
    private volatile List<ScriptCatalog.ClientScript> scripts = List.of();
    private volatile List<KeyList.Entry> keys = List.of();
    private volatile Optional<ServerDelivery.Catalog> catalog = Optional.empty();

    ClientScriptsDelivery(Logger log, ServerDelivery.OnReject policy) {
        this.log = log;
        this.policy = policy;
    }

    /** Payloads y eventos; se llama después de instalar el login, así esta tarea va detrás de {@code sam:auth}. */
    void install() {
        PayloadTypeRegistry.configurationS2C().register(OFFER, SamPayload.codec(OFFER, ScriptsOffer.MAX_BYTES));
        PayloadTypeRegistry.configurationS2C().register(CHUNK, SamPayload.codec(CHUNK, ScriptChunk.MAX_BYTES));
        PayloadTypeRegistry.configurationC2S().register(WANT, SamPayload.codec(WANT, ScriptsWant.MAX_BYTES));
        PayloadTypeRegistry.configurationC2S().register(CONSENT, SamPayload.codec(CONSENT, ScriptsConsent.MAX_BYTES));
        ServerConfigurationConnectionEvents.CONFIGURE.register(this::configure);
        ServerConfigurationConnectionEvents.DISCONNECT.register((handler, server) -> sessions.remove(handler));
        // Los receptores de configuration corren en el hilo de red: todo se atiende en el del servidor
        ServerConfigurationNetworking.registerGlobalReceiver(WANT, (payload, context) -> context.server().execute(() ->
            receive(context.networkHandler(), payload, ScriptsWant.MAX_BYTES, ScriptsWant::read, (handler, session, want) ->
                session.onWant(want).forEach(chunk -> ServerConfigurationNetworking.send(handler,
                    new SamPayload(CHUNK, encode(chunk::write)))))));
        ServerConfigurationNetworking.registerGlobalReceiver(CONSENT, (payload, context) -> context.server().execute(() ->
            receive(context.networkHandler(), payload, ScriptsConsent.MAX_BYTES, ScriptsConsent::read, this::consent)));
    }

    /** La clave de la identidad del servidor: firma la keylist (RS-SIG-05). */
    void identity(PrivateKey key) {
        identity = key;
        rebuild();
    }

    /** Lo que quedó tras cada reload: los scripts de cliente verificados y las claves activas del trust store. */
    void update(List<ScriptCatalog.ClientScript> clientScripts, List<KeyList.Entry> activeKeys) {
        scripts = List.copyOf(clientScripts);
        keys = List.copyOf(activeKeys);
        rebuild();
    }

    int offered() {
        return catalog.map(c -> c.offer().scripts().size()).orElse(0);
    }

    private synchronized void rebuild() {
        var key = identity;
        var current = scripts;
        if (key == null || current.isEmpty()) {
            if (key == null && !current.isEmpty()) {
                log.warn("Hay {} scripts de cliente pero la identidad del servidor no está cargada: no se ofrecen", current.size());
            }
            catalog = Optional.empty();
            return;
        }
        try {
            catalog = Optional.of(ServerDelivery.Catalog.of(current, KeyList.issue(keys, key, Instant.now().getEpochSecond())));
        } catch (IllegalArgumentException e) {
            log.error("Los scripts de cliente no se ofrecen: {}", e.getMessage());
            catalog = Optional.empty();
        }
    }

    /** Si ese jugador aceptó ese script en su conexión actual. */
    boolean accepted(String nick, String script) {
        return accepted.getOrDefault(nick, java.util.Set.of()).contains(script);
    }

    /** Al salir del juego, lo aceptado deja de valer. */
    void forget(String nick) {
        accepted.remove(nick);
    }

    private void configure(ServerConfigurationPacketListenerImpl handler, MinecraftServer server) {
        // Una conexión nueva empieza sin scripts aceptados
        accepted.remove(handler.getOwner().getName());
        var offer = catalog;
        if (offer.isEmpty()) {
            return;
        }
        if (!ServerConfigurationNetworking.canSend(handler, OFFER)) {
            // Un cliente sin entrega de scripts los rechaza todos
            var required = offer.get().offer().scripts().stream().anyMatch(r -> r.required());
            if (policy == ServerDelivery.OnReject.KICK || (policy == ServerDelivery.OnReject.PER_SCRIPT && required)) {
                handler.disconnect(Component.literal(ServerDelivery.KICK_REJECTED));
            }
            return;
        }
        handler.addTask(new Task(handler, server, offer.get()));
    }

    private final class Task implements ConfigurationTask {
        private final ServerConfigurationPacketListenerImpl handler;
        private final MinecraftServer server;
        private final ServerDelivery.Catalog offer;

        Task(ServerConfigurationPacketListenerImpl handler, MinecraftServer server, ServerDelivery.Catalog offer) {
            this.handler = handler;
            this.server = server;
            this.offer = offer;
        }

        @Override
        public void start(Consumer<Packet<?>> sender) {
            var session = new ServerDelivery(offer, policy);
            sessions.put(handler, session);
            sender.accept(ServerConfigurationNetworking.createS2CPacket(new SamPayload(OFFER, encode(offer.offer()::write))));
            timer.schedule(() -> server.execute(() -> {
                if (sessions.remove(handler, session)) {
                    log.info("[auditoría] {} no respondió a la oferta de scripts en {} s", handler.getOwner().getName(), TIMEOUT_SECONDS);
                    handler.disconnect(Component.literal(SamAuth.KICK_TIMEOUT));
                }
            }), TIMEOUT_SECONDS, TimeUnit.SECONDS);
        }

        @Override
        public Type type() {
            return TASK;
        }
    }

    @FunctionalInterface
    private interface Step<M> {
        void apply(ServerConfigurationPacketListenerImpl handler, ServerDelivery session, M message);
    }

    private <M> void receive(ServerConfigurationPacketListenerImpl handler, SamPayload payload, int max, Function<SamReader, M> reader,
            Step<M> step) {
        try {
            var session = sessions.get(handler);
            if (session == null) {
                throw new ProtocolException(ProtocolException.OUT_OF_STATE, "mensaje de scripts sin oferta en curso");
            }
            step.apply(handler, session, SamReader.decode(Unpooled.wrappedBuffer(payload.data()), max, reader));
        } catch (ProtocolException e) {
            log.warn("[auditoría] Error de protocolo de {}: {} ({})", handler.getOwner().getName(), e.code(), e.getMessage());
            sessions.remove(handler);
            handler.disconnect(Component.literal("Error de protocolo. [" + e.code() + "]"));
        }
    }

    private void consent(ServerConfigurationPacketListenerImpl handler, ServerDelivery session, ScriptsConsent consent) {
        var reply = session.onConsent(consent);
        var nick = handler.getOwner().getName();
        sessions.remove(handler);
        if (reply.kick().isPresent()) {
            log.info("[auditoría] {} rechazó scripts requeridos (aceptó {}): expulsado", nick, consent.accepted());
            handler.disconnect(Component.literal(reply.kick().get()));
            return;
        }
        log.info("[auditoría] {} aceptó los scripts {}", nick, reply.accepted());
        accepted.put(nick, java.util.Set.copyOf(reply.accepted()));
        handler.completeTask(TASK);
    }

    private static byte[] encode(Consumer<SamWriter> message) {
        var buf = Unpooled.buffer();
        message.accept(new SamWriter(buf));
        return ByteBufUtil.getBytes(buf);
    }
}
