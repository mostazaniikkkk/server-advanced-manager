package dev.sam.server.auth;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.function.Consumer;
import java.util.function.Function;

import org.slf4j.Logger;

import dev.sam.common.auth.AccountService;
import dev.sam.common.auth.LoginFlow;
import dev.sam.common.identity.ServerId;
import dev.sam.common.proto.ProtocolException;
import dev.sam.common.proto.SamReader;
import dev.sam.common.proto.SamWriter;
import dev.sam.common.proto.auth.AuthPolicyView;
import dev.sam.common.proto.auth.HelloAck;
import dev.sam.common.proto.auth.LoginPassword;
import dev.sam.common.proto.auth.Register;
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
 * La tarea de configuration {@code sam:auth} (PROTOCOLO.md 5): retiene al jugador hasta que se
 * registra o entra con su contraseña. Un cliente sin SAM se expulsa con SAM-K001; sin respuesta en
 * {@value #TIMEOUT_SECONDS} s, SAM-K003. Argon2 corre fuera del hilo del servidor.
 */
public final class SamAuth {

    public static final CustomPacketPayload.Type<SamPayload> HELLO = SamPayload.type("hello");
    public static final CustomPacketPayload.Type<SamPayload> AUTH_RESULT = SamPayload.type("auth_result");
    public static final CustomPacketPayload.Type<SamPayload> HELLO_ACK = SamPayload.type("hello_ack");
    public static final CustomPacketPayload.Type<SamPayload> REGISTER = SamPayload.type("register");
    public static final CustomPacketPayload.Type<SamPayload> LOGIN_PASSWORD = SamPayload.type("login_password");

    static final ConfigurationTask.Type TASK = new ConfigurationTask.Type("sam:auth");
    static final int TIMEOUT_SECONDS = 120;
    static final int MAX_ATTEMPTS = 5;
    private static final int MAX_SERVER_MESSAGE = 256 * 1024;

    public static final String KICK_NO_SAM = "Este servidor requiere SAM Client para entrar. [SAM-K001]";
    public static final String KICK_TIMEOUT = "Tiempo de espera agotado. [SAM-K003]";
    public static final String KICK_UNAVAILABLE = "Inicio de sesión no disponible. [SAM-K006]";

    /** Lo que se necesita para atender logins; hasta tenerlo, el login queda cerrado. */
    public record Setup(AccountService accounts, ServerId serverId, AuthPolicyView policy) {
    }

    private final Logger log;
    private final Map<ServerConfigurationPacketListenerImpl, LoginFlow> flows = new ConcurrentHashMap<>();
    private final ExecutorService hashing = Executors.newFixedThreadPool(2, daemon("SAM Argon2"));
    private final ScheduledExecutorService timer = Executors.newSingleThreadScheduledExecutor(daemon("SAM auth timeout"));
    private volatile Setup setup;

    public SamAuth(Logger log) {
        this.log = log;
    }

    /** Registra los payloads y los eventos; se llama una vez al iniciar el mod. */
    public void install() {
        PayloadTypeRegistry.configurationS2C().register(HELLO, SamPayload.codec(HELLO, MAX_SERVER_MESSAGE));
        PayloadTypeRegistry.configurationS2C().register(AUTH_RESULT, SamPayload.codec(AUTH_RESULT, MAX_SERVER_MESSAGE));
        PayloadTypeRegistry.configurationC2S().register(HELLO_ACK, SamPayload.codec(HELLO_ACK, HelloAck.MAX_BYTES));
        PayloadTypeRegistry.configurationC2S().register(REGISTER, SamPayload.codec(REGISTER, Register.MAX_BYTES));
        PayloadTypeRegistry.configurationC2S().register(LOGIN_PASSWORD, SamPayload.codec(LOGIN_PASSWORD, LoginPassword.MAX_BYTES));

        ServerConfigurationConnectionEvents.CONFIGURE.register(this::configure);
        ServerConfigurationConnectionEvents.DISCONNECT.register((handler, server) -> flows.remove(handler));
        ServerConfigurationNetworking.registerGlobalReceiver(HELLO_ACK,
            (payload, context) -> receive(context.networkHandler(), context.server(), payload, HelloAck.MAX_BYTES, HelloAck::read,
                LoginFlow::onHelloAck));
        ServerConfigurationNetworking.registerGlobalReceiver(REGISTER,
            (payload, context) -> receive(context.networkHandler(), context.server(), payload, Register.MAX_BYTES, Register::read,
                LoginFlow::onRegister));
        ServerConfigurationNetworking.registerGlobalReceiver(LOGIN_PASSWORD,
            (payload, context) -> receive(context.networkHandler(), context.server(), payload, LoginPassword.MAX_BYTES,
                LoginPassword::read, LoginFlow::onLogin));
    }

    /** Con cuentas e identidad cargadas, se atienden logins. */
    public void activate(Setup ready) {
        this.setup = ready;
    }

    private void configure(ServerConfigurationPacketListenerImpl handler, MinecraftServer server) {
        var ready = setup;
        if (ready == null) {
            handler.disconnect(Component.literal(KICK_UNAVAILABLE));
            return;
        }
        if (!ServerConfigurationNetworking.canSend(handler, HELLO)) {
            handler.disconnect(Component.literal(KICK_NO_SAM));
            return;
        }
        handler.addTask(new AuthTask(handler, server, ready));
    }

    private final class AuthTask implements ConfigurationTask {
        private final ServerConfigurationPacketListenerImpl handler;
        private final MinecraftServer server;
        private final Setup ready;

        AuthTask(ServerConfigurationPacketListenerImpl handler, MinecraftServer server, Setup ready) {
            this.handler = handler;
            this.server = server;
            this.ready = ready;
        }

        @Override
        public void start(Consumer<Packet<?>> sender) {
            var nick = handler.getOwner().getName();
            var flow = new LoginFlow(nick, ready.serverId(), serverName(server), ready.policy(), ready.accounts(), MAX_ATTEMPTS);
            flows.put(handler, flow);
            var hello = flow.hello();
            sender.accept(ServerConfigurationNetworking.createS2CPacket(new SamPayload(HELLO, encode(hello::write))));
            timer.schedule(() -> server.execute(() -> {
                if (flows.get(handler) == flow && !flow.done()) {
                    log.info("[auditoría] {} no completó el login en {} s", nick, TIMEOUT_SECONDS);
                    handler.disconnect(Component.literal(KICK_TIMEOUT));
                }
            }), TIMEOUT_SECONDS, TimeUnit.SECONDS);
        }

        @Override
        public Type type() {
            return TASK;
        }
    }

    private <M> void receive(ServerConfigurationPacketListenerImpl handler, MinecraftServer server, SamPayload payload,
            int max, Function<SamReader, M> reader, java.util.function.BiFunction<LoginFlow, M, LoginFlow.Reply> step) {
        var flow = flows.get(handler);
        var nick = handler.getOwner().getName();
        if (flow == null) {
            protocolError(handler, nick, new ProtocolException(ProtocolException.OUT_OF_STATE, "mensaje sin login en curso"));
            return;
        }
        M message;
        try {
            message = SamReader.decode(Unpooled.wrappedBuffer(payload.data()), max, reader);
        } catch (ProtocolException e) {
            protocolError(handler, nick, e);
            return;
        }
        // Argon2 fuera del hilo del servidor; la respuesta vuelve a él
        hashing.execute(() -> {
            LoginFlow.Reply reply;
            try {
                reply = step.apply(flow, message);
            } catch (ProtocolException e) {
                server.execute(() -> protocolError(handler, nick, e));
                return;
            } catch (RuntimeException e) {
                log.error("Error en el login de {}", nick, e);
                server.execute(() -> handler.disconnect(Component.literal(KICK_UNAVAILABLE)));
                return;
            }
            server.execute(() -> apply(handler, nick, flow, reply));
        });
    }

    private void apply(ServerConfigurationPacketListenerImpl handler, String nick, LoginFlow flow, LoginFlow.Reply reply) {
        if (flows.get(handler) != flow) {
            return;
        }
        reply.result().ifPresent(result -> ServerConfigurationNetworking.send(handler,
            new SamPayload(AUTH_RESULT, encode(result::write))));
        if (reply.kick().isPresent()) {
            log.info("[auditoría] {} expulsado: {}", nick, reply.kick().get());
            flows.remove(handler);
            handler.disconnect(Component.literal(reply.kick().get()));
        } else if (reply.done()) {
            log.info("[auditoría] {} completó el login de SAM", nick);
            flows.remove(handler);
            handler.completeTask(TASK);
        }
    }

    private void protocolError(ServerConfigurationPacketListenerImpl handler, String nick, ProtocolException e) {
        log.warn("[auditoría] Error de protocolo de {}: {} ({})", nick, e.code(), e.getMessage());
        flows.remove(handler);
        handler.disconnect(Component.literal("Error de protocolo. [" + e.code() + "]"));
    }

    private static byte[] encode(Consumer<SamWriter> message) {
        var buf = Unpooled.buffer();
        message.accept(new SamWriter(buf));
        return ByteBufUtil.getBytes(buf);
    }

    /** El MOTD acotado a 16 caracteres (≤ 64 bytes en UTF-8). */
    private static String serverName(MinecraftServer server) {
        var motd = server.getMotd().replaceAll("§.", "");
        return motd.codePoints().limit(16).collect(StringBuilder::new, StringBuilder::appendCodePoint, StringBuilder::append)
            .toString();
    }

    private static java.util.concurrent.ThreadFactory daemon(String name) {
        return runnable -> {
            var thread = new Thread(runnable, name);
            thread.setDaemon(true);
            return thread;
        };
    }
}
