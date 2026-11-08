package dev.sam.server.auth;

import java.util.Map;
import java.util.Optional;
import java.util.Set;
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
import dev.sam.common.oauth.OAuthStates;
import dev.sam.common.proto.account.OAuthCode;
import dev.sam.common.proto.account.OAuthProvider;
import dev.sam.common.proto.account.OAuthStart;
import dev.sam.common.proto.account.OAuthUrl;
import dev.sam.common.proto.auth.AuthResult;
import dev.sam.common.proto.auth.AuthPolicyView;
import dev.sam.common.proto.auth.HelloAck;
import dev.sam.common.proto.auth.LoginPassword;
import dev.sam.common.proto.auth.LoginTotp;
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
    public static final CustomPacketPayload.Type<SamPayload> OAUTH_START = SamPayload.type(OAuthStart.ID);
    public static final CustomPacketPayload.Type<SamPayload> OAUTH_URL = SamPayload.type(OAuthUrl.ID);
    public static final CustomPacketPayload.Type<SamPayload> OAUTH_CODE = SamPayload.type(OAuthCode.ID);
    public static final CustomPacketPayload.Type<SamPayload> LOGIN_TOTP = SamPayload.type(LoginTotp.ID);

    static final ConfigurationTask.Type TASK = new ConfigurationTask.Type("sam:auth");
    static final int TIMEOUT_SECONDS = 120;
    /** Mientras hay un flujo OAuth abierto (el jugador está en el navegador), PROTOCOLO.md 5. */
    static final int OAUTH_TIMEOUT_SECONDS = 300;
    static final int MAX_ATTEMPTS = 5;
    private static final int MAX_SERVER_MESSAGE = 256 * 1024;

    public static final String KICK_NO_SAM = "Este servidor requiere SAM Client para entrar. [SAM-K001]";
    public static final String KICK_TIMEOUT = "Tiempo de espera agotado. [SAM-K003]";
    public static final String KICK_UNAVAILABLE = "Inicio de sesión no disponible. [SAM-K006]";
    public static final String KICK_BUSY = "Servidor ocupado, reintenta en unos segundos. [SAM-K005]";
    /** Logins esperando Argon2 (RF-AUTH-06b): con la cola llena, la conexión se rechaza con SAM-K005. */
    private static final int HASH_QUEUE = 64;

    /** Lo que se necesita para atender logins; hasta tenerlo, el login queda cerrado. */
    public record Setup(AccountService accounts, ServerId serverId, AuthPolicyView policy, Optional<GoogleSignIn> google,
            dev.sam.common.auth.LoginThrottle throttle) {
    }

    private final Logger log;
    private final Map<ServerConfigurationPacketListenerImpl, LoginFlow> flows = new ConcurrentHashMap<>();
    /** Conexiones cuyo plazo se extendió por OAuth: el plazo normal ya no las expulsa. */
    private final Set<ServerConfigurationPacketListenerImpl> extended = ConcurrentHashMap.newKeySet();
    private final ExecutorService hashing = new java.util.concurrent.ThreadPoolExecutor(2, 2, 0, TimeUnit.SECONDS,
        new java.util.concurrent.ArrayBlockingQueue<>(HASH_QUEUE), daemon("SAM Argon2"));
    /** La IP de cada login pendiente, para liberar su lugar al terminar (RF-AUTH-06a). */
    private final Map<ServerConfigurationPacketListenerImpl, String> pendingIps = new ConcurrentHashMap<>();
    private final ScheduledExecutorService timer = Executors.newSingleThreadScheduledExecutor(daemon("SAM auth timeout"));
    private volatile Setup setup;
    /** Los nicks que completaron el 2FA en su sesión actual (RF-ADM-04, nodos {@code verified} de RF-PERM-06). */
    private final Set<String> verified = ConcurrentHashMap.newKeySet();

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
        PayloadTypeRegistry.configurationC2S().register(OAUTH_START, SamPayload.codec(OAUTH_START, OAuthStart.MAX_BYTES));
        PayloadTypeRegistry.configurationC2S().register(OAUTH_CODE, SamPayload.codec(OAUTH_CODE, OAuthCode.MAX_BYTES));
        PayloadTypeRegistry.configurationC2S().register(LOGIN_TOTP, SamPayload.codec(LOGIN_TOTP, LoginTotp.MAX_BYTES));
        ServerConfigurationNetworking.registerGlobalReceiver(LOGIN_TOTP,
            (payload, context) -> receive(context.networkHandler(), context.server(), payload, LoginTotp.MAX_BYTES, LoginTotp::read,
                LoginFlow::onTotp));
        PayloadTypeRegistry.configurationS2C().register(OAUTH_URL, SamPayload.codec(OAUTH_URL, MAX_SERVER_MESSAGE));

        ServerConfigurationConnectionEvents.CONFIGURE.register(this::configure);
        // sam auth reset <nick> (RF-AUTH-07, RF-ADM-07): solo la consola real; nadie más lo ve
        net.fabricmc.fabric.api.command.v2.CommandRegistrationCallback.EVENT.register((dispatcher, registry, environment) ->
            dispatcher.register(net.minecraft.commands.Commands.literal("sam").then(net.minecraft.commands.Commands.literal("auth")
                .requires(dev.sam.server.SamConsole::isConsole)
                .then(net.minecraft.commands.Commands.literal("reset").then(net.minecraft.commands.Commands.argument("nick",
                    com.mojang.brigadier.arguments.StringArgumentType.word()).executes(c -> reset(c.getSource(),
                        com.mojang.brigadier.arguments.StringArgumentType.getString(c, "nick"))))))));
        ServerConfigurationConnectionEvents.DISCONNECT.register((handler, server) -> {
            flows.remove(handler);
            extended.remove(handler);
            release(handler);
            var ready = setup;
            if (ready != null) {
                ready.google().ifPresent(google -> google.forget(handler));
            }
        });
        ServerConfigurationNetworking.registerGlobalReceiver(OAUTH_START,
            (payload, context) -> oauthStart(context.networkHandler(), context.server(), payload));
        ServerConfigurationNetworking.registerGlobalReceiver(OAUTH_CODE,
            (payload, context) -> oauthCode(context.networkHandler(), context.server(), payload));
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

    private int reset(net.minecraft.commands.CommandSourceStack source, String nick) {
        var ready = setup;
        if (ready == null) {
            source.sendFailure(Component.literal("El login de SAM está cerrado: no hay cuentas cargadas."));
            return 0;
        }
        if (!ready.accounts().reset(nick)) {
            source.sendFailure(Component.literal("No hay una cuenta " + nick + "."));
            return 0;
        }
        forget(nick);
        dev.sam.server.SamAudit.event("cuenta.reset", "consola", "", nick + ": se borró contraseña, correo, 2FA y Google");
        var online = source.getServer().getPlayerList().getPlayerByName(nick);
        if (online != null) {
            online.connection.disconnect(Component.literal("Tu cuenta se reinició. Vuelve a entrar para crearla de nuevo."));
        }
        source.sendSuccess(() -> Component.literal("Cuenta de " + nick + " borrada: al volver a entrar la crea de nuevo."), false);
        return 1;
    }

    /** Si ese jugador completó el 2FA al entrar en esta sesión. */
    public boolean verified(String nick) {
        return verified.contains(nick.toLowerCase(java.util.Locale.ROOT));
    }

    /** Al salir, la sesión verificada termina. */
    public void forget(String nick) {
        verified.remove(nick.toLowerCase(java.util.Locale.ROOT));
    }

    private void configure(ServerConfigurationPacketListenerImpl handler, MinecraftServer server) {
        // Una conexión nueva empieza sin verificar
        forget(handler.getOwner().getName());
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
            var ip = clientIp(handler);
            // Antes de cualquier Argon2: logins pendientes (RF-AUTH-06b) y bloqueo vigente (RF-AUTH-06a)
            if (!ready.throttle().enter(ip)) {
                dev.sam.server.SamAudit.event("login.ocupado", nick, ip, "demasiados logins pendientes");
                handler.disconnect(Component.literal(KICK_BUSY));
                return;
            }
            pendingIps.put(handler, ip);
            var locked = ready.throttle().lockedUntil(nick, ip);
            if (locked.isPresent()) {
                dev.sam.server.SamAudit.event("login.bloqueado", nick, ip, "bloqueado hasta " + locked.get());
                handler.disconnect(Component.literal(LoginFlow.lockedKick(ready.throttle().remaining(locked.get()))));
                return;
            }
            var throttle = ready.throttle();
            var flow = new LoginFlow(nick, ready.serverId(), serverName(server), ready.policy(), ready.accounts(), MAX_ATTEMPTS, throttle, ip);
            flows.put(handler, flow);
            var hello = flow.hello();
            sender.accept(ServerConfigurationNetworking.createS2CPacket(new SamPayload(HELLO, encode(hello::write))));
            timer.schedule(() -> server.execute(() -> {
                if (flows.get(handler) == flow && !flow.done() && !extended.contains(handler)) {
                    dev.sam.server.SamAudit.event("login.tiempo", nick, pendingIps.getOrDefault(handler, ""), "no completó el login en " + TIMEOUT_SECONDS + " s");
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
        // Argon2 fuera del hilo del servidor; la respuesta vuelve a él. Con la cola llena, SAM-K005
        try {
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
        } catch (java.util.concurrent.RejectedExecutionException e) {
            dev.sam.server.SamAudit.event("login.ocupado", nick, pendingIps.getOrDefault(handler, ""), "la cola de Argon2 está llena");
            flows.remove(handler);
            handler.disconnect(Component.literal(KICK_BUSY));
        }
    }

    /** "Entrar con Google" (PROTOCOLO.md 5.4): abre el flujo y manda la URL; el plazo pasa a 300 s. */
    private void oauthStart(ServerConfigurationPacketListenerImpl handler, MinecraftServer server, SamPayload payload) {
        var flow = flows.get(handler);
        var nick = handler.getOwner().getName();
        var google = setup == null ? Optional.<GoogleSignIn>empty() : setup.google();
        try {
            if (flow == null) {
                throw new ProtocolException(ProtocolException.OUT_OF_STATE, "mensaje sin login en curso");
            }
            var start = SamReader.decode(Unpooled.wrappedBuffer(payload.data()), OAuthStart.MAX_BYTES, OAuthStart::read);
            flow.startOAuth();
            if (google.isEmpty() || start.provider() != OAuthProvider.GOOGLE) {
                ServerConfigurationNetworking.send(handler, new SamPayload(AUTH_RESULT, encode(new AuthResult(AuthResult.Status.FAILED,
                    Optional.empty(), Optional.of("Ese método no está habilitado en este servidor"))::write)));
                return;
            }
            var url = google.get().start(handler, nick, OAuthStates.Purpose.LOGIN, start.port());
            ServerConfigurationNetworking.send(handler, new SamPayload(OAUTH_URL, encode(new OAuthUrl(url)::write)));
            if (extended.add(handler)) {
                timer.schedule(() -> server.execute(() -> {
                    if (flows.get(handler) == flow && !flow.done()) {
                        dev.sam.server.SamAudit.event("login.tiempo", nick, pendingIps.getOrDefault(handler, ""), "no completó el login con Google en " + OAUTH_TIMEOUT_SECONDS + " s");
                        handler.disconnect(Component.literal(KICK_TIMEOUT));
                    }
                }), OAUTH_TIMEOUT_SECONDS, TimeUnit.SECONDS);
            }
        } catch (ProtocolException e) {
            protocolError(handler, nick, e);
        }
    }

    /** El código que llegó al loopback del cliente: canje y validación fuera del hilo del servidor. */
    private void oauthCode(ServerConfigurationPacketListenerImpl handler, MinecraftServer server, SamPayload payload) {
        var flow = flows.get(handler);
        var nick = handler.getOwner().getName();
        OAuthCode code;
        try {
            if (flow == null || setup == null || setup.google().isEmpty()) {
                throw new ProtocolException(ProtocolException.OUT_OF_STATE, "código OAuth sin flujo abierto");
            }
            code = SamReader.decode(Unpooled.wrappedBuffer(payload.data()), OAuthCode.MAX_BYTES, OAuthCode::read);
        } catch (ProtocolException e) {
            protocolError(handler, nick, e);
            return;
        }
        setup.google().get().finish(handler, code).whenComplete((verified, error) -> server.execute(() -> {
            // Solo vale un flujo de login abierto por esta conexión y para este mismo nick
            var sub = verified == null ? Optional.<String>empty() : verified
                .filter(v -> v.pending().purpose() == OAuthStates.Purpose.LOGIN && v.pending().nick().equals(nick))
                .flatMap(GoogleSignIn.Verified::sub);
            if (error != null) {
                log.warn("Error al verificar Google de {}: {}", nick, error.toString());
            }
            try {
                apply(handler, nick, flow, flow.onGoogle(sub));
            } catch (ProtocolException e) {
                protocolError(handler, nick, e);
            }
        }));
    }

    private void apply(ServerConfigurationPacketListenerImpl handler, String nick, LoginFlow flow, LoginFlow.Reply reply) {
        if (flows.get(handler) != flow) {
            return;
        }
        reply.result().ifPresent(result -> ServerConfigurationNetworking.send(handler,
            new SamPayload(AUTH_RESULT, encode(result::write))));
        // H-09: cada intento fallido queda en la auditoría, con la IP y el motivo
        reply.result().filter(result -> result.status() == AuthResult.Status.FAILED).ifPresent(result ->
            dev.sam.server.SamAudit.event("login.fallido", nick, pendingIps.getOrDefault(handler, ""),
                result.detail().orElse("sin detalle")));
        if (reply.kick().isPresent()) {
            dev.sam.server.SamAudit.event("login.expulsado", nick, pendingIps.getOrDefault(handler, ""), reply.kick().get());
            flows.remove(handler);
            handler.disconnect(Component.literal(reply.kick().get()));
        } else if (reply.done()) {
            // El flujo solo termina después del código si la cuenta tiene 2FA (5.0)
            var withTotp = setup != null && setup.accounts().hasTotp(nick);
            if (withTotp) {
                verified.add(nick.toLowerCase(java.util.Locale.ROOT));
            }
            dev.sam.server.SamAudit.event("login.ok", nick, pendingIps.getOrDefault(handler, ""),
                withTotp ? "con 2FA: sesión verificada" : "sin 2FA");
            flows.remove(handler);
            release(handler);
            handler.completeTask(TASK);
        }
    }

    private void release(ServerConfigurationPacketListenerImpl handler) {
        var ip = pendingIps.remove(handler);
        var ready = setup;
        if (ip != null && ready != null) {
            ready.throttle().leave(ip);
        }
    }

    /** La IP del cliente (la real si vino por un proxy de confianza, RS-WS-02), como texto. */
    private static String clientIp(ServerConfigurationPacketListenerImpl handler) {
        var connection = ((dev.sam.server.mixin.ServerCommonPacketListenerAccessor) handler).sam$connection();
        var channel = ((dev.sam.server.mixin.ConnectionAccessor) connection).sam$channel();
        return channel == null ? "desconocida"
            : dev.sam.common.net.ip.ClientIp.of(channel).map(java.net.InetAddress::getHostAddress).orElse("desconocida");
    }

    private void protocolError(ServerConfigurationPacketListenerImpl handler, String nick, ProtocolException e) {
        dev.sam.server.SamAudit.event("protocolo.error", nick, pendingIps.getOrDefault(handler, ""), e.code() + " (" + e.getMessage() + ")");
        flows.remove(handler);
        handler.disconnect(Component.literal("Error de protocolo. [" + e.code() + "]"));
    }

    private static byte[] encode(Consumer<SamWriter> message) {
        var buf = Unpooled.buffer();
        message.accept(new SamWriter(buf));
        return ByteBufUtil.getBytes(buf);
    }

    /**
     * El nombre del servidor para el jugador: la primera línea del MOTD sin formato y sin lo que va
     * después de un " | " (el lema), acotado a 16 caracteres (≤ 64 bytes en UTF-8).
     */
    public static String serverName(MinecraftServer server) {
        var motd = server.getMotd().replaceAll("§.", "").split("\n", 2)[0];
        var bar = motd.indexOf(" | ");
        motd = (bar > 0 ? motd.substring(0, bar) : motd).strip();
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
