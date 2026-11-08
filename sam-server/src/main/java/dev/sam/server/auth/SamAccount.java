package dev.sam.server.auth;

import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.function.Consumer;
import java.util.function.Supplier;

import org.slf4j.Logger;

import dev.sam.common.auth.AccountService;
import dev.sam.common.auth.LoginFlow;
import dev.sam.common.oauth.OAuthStates;
import dev.sam.common.proto.ProtocolException;
import dev.sam.common.proto.SamReader;
import dev.sam.common.proto.SamWriter;
import dev.sam.common.proto.account.AccountEmail;
import dev.sam.common.proto.account.AccountInfo;
import dev.sam.common.proto.account.AccountResult;
import dev.sam.common.proto.account.AccountUnlink;
import dev.sam.common.proto.account.OAuthCode;
import dev.sam.common.proto.account.OAuthProvider;
import dev.sam.common.proto.account.OAuthStart;
import dev.sam.common.proto.account.OAuthUrl;
import dev.sam.common.proto.account.TotpBegin;
import dev.sam.common.proto.account.TotpConfirm;
import dev.sam.common.proto.account.TotpDisable;
import dev.sam.common.proto.account.TotpEnroll;
import io.netty.buffer.ByteBufUtil;
import io.netty.buffer.Unpooled;
import net.fabricmc.fabric.api.networking.v1.PayloadTypeRegistry;
import net.fabricmc.fabric.api.networking.v1.ServerPlayConnectionEvents;
import net.fabricmc.fabric.api.networking.v1.ServerPlayNetworking;
import net.minecraft.network.chat.Component;
import net.minecraft.network.protocol.common.custom.CustomPacketPayload;
import net.minecraft.server.MinecraftServer;
import net.minecraft.server.level.ServerPlayer;

/**
 * "Opciones de cuenta" en la fase play (RF-AUTH-07d, PROTOCOLO.md 5.7): información de la cuenta, cambio
 * de correo con la contraseña (RF-AUTH-07b) y vincular o desvincular Google (RF-OAUTH-02). Los fallos de
 * contraseña cuentan para el mismo tope que el login (SAM-K004). Argon2 y Google van fuera del hilo del
 * servidor.
 */
public final class SamAccount {

    public static final CustomPacketPayload.Type<SamPayload> REQUEST = SamPayload.type("account_request");
    public static final CustomPacketPayload.Type<SamPayload> INFO = SamPayload.type(AccountInfo.ID);
    public static final CustomPacketPayload.Type<SamPayload> EMAIL = SamPayload.type(AccountEmail.ID);
    public static final CustomPacketPayload.Type<SamPayload> UNLINK = SamPayload.type(AccountUnlink.ID);
    public static final CustomPacketPayload.Type<SamPayload> RESULT = SamPayload.type(AccountResult.ID);
    public static final CustomPacketPayload.Type<SamPayload> TOTP_BEGIN = SamPayload.type(TotpBegin.ID);
    public static final CustomPacketPayload.Type<SamPayload> TOTP_ENROLL = SamPayload.type(TotpEnroll.ID);
    public static final CustomPacketPayload.Type<SamPayload> TOTP_CONFIRM = SamPayload.type(TotpConfirm.ID);
    public static final CustomPacketPayload.Type<SamPayload> TOTP_DISABLE = SamPayload.type(TotpDisable.ID);

    private static final int MAX_SERVER_MESSAGE = 4096;
    private static final String GOOGLE_DISABLED = "Google no está habilitado en este servidor";

    /** Lo que necesita; llega junto con el login. */
    public record Setup(AccountService accounts, Optional<GoogleSignIn> google, dev.sam.common.auth.LoginThrottle throttle) {
    }

    /** Lo que SamServer agrega al exportar y al borrar los datos de un jugador (RF-AUTH-07e). */
    public interface DataHooks {
        /** Lo demás que se sabe del jugador (permisos, auditoría), como pares nombre → JSON. */
        Map<String, com.google.gson.JsonElement> export(String nick);

        /** Borra lo demás del jugador (permisos y datos de los scripts). */
        void erase(MinecraftServer server, String nick, String uuid);
    }

    private volatile DataHooks hooks;

    public void hooks(DataHooks dataHooks) {
        hooks = dataHooks;
    }

    public static final CustomPacketPayload.Type<SamPayload> DATA = SamPayload.type(dev.sam.common.proto.account.AccountData.ID);
    public static final CustomPacketPayload.Type<SamPayload> EXPORT = SamPayload.type(dev.sam.common.proto.account.AccountExport.ID);

    private final Logger log;
    private final ExecutorService hashing = Executors.newFixedThreadPool(1, runnable -> {
        var thread = new Thread(runnable, "SAM cuenta");
        thread.setDaemon(true);
        return thread;
    });
    private volatile Setup setup;

    public SamAccount(Logger log) {
        this.log = log;
    }

    public void install() {
        PayloadTypeRegistry.playC2S().register(REQUEST, SamPayload.codec(REQUEST, 0));
        PayloadTypeRegistry.playC2S().register(EMAIL, SamPayload.codec(EMAIL, AccountEmail.MAX_BYTES));
        PayloadTypeRegistry.playC2S().register(UNLINK, SamPayload.codec(UNLINK, AccountUnlink.MAX_BYTES));
        PayloadTypeRegistry.playC2S().register(SamAuth.OAUTH_START, SamPayload.codec(SamAuth.OAUTH_START, OAuthStart.MAX_BYTES));
        PayloadTypeRegistry.playC2S().register(SamAuth.OAUTH_CODE, SamPayload.codec(SamAuth.OAUTH_CODE, OAuthCode.MAX_BYTES));
        PayloadTypeRegistry.playC2S().register(TOTP_BEGIN, SamPayload.codec(TOTP_BEGIN, TotpBegin.MAX_BYTES));
        PayloadTypeRegistry.playC2S().register(TOTP_CONFIRM, SamPayload.codec(TOTP_CONFIRM, TotpConfirm.MAX_BYTES));
        PayloadTypeRegistry.playC2S().register(TOTP_DISABLE, SamPayload.codec(TOTP_DISABLE, TotpDisable.MAX_BYTES));
        PayloadTypeRegistry.playS2C().register(TOTP_ENROLL, SamPayload.codec(TOTP_ENROLL, MAX_SERVER_MESSAGE));
        PayloadTypeRegistry.playC2S().register(DATA, SamPayload.codec(DATA, dev.sam.common.proto.account.AccountData.MAX_BYTES));
        PayloadTypeRegistry.playS2C().register(EXPORT, SamPayload.codec(EXPORT, dev.sam.common.proto.account.AccountExport.MAX_BYTES));
        // RF-AUTH-07e: exportar o borrar los datos del jugador, con reautenticación
        ServerPlayNetworking.registerGlobalReceiver(DATA, (payload, context) -> withSetup(context.player(), ready -> {
            var request = decode(context.player(), payload, dev.sam.common.proto.account.AccountData.MAX_BYTES,
                dev.sam.common.proto.account.AccountData::read);
            if (request != null) {
                data(context.player(), context.server(), ready, request);
            }
        }));
        PayloadTypeRegistry.playS2C().register(INFO, SamPayload.codec(INFO, MAX_SERVER_MESSAGE));
        PayloadTypeRegistry.playS2C().register(RESULT, SamPayload.codec(RESULT, MAX_SERVER_MESSAGE));
        PayloadTypeRegistry.playS2C().register(SamAuth.OAUTH_URL, SamPayload.codec(SamAuth.OAUTH_URL, MAX_SERVER_MESSAGE));

        ServerPlayConnectionEvents.DISCONNECT.register((handler, server) -> {
            var ready = setup;
            if (ready != null) {
                ready.google().ifPresent(google -> google.forget(handler.getPlayer().getUUID()));
            }
        });
        ServerPlayNetworking.registerGlobalReceiver(REQUEST, (payload, context) -> withSetup(context.player(), ready -> sendInfo(context.player(), ready)));
        ServerPlayNetworking.registerGlobalReceiver(EMAIL, (payload, context) -> withSetup(context.player(), ready -> {
            var change = decode(context.player(), payload, AccountEmail.MAX_BYTES, AccountEmail::read);
            if (change != null) {
                withPassword(context.player(), context.server(), ready, () -> ready.accounts().changeEmail(nick(context.player()),
                    change.k(), change.code(), change.email()), "cambió su correo");
            }
        }));
        ServerPlayNetworking.registerGlobalReceiver(UNLINK, (payload, context) -> withSetup(context.player(), ready -> {
            var unlink = decode(context.player(), payload, AccountUnlink.MAX_BYTES, AccountUnlink::read);
            if (unlink != null) {
                withPassword(context.player(), context.server(), ready, () -> ready.accounts().unlink(nick(context.player()),
                    unlink.k(), unlink.code(), unlink.provider()), "desvinculó " + unlink.provider());
            }
        }));
        // 2FA (RF-AUTH-04): activar con la contraseña, confirmar con el primer código, desactivar con ambos
        ServerPlayNetworking.registerGlobalReceiver(TOTP_BEGIN, (payload, context) -> withSetup(context.player(), ready -> {
            var begin = decode(context.player(), payload, TotpBegin.MAX_BYTES, TotpBegin::read);
            if (begin == null) {
                return;
            }
            var player = context.player();
            var issuer = SamAuth.serverName(context.server());
            hashing.execute(() -> {
                var started = ready.accounts().beginTotp(nick(player), begin.k(), issuer.isBlank() ? "Minecraft" : issuer);
                context.server().execute(() -> {
                    if (player.hasDisconnected() || countFailure(player, ready, started.result())) {
                        return;
                    }
                    started.enrollment().ifPresentOrElse(
                        enrollment -> send(player, TOTP_ENROLL, new TotpEnroll(enrollment.uri(), enrollment.backupCodes())::write),
                        () -> send(player, RESULT, started.result()::write));
                });
            });
        }));
        ServerPlayNetworking.registerGlobalReceiver(TOTP_CONFIRM, (payload, context) -> withSetup(context.player(), ready -> {
            var confirm = decode(context.player(), payload, TotpConfirm.MAX_BYTES, TotpConfirm::read);
            if (confirm != null) {
                withPassword(context.player(), context.server(), ready, () -> ready.accounts().confirmTotp(nick(context.player()),
                    confirm.code()), "activó el 2FA");
            }
        }));
        ServerPlayNetworking.registerGlobalReceiver(TOTP_DISABLE, (payload, context) -> withSetup(context.player(), ready -> {
            var disable = decode(context.player(), payload, TotpDisable.MAX_BYTES, TotpDisable::read);
            if (disable != null) {
                withPassword(context.player(), context.server(), ready, () -> ready.accounts().disableTotp(nick(context.player()),
                    disable.k(), disable.code()), "desactivó el 2FA");
            }
        }));
        ServerPlayNetworking.registerGlobalReceiver(SamAuth.OAUTH_START, (payload, context) -> withSetup(context.player(), ready -> {
            var start = decode(context.player(), payload, OAuthStart.MAX_BYTES, OAuthStart::read);
            if (start == null) {
                return;
            }
            if (ready.google().isEmpty() || start.provider() != OAuthProvider.GOOGLE) {
                sendResult(context.player(), AccountResult.Status.FAILED, GOOGLE_DISABLED);
                return;
            }
            var url = ready.google().get().start(context.player().getUUID(), nick(context.player()), OAuthStates.Purpose.LINK,
                start.port());
            send(context.player(), SamAuth.OAUTH_URL, new OAuthUrl(url)::write);
        }));
        ServerPlayNetworking.registerGlobalReceiver(SamAuth.OAUTH_CODE, (payload, context) -> withSetup(context.player(), ready -> {
            var code = decode(context.player(), payload, OAuthCode.MAX_BYTES, OAuthCode::read);
            if (code == null || ready.google().isEmpty()) {
                return;
            }
            var player = context.player();
            var nick = nick(player);
            ready.google().get().finish(player.getUUID(), code).whenComplete((verified, error) -> context.server().execute(() -> {
                var sub = verified == null ? Optional.<String>empty() : verified
                    .filter(v -> v.pending().purpose() == OAuthStates.Purpose.LINK && v.pending().nick().equals(nick))
                    .flatMap(GoogleSignIn.Verified::sub);
                if (player.hasDisconnected()) {
                    return;
                }
                if (sub.isEmpty()) {
                    sendResult(player, AccountResult.Status.FAILED, LoginFlow.GOOGLE_FAILED);
                    return;
                }
                var result = ready.accounts().linkGoogle(nick, sub.get());
                if (result.status() == AccountResult.Status.OK) {
                    dev.sam.server.SamAudit.event("cuenta.google", nick, "", "vinculó Google");
                }
                send(player, RESULT, result::write);
                sendInfo(player, ready);
            }));
        }));
    }

    public void activate(Setup ready) {
        this.setup = ready;
    }

    private void withSetup(ServerPlayer player, Consumer<Setup> action) {
        var ready = setup;
        if (ready != null) {
            action.accept(ready);
        }
    }

    private void data(ServerPlayer player, MinecraftServer server, Setup ready, dev.sam.common.proto.account.AccountData request) {
        var nick = nick(player);
        var uuid = player.getUUID().toString();
        hashing.execute(() -> {
            var delete = request.action() == dev.sam.common.proto.account.AccountData.Action.DELETE;
            var exported = delete ? null : ready.accounts().export(nick, request.k(), request.code());
            var result = delete ? ready.accounts().delete(nick, request.k(), request.code()) : exported.result();
            server.execute(() -> {
                if (player.hasDisconnected() || countFailure(player, ready, result)) {
                    return;
                }
                if (result.status() != AccountResult.Status.OK) {
                    send(player, RESULT, result::write);
                    return;
                }
                var dataHooks = hooks;
                if (delete) {
                    if (dataHooks != null) {
                        dataHooks.erase(server, nick, uuid);
                    }
                    dev.sam.server.SamAudit.event("cuenta.borrada", nick, "", "el jugador borró su cuenta y sus datos");
                    player.connection.disconnect(Component.literal("Tu cuenta y tus datos se borraron de este servidor. "
                        + "Si vuelves a entrar, empiezas de cero."));
                    return;
                }
                var account = exported.data().orElseThrow();
                var json = new com.google.gson.JsonObject();
                json.addProperty("servidor", SamAuth.serverName(server));
                json.addProperty("exportado", java.time.Instant.now().toString());
                var cuenta = new com.google.gson.JsonObject();
                cuenta.addProperty("nick", account.nick());
                cuenta.addProperty("correo", account.email());
                cuenta.addProperty("google", account.google());
                cuenta.addProperty("dosFactores", account.totp());
                json.add("cuenta", cuenta);
                if (dataHooks != null) {
                    dataHooks.export(nick).forEach(json::add);
                }
                // Tope del mensaje: si no cabe, se quitan primero los eventos más viejos de la auditoría
                var text = json.toString();
                while (text.getBytes(java.nio.charset.StandardCharsets.UTF_8).length > dev.sam.common.proto.account.AccountExport.MAX_JSON
                        && json.has("auditoria") && json.getAsJsonArray("auditoria").size() > 0) {
                    json.getAsJsonArray("auditoria").remove(0);
                    text = json.toString();
                }
                dev.sam.server.SamAudit.event("cuenta.exportada", nick, "", "el jugador exportó sus datos");
                send(player, EXPORT, new dev.sam.common.proto.account.AccountExport(text)::write);
                send(player, RESULT, result::write);
            });
        });
    }

    /** Operación con reautenticación: Argon2 fuera del hilo; los fallos cuentan para SAM-K004. */
    private void withPassword(ServerPlayer player, MinecraftServer server, Setup ready, Supplier<AccountResult> operation, String audit) {
        hashing.execute(() -> {
            var result = operation.get();
            server.execute(() -> {
                if (player.hasDisconnected()) {
                    return;
                }
                var nick = nick(player);
                if (result.status() == AccountResult.Status.OK) {
                    dev.sam.server.SamAudit.event("cuenta.cambio", nick, "", audit);
                }
                if (countFailure(player, ready, result)) {
                    return;
                }
                send(player, RESULT, result::write);
                sendInfo(player, ready);
            });
        });
    }

    /**
     * Una contraseña o un código equivocados cuentan para el mismo bloqueo que el login (RF-AUTH-06a): al llegar al
     * tope, SAM-K004 con los minutos que faltan. Un OK limpia los intentos.
     *
     * @return {@code true} si el jugador fue expulsado
     */
    private boolean countFailure(ServerPlayer player, Setup ready, AccountResult result) {
        var nick = nick(player);
        var ip = playerIp(player);
        if (result.status() == AccountResult.Status.OK) {
            ready.throttle().success(nick, ip);
            return false;
        }
        var wrong = result.detail().filter(d -> d.equals(AccountService.WRONG_PASSWORD) || d.equals(AccountService.WRONG_CODE));
        if (wrong.isEmpty()) {
            return false;
        }
        dev.sam.server.SamAudit.event("cuenta.fallido", nick, ip, wrong.get());
        var locked = ready.throttle().failure(nick, ip);
        if (locked.isPresent()) {
            var kick = LoginFlow.lockedKick(ready.throttle().remaining(locked.get()));
            dev.sam.server.SamAudit.event("cuenta.expulsado", nick, ip, kick);
            player.connection.disconnect(Component.literal(kick));
            return true;
        }
        return false;
    }

    private static String playerIp(ServerPlayer player) {
        var connection = ((dev.sam.server.mixin.ServerCommonPacketListenerAccessor) player.connection).sam$connection();
        var channel = ((dev.sam.server.mixin.ConnectionAccessor) connection).sam$channel();
        return channel == null ? "desconocida"
            : dev.sam.common.net.ip.ClientIp.of(channel).map(java.net.InetAddress::getHostAddress).orElse("desconocida");
    }

    private void sendInfo(ServerPlayer player, Setup ready) {
        send(player, INFO, ready.accounts().info(nick(player), ready.google().isPresent())::write);
    }

    private void sendResult(ServerPlayer player, AccountResult.Status status, String detail) {
        send(player, RESULT, new AccountResult(status, Optional.of(detail))::write);
    }

    private <T> T decode(ServerPlayer player, SamPayload payload, int max, java.util.function.Function<SamReader, T> reader) {
        try {
            return SamReader.decode(Unpooled.wrappedBuffer(payload.data()), max, reader);
        } catch (ProtocolException e) {
            dev.sam.server.SamAudit.event("protocolo.error", nick(player), "", e.code() + " (" + e.getMessage() + ")");
            player.connection.disconnect(Component.literal("Error de protocolo. [" + e.code() + "]"));
            return null;
        }
    }

    private static String nick(ServerPlayer player) {
        return player.getGameProfile().getName();
    }

    private static void send(ServerPlayer player, CustomPacketPayload.Type<SamPayload> type, Consumer<SamWriter> message) {
        var buf = Unpooled.buffer();
        message.accept(new SamWriter(buf));
        ServerPlayNetworking.send(player, new SamPayload(type, ByteBufUtil.getBytes(buf)));
    }
}
