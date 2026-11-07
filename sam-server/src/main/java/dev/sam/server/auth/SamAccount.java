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

    private static final int MAX_SERVER_MESSAGE = 4096;
    private static final String GOOGLE_DISABLED = "Google no está habilitado en este servidor";

    /** Lo que necesita; llega junto con el login. */
    public record Setup(AccountService accounts, Optional<GoogleSignIn> google) {
    }

    private final Logger log;
    private final Map<UUID, Integer> failures = new ConcurrentHashMap<>();
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
        PayloadTypeRegistry.playS2C().register(INFO, SamPayload.codec(INFO, MAX_SERVER_MESSAGE));
        PayloadTypeRegistry.playS2C().register(RESULT, SamPayload.codec(RESULT, MAX_SERVER_MESSAGE));
        PayloadTypeRegistry.playS2C().register(SamAuth.OAUTH_URL, SamPayload.codec(SamAuth.OAUTH_URL, MAX_SERVER_MESSAGE));

        ServerPlayConnectionEvents.DISCONNECT.register((handler, server) -> {
            failures.remove(handler.getPlayer().getUUID());
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
                    change.k(), change.email()), "cambió su correo");
            }
        }));
        ServerPlayNetworking.registerGlobalReceiver(UNLINK, (payload, context) -> withSetup(context.player(), ready -> {
            var unlink = decode(context.player(), payload, AccountUnlink.MAX_BYTES, AccountUnlink::read);
            if (unlink != null) {
                withPassword(context.player(), context.server(), ready, () -> ready.accounts().unlink(nick(context.player()),
                    unlink.k(), unlink.provider()), "desvinculó " + unlink.provider());
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
                    log.info("[auditoría] {} vinculó Google", nick);
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
                    failures.remove(player.getUUID());
                    log.info("[auditoría] {} {}", nick, audit);
                } else if (result.detail().filter(AccountService.WRONG_PASSWORD::equals).isPresent()
                        && failures.merge(player.getUUID(), 1, Integer::sum) >= SamAuth.MAX_ATTEMPTS) {
                    log.info("[auditoría] {} expulsado: {}", nick, LoginFlow.KICK_TOO_MANY);
                    player.connection.disconnect(Component.literal(LoginFlow.KICK_TOO_MANY));
                    return;
                }
                send(player, RESULT, result::write);
                sendInfo(player, ready);
            });
        });
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
            log.warn("[auditoría] Error de protocolo de {}: {} ({})", nick(player), e.code(), e.getMessage());
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
