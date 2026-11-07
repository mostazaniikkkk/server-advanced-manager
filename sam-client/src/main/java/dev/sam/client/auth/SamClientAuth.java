package dev.sam.client.auth;

import java.util.function.Consumer;
import java.util.function.Function;

import org.slf4j.Logger;

import dev.sam.client.mixin.ClientCommonPacketListenerAccessor;
import dev.sam.client.net.SamClientNet;
import dev.sam.client.net.SamPayload;
import dev.sam.common.proto.ProtocolException;
import dev.sam.common.proto.SamReader;
import dev.sam.common.proto.SamWriter;
import dev.sam.common.proto.account.OAuthCode;
import dev.sam.common.proto.account.OAuthStart;
import dev.sam.common.proto.account.OAuthUrl;
import dev.sam.common.proto.auth.AuthResult;
import dev.sam.common.proto.auth.Hello;
import dev.sam.common.proto.auth.HelloAck;
import dev.sam.common.proto.auth.LoginPassword;
import dev.sam.common.proto.auth.ProtocolVersion;
import dev.sam.common.proto.auth.Register;
import io.netty.buffer.ByteBufUtil;
import io.netty.buffer.Unpooled;
import net.fabricmc.fabric.api.client.networking.v1.ClientConfigurationNetworking;
import net.fabricmc.fabric.api.networking.v1.PayloadTypeRegistry;
import net.fabricmc.fabric.api.networking.v1.PacketSender;
import net.minecraft.network.chat.Component;
import net.minecraft.network.protocol.common.custom.CustomPacketPayload;

/**
 * El login de SAM en el cliente (PROTOCOLO.md 5): al llegar {@code sam:hello} se abre la AuthScreen y
 * se contesta {@code sam:hello_ack}; la pantalla envía el registro o el login y muestra el resultado.
 */
public final class SamClientAuth {

    public static final CustomPacketPayload.Type<SamPayload> HELLO = SamPayload.type("hello");
    public static final CustomPacketPayload.Type<SamPayload> AUTH_RESULT = SamPayload.type("auth_result");
    public static final CustomPacketPayload.Type<SamPayload> HELLO_ACK = SamPayload.type("hello_ack");
    public static final CustomPacketPayload.Type<SamPayload> REGISTER = SamPayload.type("register");
    public static final CustomPacketPayload.Type<SamPayload> LOGIN_PASSWORD = SamPayload.type("login_password");
    public static final CustomPacketPayload.Type<SamPayload> OAUTH_START = SamPayload.type(OAuthStart.ID);
    public static final CustomPacketPayload.Type<SamPayload> OAUTH_URL = SamPayload.type(OAuthUrl.ID);
    public static final CustomPacketPayload.Type<SamPayload> OAUTH_CODE = SamPayload.type(OAuthCode.ID);

    private static final int MAX_SERVER_MESSAGE = 256 * 1024;

    private static Logger log;
    private static String version;

    private SamClientAuth() {
    }

    public static void install(Logger logger, String clientVersion) {
        log = logger;
        version = clientVersion;
        PayloadTypeRegistry.configurationS2C().register(HELLO, SamPayload.codec(HELLO, MAX_SERVER_MESSAGE));
        PayloadTypeRegistry.configurationS2C().register(AUTH_RESULT, SamPayload.codec(AUTH_RESULT, MAX_SERVER_MESSAGE));
        PayloadTypeRegistry.configurationC2S().register(HELLO_ACK, SamPayload.codec(HELLO_ACK, HelloAck.MAX_BYTES));
        PayloadTypeRegistry.configurationC2S().register(REGISTER, SamPayload.codec(REGISTER, Register.MAX_BYTES));
        PayloadTypeRegistry.configurationC2S().register(LOGIN_PASSWORD, SamPayload.codec(LOGIN_PASSWORD, LoginPassword.MAX_BYTES));
        PayloadTypeRegistry.configurationC2S().register(OAUTH_START, SamPayload.codec(OAUTH_START, OAuthStart.MAX_BYTES));
        PayloadTypeRegistry.configurationC2S().register(OAUTH_CODE, SamPayload.codec(OAUTH_CODE, OAuthCode.MAX_BYTES));
        PayloadTypeRegistry.configurationS2C().register(OAUTH_URL, SamPayload.codec(OAUTH_URL, MAX_SERVER_MESSAGE));
        ClientConfigurationNetworking.registerGlobalReceiver(OAUTH_URL, (payload, context) -> {
            var url = decode(payload, OAuthUrl::read, context.responseSender());
            if (url != null) {
                context.client().execute(() -> GoogleFlow.onUrl(url.url()));
            }
        });

        ClientConfigurationNetworking.registerGlobalReceiver(HELLO, (payload, context) -> {
            var hello = decode(payload, Hello::read, context.responseSender());
            if (hello == null) {
                return;
            }
            // El hello debe venir del servidor cuyo certificado se verificó (PROTOCOLO.md 5.1)
            var verified = SamClientNet.lastVerified();
            if (verified.isEmpty() || !verified.get().equals(hello.serverId())) {
                log.error("[SAM-C001] El sam:hello trae un server_id distinto al del certificado verificado");
                context.responseSender().disconnect(Component.literal("La identidad del servidor no coincide. [SAM-C001]"));
                return;
            }
            context.responseSender().sendPacket(new SamPayload(HELLO_ACK,
                encode(new HelloAck(ProtocolVersion.CURRENT, version, new byte[32])::write)));
            var client = context.client();
            var sender = context.responseSender();
            var connection = ((ClientCommonPacketListenerAccessor) context.networkHandler()).sam$connection();
            client.execute(() -> client.setScreen(new AuthScreen(hello, client.getUser().getName(), sender, connection)));
        });
        ClientConfigurationNetworking.registerGlobalReceiver(AUTH_RESULT, (payload, context) -> {
            var result = decode(payload, AuthResult::read, context.responseSender());
            if (result != null) {
                context.client().execute(() -> {
                    if (context.client().screen instanceof AuthScreen screen) {
                        screen.onResult(result);
                    }
                });
            }
        });
    }

    static void send(CustomPacketPayload.Type<SamPayload> type, Consumer<SamWriter> message) {
        ClientConfigurationNetworking.send(new SamPayload(type, encode(message)));
    }

    private static <T> T decode(SamPayload payload, Function<SamReader, T> reader, PacketSender sender) {
        try {
            return SamReader.decode(Unpooled.wrappedBuffer(payload.data()), MAX_SERVER_MESSAGE, reader);
        } catch (ProtocolException e) {
            log.error("Mensaje {} mal formado del servidor: {} ({})", payload.type().id(), e.code(), e.getMessage());
            sender.disconnect(Component.literal("Error de protocolo. [" + e.code() + "]"));
            return null;
        }
    }

    private static byte[] encode(Consumer<SamWriter> message) {
        var buf = Unpooled.buffer();
        message.accept(new SamWriter(buf));
        return ByteBufUtil.getBytes(buf);
    }
}
