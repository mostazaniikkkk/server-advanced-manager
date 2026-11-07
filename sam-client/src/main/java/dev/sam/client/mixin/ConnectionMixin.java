package dev.sam.client.mixin;

import java.net.InetSocketAddress;

import org.spongepowered.asm.mixin.Mixin;
import org.spongepowered.asm.mixin.Shadow;
import org.spongepowered.asm.mixin.Unique;
import org.spongepowered.asm.mixin.injection.At;
import org.spongepowered.asm.mixin.injection.Inject;
import org.spongepowered.asm.mixin.injection.callback.CallbackInfo;
import org.spongepowered.asm.mixin.injection.callback.CallbackInfoReturnable;

import dev.sam.client.net.SamClientNet;
import dev.sam.client.net.SamTlsConnection;
import io.netty.channel.Channel;
import io.netty.channel.ChannelFuture;
import io.netty.channel.ChannelHandlerContext;
import net.minecraft.network.Connection;
import net.minecraft.network.DisconnectionDetails;
import net.minecraft.network.chat.Component;

/**
 * El TLS de SAM en la conexión del cliente: antes de abrir el socket se decide si va por TLS (en el
 * hilo del conector) y, al activarse el canal, el TLS se pone pegado al socket. Lo que vanilla
 * escribe mientras dura el handshake queda en espera dentro del TLS.
 */
@Mixin(Connection.class)
public abstract class ConnectionMixin implements SamTlsConnection {

    @Unique
    private volatile SamClientNet.Plan sam$plan;

    @Shadow
    private Channel channel;

    @Shadow
    private DisconnectionDetails disconnectionDetails;

    @Override
    public void sam$setPlan(SamClientNet.Plan plan) {
        this.sam$plan = plan;
    }

    @Override
    public SamClientNet.Plan sam$plan() {
        return sam$plan;
    }

    @Inject(method = "connect(Ljava/net/InetSocketAddress;ZLnet/minecraft/network/Connection;)Lio/netty/channel/ChannelFuture;",
        at = @At("HEAD"))
    private static void sam$decide(InetSocketAddress address, boolean useEpoll, Connection connection,
            CallbackInfoReturnable<ChannelFuture> cir) {
        SamClientNet.prepare(address, connection);
    }

    @Unique
    private boolean sam$resumed;

    /** El canal mientras vanilla espera (aún no lo conoce). */
    @Unique
    private volatile Channel sam$held;

    @Override
    public boolean sam$waiting() {
        var held = sam$held;
        return channel == null && held != null && held.isOpen();
    }

    /**
     * Por WebSocket, vanilla espera: su channelActive se retiene hasta que el túnel y el TLS de SAM están
     * listos (antes de eso vanilla no escribe nada: sus acciones quedan en cola sin canal).
     */
    @Inject(method = "channelActive", at = @At("HEAD"), cancellable = true)
    private void sam$holdForWebSocket(ChannelHandlerContext ctx, CallbackInfo ci) {
        var plan = sam$plan;
        if (plan == null || !plan.webSocket() || sam$resumed) {
            return;
        }
        ci.cancel();
        sam$held = ctx.channel();
        var self = (Connection) (Object) this;
        // Si se corta antes de entregarle el canal a vanilla, vanilla no se entera (su canal sigue nulo) y la
        // pantalla queda en "Conectando": se le entrega el canal ya cerrado, con el motivo
        ctx.channel().closeFuture().addListener(closed -> {
            if (!sam$resumed) {
                sam$resumed = true;
                sam$explain(ctx.channel(), "No se pudo conectar con el servidor por WebSocket.");
                this.channel = ctx.channel();
            }
        });
        SamClientNet.installWebSocket(ctx.channel(), plan, () -> ctx.channel().eventLoop().execute(() -> {
            sam$resumed = true;
            try {
                self.channelActive(ctx);
            } catch (Exception e) {
                ctx.fireExceptionCaught(e);
            }
        }));
    }

    /** Mientras vanilla espera no tiene canal: un error (p. ej. el timeout de lectura) corta la conexión. */
    @Inject(method = "exceptionCaught", at = @At("HEAD"), cancellable = true)
    private void sam$failWhileHeld(ChannelHandlerContext ctx, Throwable cause, CallbackInfo ci) {
        var plan = sam$plan;
        if (plan != null && plan.webSocket() && !sam$resumed) {
            ci.cancel();
            SamClientNet.fail(ctx.channel(), cause instanceof io.netty.handler.timeout.TimeoutException
                ? "El servidor no respondió a tiempo." : "Error de conexión: " + cause.getMessage());
            ctx.channel().close();
        }
    }

    /** Si SAM cortó la conexión, el jugador ve por qué (no un "Desconectado" a secas). */
    @Inject(method = "channelInactive", at = @At("HEAD"))
    private void sam$explainOnClose(ChannelHandlerContext ctx, CallbackInfo ci) {
        sam$explain(ctx.channel(), null);
    }

    @Unique
    private void sam$explain(Channel closed, String fallback) {
        if (disconnectionDetails != null) {
            return;
        }
        var reason = SamClientNet.failure(closed).orElse(fallback);
        if (reason != null) {
            disconnectionDetails = new DisconnectionDetails(Component.literal(reason));
        }
    }

    @Inject(method = "channelActive", at = @At("TAIL"))
    private void sam$installTls(ChannelHandlerContext ctx, CallbackInfo ci) {
        SamClientNet.install(ctx.channel(), sam$plan);
    }
}
