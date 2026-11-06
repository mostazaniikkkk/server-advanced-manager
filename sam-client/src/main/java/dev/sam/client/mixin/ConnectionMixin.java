package dev.sam.client.mixin;

import java.net.InetSocketAddress;

import org.spongepowered.asm.mixin.Mixin;
import org.spongepowered.asm.mixin.Unique;
import org.spongepowered.asm.mixin.injection.At;
import org.spongepowered.asm.mixin.injection.Inject;
import org.spongepowered.asm.mixin.injection.callback.CallbackInfo;
import org.spongepowered.asm.mixin.injection.callback.CallbackInfoReturnable;

import dev.sam.client.net.SamClientNet;
import dev.sam.client.net.SamTlsConnection;
import io.netty.channel.ChannelFuture;
import io.netty.channel.ChannelHandlerContext;
import net.minecraft.network.Connection;

/**
 * El TLS de SAM en la conexión del cliente: antes de abrir el socket se decide si va por TLS (en el
 * hilo del conector) y, al activarse el canal, el TLS se pone pegado al socket. Lo que vanilla
 * escribe mientras dura el handshake queda en espera dentro del TLS.
 */
@Mixin(Connection.class)
public abstract class ConnectionMixin implements SamTlsConnection {

    @Unique
    private volatile SamClientNet.Plan sam$plan;

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
        var self = (Connection) (Object) this;
        SamClientNet.installWebSocket(ctx.channel(), plan, () -> ctx.channel().eventLoop().execute(() -> {
            sam$resumed = true;
            try {
                self.channelActive(ctx);
            } catch (Exception e) {
                ctx.fireExceptionCaught(e);
            }
        }));
    }

    @Inject(method = "channelActive", at = @At("TAIL"))
    private void sam$installTls(ChannelHandlerContext ctx, CallbackInfo ci) {
        SamClientNet.install(ctx.channel(), sam$plan);
    }
}
