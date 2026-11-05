package dev.sam.server.mixin;

import org.spongepowered.asm.mixin.Mixin;
import org.spongepowered.asm.mixin.injection.At;
import org.spongepowered.asm.mixin.injection.Inject;
import org.spongepowered.asm.mixin.injection.callback.CallbackInfo;

import dev.sam.server.SamServer;
import io.netty.channel.Channel;

/**
 * El {@code ChannelInitializer} anónimo de {@code ServerConnectionListener} arma el pipeline de
 * cada conexión TCP aceptada. Al terminar, SAM pone su compuerta de entrada primera.
 */
@Mixin(targets = "net.minecraft.server.network.ServerConnectionListener$1")
public abstract class ServerChannelInitializerMixin {

    @Inject(method = "initChannel", at = @At("TAIL"))
    private void sam$installIngressGate(Channel channel, CallbackInfo ci) {
        SamServer.installIngressGate(channel.pipeline());
    }
}
