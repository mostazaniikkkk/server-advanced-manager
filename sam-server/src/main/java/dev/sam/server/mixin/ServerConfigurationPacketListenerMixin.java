package dev.sam.server.mixin;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.spongepowered.asm.mixin.Final;
import org.spongepowered.asm.mixin.Mixin;
import org.spongepowered.asm.mixin.Shadow;
import org.spongepowered.asm.mixin.Unique;
import org.spongepowered.asm.mixin.injection.At;
import org.spongepowered.asm.mixin.injection.Inject;
import org.spongepowered.asm.mixin.injection.callback.CallbackInfo;

import com.mojang.authlib.GameProfile;

import net.minecraft.network.Connection;
import net.minecraft.network.protocol.configuration.ServerboundFinishConfigurationPacket;
import net.minecraft.server.MinecraftServer;
import net.minecraft.server.TickTask;
import net.minecraft.server.network.CommonListenerCookie;
import net.minecraft.server.network.ServerCommonPacketListenerImpl;
import net.minecraft.server.network.ServerConfigurationPacketListenerImpl;

/**
 * RN-04 (RF-AUTH-06c): al terminar configuration la conexión ya pasó el login de SAM (es una tarea de
 * configuration). Recién aquí reemplaza a la sesión anterior con su nick; vanilla en cambio rechazaría a la
 * nueva. La sesión anterior sale de la lista en un tick posterior (cuando se cierra su canal): hasta
 * entonces se reintenta en cada tick, como hace vanilla en el login. Si no sale en {@value #MAX_WAIT_TICKS}
 * ticks, sigue vanilla y rechaza a la nueva (el lado seguro).
 */
@Mixin(ServerConfigurationPacketListenerImpl.class)
public abstract class ServerConfigurationPacketListenerMixin extends ServerCommonPacketListenerImpl {

    @Unique
    private static final Logger SAM_LOG = LoggerFactory.getLogger("SAM");
    @Unique
    private static final int MAX_WAIT_TICKS = 100;

    @Shadow
    @Final
    private GameProfile gameProfile;

    @Unique
    private int sam$replaceDeadline = -1;

    private ServerConfigurationPacketListenerMixin(MinecraftServer server, Connection connection, CommonListenerCookie cookie) {
        super(server, connection, cookie);
    }

    @Inject(method = "handleConfigurationFinished", cancellable = true, at = @At(value = "INVOKE",
        target = "Lnet/minecraft/server/network/ServerConfigurationPacketListenerImpl;finishCurrentTask(Lnet/minecraft/server/network/ConfigurationTask$Type;)V"))
    private void sam$replaceExistingSession(ServerboundFinishConfigurationPacket packet, CallbackInfo ci) {
        var players = server.getPlayerList();
        if (players.getPlayer(gameProfile.getId()) == null) {
            return;
        }
        if (sam$replaceDeadline < 0) {
            SAM_LOG.info("[auditoría] {} se autenticó desde otra conexión: reemplaza a la sesión anterior", gameProfile.getName());
            players.disconnectAllPlayersWithProfile(gameProfile);
            sam$replaceDeadline = server.getTickCount() + MAX_WAIT_TICKS;
        }
        if (server.getTickCount() < sam$replaceDeadline) {
            ci.cancel();
            var self = (ServerConfigurationPacketListenerImpl) (Object) this;
            server.tell(new TickTask(server.getTickCount() + 1, () -> {
                if (connection.isConnected()) {
                    self.handleConfigurationFinished(packet);
                }
            }));
        }
    }
}
