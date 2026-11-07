package dev.sam.client.mixin;

import org.spongepowered.asm.mixin.Mixin;
import org.spongepowered.asm.mixin.injection.At;
import org.spongepowered.asm.mixin.injection.Redirect;

import dev.sam.client.net.SamTlsConnection;
import net.minecraft.client.multiplayer.ServerStatusPinger;
import net.minecraft.network.Connection;

/**
 * La lista de servidores descarta en cada tick las conexiones que no están conectadas. Por WebSocket,
 * vanilla espera el túnel y el TLS de SAM sin canal: la conexión se descartaría en el primer tick y la
 * entrada quedaría en "Conectando..." para siempre. Mientras espera, se conserva.
 */
@Mixin(ServerStatusPinger.class)
public abstract class ServerStatusPingerMixin {

    @Redirect(method = "tick", at = @At(value = "INVOKE", target = "Lnet/minecraft/network/Connection;isConnected()Z"))
    private boolean sam$keepWaiting(Connection connection) {
        return connection.isConnected() || ((SamTlsConnection) connection).sam$waiting();
    }
}
