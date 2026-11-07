package dev.sam.server.mixin;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.spongepowered.asm.mixin.Mixin;
import org.spongepowered.asm.mixin.Unique;
import org.spongepowered.asm.mixin.injection.At;
import org.spongepowered.asm.mixin.injection.Redirect;

import com.mojang.authlib.GameProfile;

import net.minecraft.server.network.ServerLoginPacketListenerImpl;
import net.minecraft.server.players.PlayerList;

/**
 * RN-04 (RF-AUTH-06c): vanilla expulsa a quien tenga el mismo nick apenas otra conexión termina el login
 * (antes de que SAM pida la contraseña). En offline cualquiera podría echar a otro jugador así. Aquí no se
 * expulsa a nadie: la sesión anterior se reemplaza recién cuando la nueva se autentica
 * ({@link ServerConfigurationPacketListenerMixin}).
 */
@Mixin(ServerLoginPacketListenerImpl.class)
public abstract class ServerLoginPacketListenerMixin {

    @Unique
    private static final Logger SAM_LOG = LoggerFactory.getLogger("SAM");

    @Redirect(method = "verifyLoginAndFinishConnectionSetup", at = @At(value = "INVOKE",
        target = "Lnet/minecraft/server/players/PlayerList;disconnectAllPlayersWithProfile(Lcom/mojang/authlib/GameProfile;)Z"))
    private boolean sam$keepExistingSession(PlayerList players, GameProfile profile) {
        if (players.getPlayer(profile.getId()) != null) {
            SAM_LOG.info("[auditoría] Otra conexión usa el nick de {}, que está conectado: no se lo expulsa; "
                + "solo lo reemplaza si se autentica", profile.getName());
        }
        return false;
    }
}
