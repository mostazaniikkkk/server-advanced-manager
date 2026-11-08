package dev.sam.server.mixin;

import org.spongepowered.asm.mixin.Mixin;
import org.spongepowered.asm.mixin.injection.At;
import org.spongepowered.asm.mixin.injection.Inject;
import org.spongepowered.asm.mixin.injection.callback.CallbackInfoReturnable;

import com.mojang.authlib.GameProfile;

import dev.sam.server.SamServer;
import net.minecraft.server.MinecraftServer;

/**
 * RF-ADM-04 / H-01: el nivel de OP de un jugador solo vale si completó el 2FA en esta sesión. Antes, juega como
 * jugador normal (nivel 0). La consola, RCON, los bloques de comando y las funciones no pasan por aquí.
 */
@Mixin(MinecraftServer.class)
public abstract class MinecraftServerPermissionsMixin {

    @Inject(method = "getProfilePermissions", at = @At("RETURN"), cancellable = true)
    private void sam$opOnlyWhenVerified(GameProfile profile, CallbackInfoReturnable<Integer> cir) {
        if (cir.getReturnValueI() > 0 && !SamServer.verified(profile.getName())) {
            cir.setReturnValue(0);
        }
    }
}
