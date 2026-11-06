package dev.sam.client.mixin;

import org.spongepowered.asm.mixin.Mixin;
import org.spongepowered.asm.mixin.injection.At;
import org.spongepowered.asm.mixin.injection.Inject;
import org.spongepowered.asm.mixin.injection.callback.CallbackInfoReturnable;

import dev.sam.client.net.SamClientNet;
import net.minecraft.client.multiplayer.resolver.ServerAddress;

/**
 * Minecraft solo entiende host:puerto. Una dirección ws://host/ruta o wss://host/ruta
 * (PROTOCOLO.md 2.3) se acepta y se convierte a host:puerto; SAM recuerda la ruta y el transporte.
 */
@Mixin(ServerAddress.class)
public abstract class ServerAddressMixin {

    @Inject(method = "parseString", at = @At("HEAD"), cancellable = true)
    private static void sam$parseWebSocket(String input, CallbackInfoReturnable<ServerAddress> cir) {
        SamClientNet.webSocketAddress(input)
            .ifPresent(address -> cir.setReturnValue(new ServerAddress(address.host(), address.port())));
    }

    @Inject(method = "isValidAddress", at = @At("HEAD"), cancellable = true)
    private static void sam$validWebSocket(String input, CallbackInfoReturnable<Boolean> cir) {
        if (SamClientNet.looksLikeWebSocket(input)) {
            cir.setReturnValue(SamClientNet.webSocketAddress(input).isPresent());
        }
    }
}
