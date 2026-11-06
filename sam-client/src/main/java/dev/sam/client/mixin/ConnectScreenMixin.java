package dev.sam.client.mixin;

import org.spongepowered.asm.mixin.Mixin;
import org.spongepowered.asm.mixin.injection.At;
import org.spongepowered.asm.mixin.injection.Inject;
import org.spongepowered.asm.mixin.injection.callback.CallbackInfo;

import dev.sam.client.net.SamClientNet;
import net.minecraft.client.Minecraft;
import net.minecraft.client.gui.screens.ConnectScreen;
import net.minecraft.client.gui.screens.Screen;
import net.minecraft.client.multiplayer.ServerData;
import net.minecraft.client.multiplayer.TransferState;
import net.minecraft.client.multiplayer.resolver.ServerAddress;

/** Guarda la dirección tal como la escribió el jugador: el pin se asocia a ese nombre (PROTOCOLO.md 3.3). */
@Mixin(ConnectScreen.class)
public abstract class ConnectScreenMixin {

    @Inject(method = "startConnecting", at = @At("HEAD"))
    private static void sam$rememberAddress(Screen parent, Minecraft minecraft, ServerAddress address, ServerData data,
            boolean quickPlay, TransferState transfer, CallbackInfo ci) {
        SamClientNet.typed(address.getHost(), address.getPort());
    }
}
