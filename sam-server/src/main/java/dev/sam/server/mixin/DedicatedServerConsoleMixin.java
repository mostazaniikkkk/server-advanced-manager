package dev.sam.server.mixin;

import org.spongepowered.asm.mixin.Mixin;
import org.spongepowered.asm.mixin.injection.At;
import org.spongepowered.asm.mixin.injection.Inject;
import org.spongepowered.asm.mixin.injection.callback.CallbackInfo;

import dev.sam.server.SamConsole;
import net.minecraft.server.dedicated.DedicatedServer;

/** Marca los comandos que escribió el operador en la consola real (ver {@link SamConsole}). */
@Mixin(DedicatedServer.class)
abstract class DedicatedServerConsoleMixin {

    @Inject(method = "handleConsoleInputs", at = @At("HEAD"))
    private void sam$consoleStart(CallbackInfo info) {
        SamConsole.reading(true);
    }

    @Inject(method = "handleConsoleInputs", at = @At("RETURN"))
    private void sam$consoleEnd(CallbackInfo info) {
        SamConsole.reading(false);
    }
}
