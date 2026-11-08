package dev.sam.server.mixin;

import org.spongepowered.asm.mixin.Mixin;
import org.spongepowered.asm.mixin.injection.At;
import org.spongepowered.asm.mixin.injection.Inject;
import org.spongepowered.asm.mixin.injection.callback.CallbackInfo;

import com.mojang.brigadier.ParseResults;

import dev.sam.server.SamAudit;
import net.minecraft.commands.CommandSourceStack;
import net.minecraft.commands.Commands;

/** RF-ADM-06a (H-09): los comandos sensibles de vanilla van a la auditoría, de quien sea (jugador, consola o RCON). */
@Mixin(Commands.class)
public abstract class CommandsAuditMixin {

    @Inject(method = "performCommand", at = @At("HEAD"))
    private void sam$audit(ParseResults<CommandSourceStack> parse, String command, CallbackInfo ci) {
        SamAudit.command(parse.getContext().getSource().getTextName(), command);
    }
}
