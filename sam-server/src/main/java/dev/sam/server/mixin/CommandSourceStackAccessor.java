package dev.sam.server.mixin;

import org.spongepowered.asm.mixin.Mixin;
import org.spongepowered.asm.mixin.gen.Accessor;

import net.minecraft.commands.CommandSource;
import net.minecraft.commands.CommandSourceStack;

/**
 * Quién ejecuta un comando: la consola real es el propio {@code MinecraftServer}; RCON y los jugadores son
 * otros {@link CommandSource}. Lo usan los comandos reservados a la consola (RS-ADM-01).
 */
@Mixin(CommandSourceStack.class)
public interface CommandSourceStackAccessor {

    @Accessor("source")
    CommandSource sam$source();
}
