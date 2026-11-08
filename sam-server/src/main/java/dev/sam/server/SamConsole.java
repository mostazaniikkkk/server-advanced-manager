package dev.sam.server;

import dev.sam.server.mixin.CommandSourceStackAccessor;
import net.minecraft.commands.CommandSourceStack;
import net.minecraft.server.MinecraftServer;
import net.minecraft.server.rcon.RconConsoleSource;

/**
 * El origen de un comando para los comandos sensibles (RS-ADM-01). En 1.21.1 las funciones de los datapacks
 * ({@code tick}, {@code load}) corren con el propio servidor como origen, igual que la consola; por eso la
 * consola real se marca: solo lo que entra por la entrada estándar mientras se procesa (mixin sobre
 * {@code DedicatedServer#handleConsoleInputs}).
 */
public final class SamConsole {

    private static final ThreadLocal<Boolean> READING = ThreadLocal.withInitial(() -> false);

    private SamConsole() {
    }

    /** Lo llama el mixin al empezar y al terminar de procesar lo que se escribió en la consola. */
    public static void reading(boolean value) {
        READING.set(value);
    }

    /** El comando lo escribió el operador en la consola real del servidor. */
    public static boolean isConsole(CommandSourceStack source) {
        return READING.get() && ((CommandSourceStackAccessor) source).sam$source() instanceof MinecraftServer;
    }

    public static boolean isRcon(CommandSourceStack source) {
        return ((CommandSourceStackAccessor) source).sam$source() instanceof RconConsoleSource;
    }
}
