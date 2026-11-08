package dev.sam.server;

import java.io.IOException;
import java.time.Instant;
import java.util.function.Predicate;

import com.mojang.brigadier.arguments.IntegerArgumentType;
import com.mojang.brigadier.context.CommandContext;

import dev.sam.common.audit.AuditLog;
import net.fabricmc.fabric.api.command.v2.CommandRegistrationCallback;
import net.minecraft.commands.CommandSourceStack;
import net.minecraft.commands.Commands;
import net.minecraft.network.chat.Component;

/**
 * {@code /sam audit verify|last [n]|export} (RF-AUTH-08a): comandos sensibles (RS-ADM-01), solo desde la consola
 * real o un admin verificado.
 */
final class SamAuditCommands {

    private static final int MAX_LAST = 20;

    private SamAuditCommands() {
    }

    static void install(Predicate<CommandSourceStack> sensitive) {
        CommandRegistrationCallback.EVENT.register((dispatcher, registry, environment) -> dispatcher.register(
            Commands.literal("sam").then(Commands.literal("audit").requires(sensitive)
                .then(Commands.literal("verify").executes(SamAuditCommands::verify))
                .then(Commands.literal("last").executes(c -> last(c, 10))
                    .then(Commands.argument("n", IntegerArgumentType.integer(1, MAX_LAST))
                        .executes(c -> last(c, IntegerArgumentType.getInteger(c, "n")))))
                .then(Commands.literal("export").executes(SamAuditCommands::export)))));
    }

    private static int verify(CommandContext<CommandSourceStack> c) {
        try {
            var result = AuditLog.verify(SamAudit.file());
            if (result.ok()) {
                c.getSource().sendSuccess(() -> Component.literal("Auditoría íntegra: " + result.lines() + " eventos."), false);
                SamAudit.event("auditoria.verificada", c.getSource().getTextName(), "", "íntegra, " + result.lines() + " eventos");
                return 1;
            }
            c.getSource().sendFailure(Component.literal("Auditoría ROTA en la línea " + result.brokenAt() + ": " + result.reason()));
            return 0;
        } catch (IOException e) {
            c.getSource().sendFailure(Component.literal("No se pudo leer la auditoría: " + e.getMessage()));
            return 0;
        }
    }

    private static int last(CommandContext<CommandSourceStack> c, int n) {
        try {
            var lines = AuditLog.last(SamAudit.file(), n);
            if (lines.isEmpty()) {
                c.getSource().sendSuccess(() -> Component.literal("La auditoría está vacía."), false);
            }
            for (var line : lines) {
                c.getSource().sendSuccess(() -> Component.literal(line), false);
            }
            return lines.size();
        } catch (IOException e) {
            c.getSource().sendFailure(Component.literal("No se pudo leer la auditoría: " + e.getMessage()));
            return 0;
        }
    }

    private static int export(CommandContext<CommandSourceStack> c) {
        try {
            var copy = AuditLog.export(SamAudit.file(), Instant.now());
            c.getSource().sendSuccess(() -> Component.literal("Auditoría exportada a " + copy), false);
            SamAudit.event("auditoria.exportada", c.getSource().getTextName(), "", String.valueOf(copy.getFileName()));
            return 1;
        } catch (IOException e) {
            c.getSource().sendFailure(Component.literal("No se pudo exportar la auditoría: " + e.getMessage()));
            return 0;
        }
    }
}
