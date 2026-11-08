package dev.sam.server.perms;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.time.Instant;
import java.util.Locale;
import java.util.Optional;
import java.util.OptionalLong;
import java.util.concurrent.CompletableFuture;
import java.util.function.Function;
import java.util.function.Predicate;
import java.util.function.UnaryOperator;

import org.slf4j.Logger;

import com.mojang.brigadier.arguments.BoolArgumentType;
import com.mojang.brigadier.arguments.IntegerArgumentType;
import com.mojang.brigadier.arguments.StringArgumentType;
import com.mojang.brigadier.builder.LiteralArgumentBuilder;
import com.mojang.brigadier.context.CommandContext;

import dev.sam.common.perms.PermissionSet;
import dev.sam.common.perms.PermissionSet.Grant;
import dev.sam.common.perms.PermissionSet.Meta;
import dev.sam.common.perms.PermissionSet.Value;
import dev.sam.server.SamConsole;
import me.lucko.fabric.api.permissions.v0.OfflinePermissionCheckEvent;
import me.lucko.fabric.api.permissions.v0.OptionRequestEvent;
import me.lucko.fabric.api.permissions.v0.PermissionCheckEvent;
import net.fabricmc.fabric.api.command.v2.CommandRegistrationCallback;
import net.fabricmc.fabric.api.event.lifecycle.v1.ServerLifecycleEvents;
import net.fabricmc.fabric.api.event.lifecycle.v1.ServerTickEvents;
import net.fabricmc.fabric.api.util.TriState;
import net.fabricmc.loader.api.FabricLoader;
import net.minecraft.commands.CommandSourceStack;
import net.minecraft.commands.Commands;
import net.minecraft.network.chat.Component;
import net.minecraft.server.MinecraftServer;
import net.minecraft.server.level.ServerPlayer;

/**
 * Los permisos nativos de SAM (RF-PERM, docs/PERMISOS.md): el archivo {@code config/sam/permissions.json},
 * el proveedor de {@code fabric-permissions-api} (salvo que esté LuckPerms) y los comandos {@code /sam perms},
 * sensibles según RS-ADM-01.
 */
public final class SamPermissions {

    static final String ADMIN_OP_LEVEL = "SAM_ADMIN_OP_LEVEL";
    static final String RCON_SENSITIVE = "SAM_RCON_SENSITIVE_COMMANDS";
    private static final int EXPIRY_TICKS = 20 * 60;

    private final Logger log;
    private final Path file;
    private final int adminOpLevel;
    private final boolean rconSensitive;
    private final Predicate<String> verifiedSession;
    private final boolean luckPerms;
    /** Lo vigente; vacío si el archivo era inválido al arrancar (todo indefinido: nivel de OP). */
    private volatile Optional<PermissionSet> active = Optional.empty();
    private volatile MinecraftServer server;
    private int ticks;

    private SamPermissions(Logger log, Path file, int adminOpLevel, boolean rconSensitive, Predicate<String> verifiedSession) {
        this.log = log;
        this.file = file;
        this.adminOpLevel = adminOpLevel;
        this.rconSensitive = rconSensitive;
        this.verifiedSession = verifiedSession;
        this.luckPerms = FabricLoader.getInstance().isModLoaded("luckperms");
    }

    /**
     * Carga el archivo y registra el proveedor y los comandos (una vez, al iniciar el mod).
     *
     * @param verifiedSession si un nick completó el 2FA en su sesión actual
     */
    public static SamPermissions install(Logger log, Path file, java.util.Map<String, String> config, Predicate<String> verifiedSession) {
        var level = 2;
        try {
            level = Integer.parseInt(config.getOrDefault(ADMIN_OP_LEVEL, "2").strip());
        } catch (NumberFormatException e) {
            log.error("{} no es un número; se usa 2", ADMIN_OP_LEVEL);
        }
        var rcon = config.getOrDefault(RCON_SENSITIVE, "false").strip().equalsIgnoreCase("true");
        var perms = new SamPermissions(log, file, level, rcon, verifiedSession);
        perms.start();
        return perms;
    }

    private void start() {
        if (luckPerms) {
            log.warn("LuckPerms está instalado: los permisos de SAM quedan inactivos y manda LuckPerms (RF-PERM-03)");
        } else {
            loadAtStart();
            PermissionCheckEvent.EVENT.register((source, node) -> source instanceof CommandSourceStack stack
                && stack.getEntity() instanceof ServerPlayer player && player == stack.getPlayer()
                ? triState(check(player.getGameProfile().getName(), node)) : TriState.DEFAULT);
            OptionRequestEvent.EVENT.register((source, key) -> source instanceof CommandSourceStack stack
                && stack.getEntity() instanceof ServerPlayer player
                ? meta(player.getGameProfile().getName(), key) : Optional.empty());
            OfflinePermissionCheckEvent.EVENT.register((uuid, node) -> {
                var current = server;
                var name = current == null ? Optional.<String>empty()
                    : current.getProfileCache() == null ? Optional.<String>empty()
                    : current.getProfileCache().get(uuid).map(profile -> profile.getName());
                return CompletableFuture.completedFuture(name.map(n -> triState(check(n, node))).orElse(TriState.DEFAULT));
            });
        }
        ServerLifecycleEvents.SERVER_STARTING.register(s -> server = s);
        ServerTickEvents.END_SERVER_TICK.register(s -> {
            if (++ticks >= EXPIRY_TICKS) {
                ticks = 0;
                expire();
            }
        });
        CommandRegistrationCallback.EVENT.register((dispatcher, registry, environment) -> dispatcher.register(commands()));
    }

    private void loadAtStart() {
        try {
            if (!Files.exists(file)) {
                save(PermissionSet.empty());
                log.info("Permisos: se creó {} con el grupo default vacío", file);
            }
            active = Optional.of(PermissionSet.parse(Files.readString(file)));
            log.info("Permisos de SAM: {} grupos y {} jugadores ({})", active.get().groups().size(), active.get().users().size(), file);
        } catch (IOException | IllegalArgumentException e) {
            // RF-PERM-04: inválido al arrancar, ningún permiso propio; el archivo no se toca
            log.error("{}: {}. SAM no aplica permisos propios: rige el nivel de OP hasta que lo corrijas y uses /sam perms reload",
                file, e.getMessage());
        }
    }

    // ===== Consultas =====

    /** El permiso de un jugador en línea, con su sesión verificada o no. */
    public Value check(String nick, String node) {
        return active.map(set -> set.check(nick, node, Instant.now().getEpochSecond(), verifiedSession.test(nick)).value())
            .orElse(Value.UNDEFINED);
    }

    public Optional<String> meta(String nick, String key) {
        return active.flatMap(set -> set.meta(nick, key, Instant.now().getEpochSecond()));
    }

    private static TriState triState(Value value) {
        return switch (value) {
            case TRUE -> TriState.TRUE;
            case FALSE -> TriState.FALSE;
            case UNDEFINED -> TriState.DEFAULT;
        };
    }

    // ===== Origen de los comandos sensibles (RS-ADM-01) =====

    /** Consola real, RCON si se habilitó, o un admin en el juego con su sesión verificada. Nunca bloques ni funciones. */
    public boolean sensitiveAllowed(CommandSourceStack source) {
        if (SamConsole.isConsole(source)) {
            return true;
        }
        if (SamConsole.isRcon(source)) {
            return rconSensitive;
        }
        // Un jugador que lo escribió él mismo: no un bloque de comandos con "execute as"
        if (source.getEntity() instanceof ServerPlayer player
                && ((dev.sam.server.mixin.CommandSourceStackAccessor) source).sam$source() == player) {
            var nick = player.getGameProfile().getName();
            var admin = player.hasPermissions(adminOpLevel) || check(nick, "sam.admin") == Value.TRUE;
            return admin && verifiedSession.test(nick);
        }
        return false;
    }

    // ===== Vencimientos y archivo =====

    private synchronized void expire() {
        var current = active;
        if (current.isEmpty()) {
            return;
        }
        var expiry = current.get().expire(Instant.now().getEpochSecond());
        if (expiry.removed().isEmpty()) {
            return;
        }
        expiry.removed().forEach(what -> dev.sam.server.SamAudit.event("permisos.vencio", "SAM", "", String.valueOf(what)));
        apply(expiry.set());
    }

    private void apply(PermissionSet set) {
        try {
            save(set);
            active = Optional.of(set);
        } catch (IOException e) {
            throw new IllegalStateException("no se pudo guardar " + file + ": " + e.getMessage(), e);
        }
    }

    private void save(PermissionSet set) throws IOException {
        // RF-CFG-10: atómico y solo para el dueño
        dev.sam.common.config.SecureFiles.writeString(file, set.toJson());
    }

    // ===== /sam perms (docs/PERMISOS.md, sección 4) =====

    private LiteralArgumentBuilder<CommandSourceStack> commands() {
        var group = StringArgumentType.word();
        return Commands.literal("sam").then(Commands.literal("perms").requires(this::sensitiveAllowed)
            .then(Commands.literal("reload").executes(c -> reload(c.getSource())))
            .then(Commands.literal("check").then(Commands.argument("nick", StringArgumentType.word())
                .then(Commands.argument("nodo", StringArgumentType.word()).executes(c -> check(c)))))
            .then(Commands.literal("group")
                .then(Commands.literal("list").executes(c -> groupList(c.getSource())))
                .then(Commands.literal("info").then(Commands.argument("grupo", group).executes(c -> groupInfo(c))))
                .then(Commands.literal("create").then(Commands.argument("grupo", group)
                    .executes(c -> edit(c, "crea el grupo " + arg(c, "grupo"), s -> s.createGroup(arg(c, "grupo"), 0)))
                    .then(Commands.argument("peso", IntegerArgumentType.integer()).executes(c -> edit(c,
                        "crea el grupo " + arg(c, "grupo") + " con peso " + IntegerArgumentType.getInteger(c, "peso"),
                        s -> s.createGroup(arg(c, "grupo"), IntegerArgumentType.getInteger(c, "peso")))))))
                .then(Commands.literal("delete").then(Commands.argument("grupo", group)
                    .executes(c -> edit(c, "borra el grupo " + arg(c, "grupo"), s -> s.deleteGroup(arg(c, "grupo"))))))
                .then(Commands.literal("weight").then(Commands.argument("grupo", group).then(Commands.argument("peso", IntegerArgumentType.integer())
                    .executes(c -> edit(c, "peso de " + arg(c, "grupo") + " = " + IntegerArgumentType.getInteger(c, "peso"),
                        s -> s.setWeight(arg(c, "grupo"), IntegerArgumentType.getInteger(c, "peso")))))))
                .then(Commands.literal("parent")
                    .then(Commands.literal("add").then(Commands.argument("grupo", group).then(Commands.argument("padre", StringArgumentType.word())
                        .executes(c -> edit(c, arg(c, "grupo") + " hereda de " + arg(c, "padre"), s -> s.addParent(arg(c, "grupo"), arg(c, "padre")))))))
                    .then(Commands.literal("remove").then(Commands.argument("grupo", group).then(Commands.argument("padre", StringArgumentType.word())
                        .executes(c -> edit(c, arg(c, "grupo") + " deja de heredar de " + arg(c, "padre"),
                            s -> s.removeParent(arg(c, "grupo"), arg(c, "padre")))))))))
            .then(holder(Commands.literal("group"), "grupo", true))
            .then(Commands.literal("user")
                .then(Commands.literal("info").then(Commands.argument("nick", StringArgumentType.word()).executes(c -> userInfo(c))))
                .then(Commands.literal("group")
                    .then(Commands.literal("add").then(Commands.argument("nick", StringArgumentType.word()).then(Commands.argument("grupo", group)
                        .executes(c -> edit(c, arg(c, "nick") + " entra al grupo " + arg(c, "grupo"),
                            s -> s.addUserGroup(arg(c, "nick"), arg(c, "grupo"), OptionalLong.empty())))
                        .then(Commands.argument("duracion", StringArgumentType.word()).executes(c -> edit(c,
                            arg(c, "nick") + " entra al grupo " + arg(c, "grupo") + " por " + arg(c, "duracion"),
                            s -> s.addUserGroup(arg(c, "nick"), arg(c, "grupo"), until(arg(c, "duracion")))))))))
                    .then(Commands.literal("remove").then(Commands.argument("nick", StringArgumentType.word()).then(Commands.argument("grupo", group)
                        .executes(c -> edit(c, arg(c, "nick") + " sale del grupo " + arg(c, "grupo"),
                            s -> s.removeUserGroup(arg(c, "nick"), arg(c, "grupo")))))))))
            .then(holder(Commands.literal("user"), "nick", false)));
    }

    /**
     * {@code set|unset <nodo>} y {@code meta set|unset <clave>} para un grupo o un jugador (mismos argumentos),
     * como hijos de {@code group} o de {@code user}. Brigadier fusiona los nodos literales con el mismo nombre.
     */
    private LiteralArgumentBuilder<CommandSourceStack> holder(LiteralArgumentBuilder<CommandSourceStack> parent, String name, boolean isGroup) {
        Function<CommandContext<CommandSourceStack>, String> who = c -> (isGroup ? "grupo " : "") + arg(c, name);
        var set = Commands.literal("set").then(Commands.argument(name, StringArgumentType.word()).then(Commands.argument("nodo", StringArgumentType.word())
            .executes(c -> setNode(c, name, isGroup, true, OptionalLong.empty(), false))
            .then(Commands.argument("valor", BoolArgumentType.bool())
                .executes(c -> setNode(c, name, isGroup, BoolArgumentType.getBool(c, "valor"), OptionalLong.empty(), false))
                .then(Commands.literal("verified")
                    .executes(c -> setNode(c, name, isGroup, BoolArgumentType.getBool(c, "valor"), OptionalLong.empty(), true)))
                .then(Commands.argument("duracion", StringArgumentType.word())
                    .executes(c -> setNode(c, name, isGroup, BoolArgumentType.getBool(c, "valor"), until(arg(c, "duracion")), false))
                    .then(Commands.literal("verified")
                        .executes(c -> setNode(c, name, isGroup, BoolArgumentType.getBool(c, "valor"), until(arg(c, "duracion")), true)))))));
        var unset = Commands.literal("unset").then(Commands.argument(name, StringArgumentType.word()).then(Commands.argument("nodo", StringArgumentType.word())
            .executes(c -> edit(c, "quita " + arg(c, "nodo") + " a " + who.apply(c), s -> isGroup
                ? s.unsetGroupPermission(arg(c, name), arg(c, "nodo")) : s.unsetUserPermission(arg(c, name), arg(c, "nodo"))))));
        var meta = Commands.literal("meta")
            .then(Commands.literal("set").then(Commands.argument(name, StringArgumentType.word()).then(Commands.argument("clave", StringArgumentType.word())
                .then(Commands.argument("valor", StringArgumentType.string())
                    .executes(c -> setMeta(c, name, isGroup, OptionalLong.empty()))
                    .then(Commands.argument("duracion", StringArgumentType.word()).executes(c -> setMeta(c, name, isGroup, until(arg(c, "duracion")))))))))
            .then(Commands.literal("unset").then(Commands.argument(name, StringArgumentType.word()).then(Commands.argument("clave", StringArgumentType.word())
                .executes(c -> edit(c, "quita la meta " + arg(c, "clave") + " a " + who.apply(c), s -> isGroup
                    ? s.unsetGroupMeta(arg(c, name), arg(c, "clave")) : s.unsetUserMeta(arg(c, name), arg(c, "clave")))))));
        return parent.then(set).then(unset).then(meta);
    }

    private int setNode(CommandContext<CommandSourceStack> c, String name, boolean isGroup, boolean value, OptionalLong expires, boolean verified) {
        var grant = new Grant(value, expires, verified);
        var node = arg(c, "nodo");
        return edit(c, (isGroup ? "grupo " : "") + arg(c, name) + ": " + node + " = " + value + (expires.isPresent() ? " hasta " + expires.getAsLong() : "")
            + (verified ? " (solo verificado)" : ""), s -> isGroup ? s.setGroupPermission(arg(c, name), node, grant)
                : s.setUserPermission(arg(c, name), node, grant));
    }

    private int setMeta(CommandContext<CommandSourceStack> c, String name, boolean isGroup, OptionalLong expires) {
        var meta = new Meta(StringArgumentType.getString(c, "valor"), expires);
        var key = arg(c, "clave");
        return edit(c, (isGroup ? "grupo " : "") + arg(c, name) + ": meta " + key + " = \"" + meta.value() + "\""
            + (expires.isPresent() ? " hasta " + expires.getAsLong() : ""), s -> isGroup ? s.setGroupMeta(arg(c, name), key, meta)
                : s.setUserMeta(arg(c, name), key, meta));
    }

    private static String arg(CommandContext<CommandSourceStack> c, String name) {
        return StringArgumentType.getString(c, name);
    }

    private static OptionalLong until(String duration) {
        return OptionalLong.of(Instant.now().getEpochSecond() + PermissionSet.duration(duration));
    }

    /** Aplica un cambio: si es válido, se guarda, se audita y vale en el acto; si no, el motivo. */
    private synchronized int edit(CommandContext<CommandSourceStack> c, String description, UnaryOperator<PermissionSet> change) {
        var source = c.getSource();
        if (active.isEmpty()) {
            source.sendFailure(Component.literal("El archivo de permisos es inválido: corrígelo y usa /sam perms reload."));
            return 0;
        }
        try {
            apply(change.apply(active.get()));
        } catch (IllegalArgumentException | IllegalStateException e) {
            source.sendFailure(Component.literal("No se cambió: " + e.getMessage()));
            return 0;
        }
        dev.sam.server.SamAudit.event("permisos.cambio", source.getTextName(), "", description);
        source.sendSuccess(() -> Component.literal("Listo: " + description), false);
        return 1;
    }

    private synchronized int reload(CommandSourceStack source) {
        try {
            var set = PermissionSet.parse(Files.readString(file));
            active = Optional.of(set);
            dev.sam.server.SamAudit.event("permisos.recarga", source.getTextName(), "", String.valueOf(file));
            source.sendSuccess(() -> Component.literal("Permisos recargados: " + set.groups().size() + " grupos, " + set.users().size()
                + " jugadores."), false);
            return 1;
        } catch (IOException | IllegalArgumentException e) {
            // RF-PERM-04: en un reload inválido se mantiene lo anterior
            source.sendFailure(Component.literal("No se recargó (sigue lo anterior): " + e.getMessage()));
            return 0;
        }
    }

    private int check(CommandContext<CommandSourceStack> c) {
        var nick = arg(c, "nick").toLowerCase(Locale.ROOT);
        var node = arg(c, "nodo");
        var source = c.getSource();
        if (active.isEmpty()) {
            source.sendFailure(Component.literal("El archivo de permisos es inválido: rige el nivel de OP."));
            return 0;
        }
        var result = active.get().check(nick, node, Instant.now().getEpochSecond(), verifiedSession.test(nick));
        source.sendSuccess(() -> Component.literal(nick + " · " + node + ": " + switch (result.value()) {
            case TRUE -> "sí";
            case FALSE -> "no";
            case UNDEFINED -> "indefinido (decide el nivel de OP)";
        } + result.source().map(s -> " — por " + s + " (" + result.entry().orElseThrow() + ")").orElse("")
            + (verifiedSession.test(nick) ? " [sesión verificada]" : "")), false);
        return 1;
    }

    private int groupList(CommandSourceStack source) {
        active.ifPresentOrElse(set -> new java.util.TreeMap<>(set.groups()).forEach((name, group) ->
            source.sendSuccess(() -> Component.literal(name + " (peso " + group.weight() + ")"
                + (group.parents().isEmpty() ? "" : " ← " + String.join(", ", group.parents()))), false)),
            () -> source.sendFailure(Component.literal("El archivo de permisos es inválido.")));
        return 1;
    }

    private int groupInfo(CommandContext<CommandSourceStack> c) {
        var source = c.getSource();
        var group = active.map(set -> set.groups().get(arg(c, "grupo")));
        if (group.isEmpty() || group.get() == null) {
            source.sendFailure(Component.literal("No existe el grupo " + arg(c, "grupo")));
            return 0;
        }
        var g = group.get();
        source.sendSuccess(() -> Component.literal(arg(c, "grupo") + ": peso " + g.weight() + ", padres " + g.parents()
            + "\nnodos " + describe(g.permissions()) + "\nmetas " + describeMeta(g.meta())), false);
        return 1;
    }

    private int userInfo(CommandContext<CommandSourceStack> c) {
        var source = c.getSource();
        var nick = arg(c, "nick").toLowerCase(Locale.ROOT);
        var user = active.map(set -> set.users().get(nick));
        if (user.isEmpty() || user.get() == null) {
            source.sendSuccess(() -> Component.literal(nick + ": solo el grupo default"), false);
            return 1;
        }
        var u = user.get();
        var groups = new java.util.TreeMap<>(u.groups()).entrySet().stream()
            .map(e -> e.getKey() + (e.getValue().isPresent() ? " (hasta " + e.getValue().getAsLong() + ")" : "")).toList();
        source.sendSuccess(() -> Component.literal(nick + ": grupos " + groups + "\nnodos " + describe(u.permissions())
            + "\nmetas " + describeMeta(u.meta())), false);
        return 1;
    }

    private static String describe(java.util.Map<String, Grant> grants) {
        return new java.util.TreeMap<>(grants).entrySet().stream().map(e -> e.getKey() + "=" + e.getValue().value()
            + (e.getValue().expires().isPresent() ? " (hasta " + e.getValue().expires().getAsLong() + ")" : "")
            + (e.getValue().verified() ? " (verificado)" : "")).toList().toString();
    }

    private static String describeMeta(java.util.Map<String, Meta> metas) {
        return new java.util.TreeMap<>(metas).entrySet().stream().map(e -> e.getKey() + "=\"" + e.getValue().value() + "\""
            + (e.getValue().expires().isPresent() ? " (hasta " + e.getValue().expires().getAsLong() + ")" : "")).toList().toString();
    }
}
