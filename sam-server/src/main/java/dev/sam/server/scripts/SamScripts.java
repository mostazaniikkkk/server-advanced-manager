package dev.sam.server.scripts;

import java.io.IOException;
import java.nio.file.Path;
import java.security.PrivateKey;
import java.time.Duration;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import org.slf4j.Logger;

import com.mojang.brigadier.arguments.StringArgumentType;

import dev.sam.common.lua.ScriptHost;
import dev.sam.common.lua.ScriptLimits;
import dev.sam.common.scripts.KeyId;
import dev.sam.common.scripts.ScriptCatalog;
import dev.sam.common.scripts.ServerDelivery;
import dev.sam.common.scripts.TrustStore;
import net.fabricmc.fabric.api.command.v2.CommandRegistrationCallback;
import net.fabricmc.fabric.api.event.lifecycle.v1.ServerLifecycleEvents;
import net.fabricmc.fabric.api.event.lifecycle.v1.ServerTickEvents;
import net.fabricmc.fabric.api.message.v1.ServerMessageEvents;
import net.fabricmc.fabric.api.networking.v1.ServerPlayConnectionEvents;
import net.fabricmc.fabric.api.resource.ResourceManagerHelper;
import net.fabricmc.fabric.api.resource.SimpleSynchronousResourceReloadListener;
import net.minecraft.commands.CommandSourceStack;
import net.minecraft.commands.Commands;
import net.minecraft.network.chat.Component;
import net.minecraft.resources.ResourceLocation;
import net.minecraft.server.MinecraftServer;
import net.minecraft.server.packs.PackType;
import net.minecraft.server.packs.resources.ResourceManager;
import net.minecraft.server.level.ServerPlayer;

/**
 * Los scripts Lua del servidor (RF-LUA-01/02/03/07): se leen de {@code data/<ns>/sam_scripts/<script>/} en
 * cada carga de datapacks ({@code /reload} incluido), se verifican contra el trust store y corren en el
 * {@link ScriptHost} con los eventos y el tick del servidor. Comandos {@code /sam scripts}.
 */
public final class SamScripts implements SimpleSynchronousResourceReloadListener {

    static final String DEV_MODE = "SAM_SCRIPTS_DEV_MODE";
    static final String ENABLED = "SAM_SCRIPTS_ENABLED";
    static final String MAX_MEMORY = "SAM_SCRIPTS_MAX_MEMORY";
    static final String MAX_CALL_MS = "SAM_SCRIPTS_MAX_CALL_MS";
    static final String ON_REJECT = "SAM_SCRIPTS_CLIENT_ON_REJECT";
    private static final String FOLDER = "sam_scripts";
    private static final int MAX_FILE_BYTES = 512 * 1024;

    private final Logger log;
    private final Path keys;
    private final boolean devMode;
    private final ScriptHost host;
    private final ClientScriptsDelivery delivery;
    private final MediaRelay media;
    /** El tope de mensajes por jugador y script ({@code nick/script}). */
    private final Map<String, dev.sam.common.lua.MessageBudget> budgets = new HashMap<>();
    private final Map<String, Integer> warned = new HashMap<>();
    static final net.minecraft.network.protocol.common.custom.CustomPacketPayload.Type<dev.sam.server.auth.SamPayload> LUA_MSG =
        dev.sam.server.auth.SamPayload.type(dev.sam.common.proto.scripts.LuaMessage.ID);
    private volatile MinecraftServer server;
    private Map<String, Map<String, byte[]>> folders = Map.of();
    /** Los comandos que SAM agregó al dispatcher actual (al recrearse con /reload, se empieza de cero). */
    private Object installedOn;
    private final java.util.Set<String> installed = new HashSet<>();

    /** Dónde se guardan los datos de los scripts ({@code storage}); vacío si no se pudo saber. */
    private Optional<Path> dataDir = Optional.empty();
    private final Map<String, dev.sam.common.lua.ScriptStore> stores = new HashMap<>();
    private int ticksSinceSave;
    private static final int SAVE_TICKS = 100;

    private SamScripts(Logger log, Path keys, boolean devMode, ScriptLimits limits, ServerDelivery.OnReject onReject) {
        this.log = log;
        this.keys = keys;
        this.devMode = devMode;
        this.host = new ScriptHost(new Bridge(), limits);
        this.delivery = new ClientScriptsDelivery(log, onReject);
        this.media = new MediaRelay(log);
    }

    /** La clave de la identidad del servidor, para firmar la keylist que va a los clientes (RS-SIG-05). */
    public void identity(PrivateKey key) {
        delivery.identity(key);
    }

    /**
     * Registra todo (una vez, al iniciar el mod, después del login), salvo que {@value #ENABLED} sea
     * {@code false}.
     */
    public static Optional<SamScripts> install(Logger log, Path keys, Map<String, String> config, Optional<Path> dataDir) {
        if (config.getOrDefault(ENABLED, "true").strip().equalsIgnoreCase("false")) {
            log.info("Scripts de SAM desactivados ({}=false)", ENABLED);
            return Optional.empty();
        }
        ServerDelivery.OnReject onReject;
        try {
            onReject = ServerDelivery.OnReject.parse(config.getOrDefault(ON_REJECT, "per_script"));
        } catch (IllegalArgumentException e) {
            // Falla cerrado: rechazar cualquier script expulsa
            log.error("{}. Se usa kick.", e.getMessage());
            onReject = ServerDelivery.OnReject.KICK;
        }
        var devMode = config.getOrDefault(DEV_MODE, "false").strip().equalsIgnoreCase("true");
        var limits = new ScriptLimits(Duration.ofMillis(Long.parseLong(config.getOrDefault(MAX_CALL_MS, "50").strip())),
            memory(config.getOrDefault(MAX_MEMORY, "32MB")), 64 * 1024);
        if (devMode) {
            // RS-SIG-04: visible en el log; los scripts sin firma nunca van a los clientes
            log.warn("MODO DESARROLLO DE SCRIPTS ACTIVO: se aceptan scripts sin firmar del lado servidor ({}=true)", DEV_MODE);
        }
        var scripts = new SamScripts(log, keys, devMode, limits, onReject);
        scripts.dataDir = dataDir;
        scripts.delivery.install();
        scripts.installMessages();
        scripts.media.install();
        ResourceManagerHelper.get(PackType.SERVER_DATA).registerReloadListener(scripts);
        ServerLifecycleEvents.SERVER_STARTING.register(s -> scripts.server = s);
        // Los comandos de los scripts entran al árbol cuando existe: al terminar de arrancar y tras cada /reload
        ServerLifecycleEvents.SERVER_STARTED.register(scripts::installCommands);
        ServerLifecycleEvents.END_DATA_PACK_RELOAD.register((s, resources, success) -> scripts.installCommands(s));
        ServerLifecycleEvents.SERVER_STOPPED.register(s -> {
            scripts.host.load(List.of());
            scripts.saveStores();
        });
        ServerTickEvents.END_SERVER_TICK.register(s -> {
            scripts.host.tick();
            // Los datos guardados de los scripts van al disco a lo sumo cada 5 s, y solo si cambiaron
            if (++scripts.ticksSinceSave >= SAVE_TICKS) {
                scripts.ticksSinceSave = 0;
                scripts.saveStores();
            }
        });
        // Los eventos se encolan en el hilo del servidor: JOIN llega antes de que el jugador esté en la lista
        // y DISCONNECT puede llegar desde un hilo de red. Lua solo corre en el hilo del servidor.
        ServerPlayConnectionEvents.JOIN.register((handler, sender, s) ->
            scripts.later(s, ScriptHost.Event.JOIN, player(handler.getPlayer()), Optional.empty()));
        ServerPlayConnectionEvents.DISCONNECT.register((handler, s) -> {
            scripts.later(s, ScriptHost.Event.QUIT, player(handler.getPlayer()), Optional.empty());
            var nick = handler.getPlayer().getGameProfile().getName();
            s.execute(() -> {
                scripts.delivery.forget(nick);
                scripts.budgets.keySet().removeIf(key -> key.startsWith(nick + "/"));
            });
        });
        ServerMessageEvents.CHAT_MESSAGE.register((message, sender, params) ->
            scripts.later(sender.server, ScriptHost.Event.CHAT, player(sender), Optional.of(message.signedContent())));
        CommandRegistrationCallback.EVENT.register((dispatcher, registry, environment) -> dispatcher.register(Commands.literal("sam")
            .then(Commands.literal("scripts").requires(source -> source.hasPermission(4))
                .then(Commands.literal("list").executes(c -> scripts.list(c.getSource())))
                .then(Commands.literal("reload").executes(c -> scripts.reloadCommand(c.getSource())))
                .then(Commands.literal("errors").then(Commands.argument("script", StringArgumentType.word())
                    .executes(c -> scripts.errors(c.getSource(), StringArgumentType.getString(c, "script")))))
                .then(Commands.literal("trust")
                    .then(Commands.literal("list").executes(c -> scripts.trustList(c.getSource())))
                    .then(Commands.literal("confirm").then(Commands.argument("key_id", StringArgumentType.word())
                        .executes(c -> scripts.trustConfirm(c.getSource(), StringArgumentType.getString(c, "key_id")))))))));
        return Optional.of(scripts);
    }

    // ===== storage (RS-LUA-02b): <mundo>/sam/scripts/<id>.dat =====

    private Optional<dev.sam.common.lua.ScriptStore> store(String script) {
        if (dataDir.isEmpty()) {
            return Optional.empty();
        }
        return Optional.of(stores.computeIfAbsent(script, id -> {
            var file = dataDir.get().resolve(id + ".dat");
            if (!java.nio.file.Files.exists(file)) {
                return new dev.sam.common.lua.ScriptStore();
            }
            try {
                return dev.sam.common.lua.ScriptStore.decode(java.nio.file.Files.readAllBytes(file));
            } catch (IOException | dev.sam.common.proto.ProtocolException e) {
                var bad = file.resolveSibling(id + ".dat.bad");
                log.error("Los datos guardados del script {} están dañados ({}): se apartan en {} y el script empieza vacío", id,
                    e.getMessage(), bad);
                try {
                    java.nio.file.Files.move(file, bad, java.nio.file.StandardCopyOption.REPLACE_EXISTING);
                } catch (IOException moveError) {
                    log.error("No se pudo apartar {}: {}", file, moveError.getMessage());
                }
                return new dev.sam.common.lua.ScriptStore();
            }
        }));
    }

    private void saveStores() {
        for (var entry : stores.entrySet()) {
            var store = entry.getValue();
            if (!store.dirty()) {
                continue;
            }
            var file = dataDir.orElseThrow().resolve(entry.getKey() + ".dat");
            try {
                // RF-CFG-10: atómico y solo para el dueño
                dev.sam.common.config.SecureFiles.write(file, store.encode());
                store.saved();
            } catch (IOException e) {
                log.error("No se pudieron guardar los datos del script {}: {}", entry.getKey(), e.getMessage());
            }
        }
    }

    /** {@code sam:lua_msg} (PROTOCOLO.md 5.7): entre la parte de cliente y la de servidor de un mismo script. */
    private void installMessages() {
        net.fabricmc.fabric.api.networking.v1.PayloadTypeRegistry.playC2S().register(LUA_MSG,
            dev.sam.server.auth.SamPayload.codec(LUA_MSG, dev.sam.common.proto.scripts.LuaMessage.MAX_BYTES));
        net.fabricmc.fabric.api.networking.v1.PayloadTypeRegistry.playS2C().register(LUA_MSG,
            dev.sam.server.auth.SamPayload.codec(LUA_MSG, dev.sam.common.proto.scripts.LuaMessage.MAX_BYTES));
        net.fabricmc.fabric.api.networking.v1.ServerPlayNetworking.registerGlobalReceiver(LUA_MSG, (payload, context) -> {
            var sender = context.player();
            sender.server.execute(() -> onMessage(sender, payload));
        });
    }

    private void onMessage(ServerPlayer sender, dev.sam.server.auth.SamPayload payload) {
        var nick = sender.getGameProfile().getName();
        try {
            var message = dev.sam.common.proto.SamReader.decode(io.netty.buffer.Unpooled.wrappedBuffer(payload.data()),
                dev.sam.common.proto.scripts.LuaMessage.MAX_BYTES, dev.sam.common.proto.scripts.LuaMessage::read);
            if (!delivery.accepted(nick, message.script())) {
                return;
            }
            var tick = sender.server.getTickCount();
            if (!budgets.computeIfAbsent(nick + "/" + message.script(), k -> new dev.sam.common.lua.MessageBudget()).take(tick)) {
                // Un aviso por segundo como mucho
                if (tick - warned.getOrDefault(nick, -20) >= 20) {
                    warned.put(nick, tick);
                    log.warn("{} superó el tope de mensajes del script {}: se descartan", nick, message.script());
                }
                return;
            }
            host.deliver(message.script(), Optional.of(player(sender)), message.channel(), message.data());
        } catch (dev.sam.common.proto.ProtocolException e) {
            dev.sam.server.SamAudit.event("protocolo.error", nick, "", e.code() + " (" + e.getMessage() + ")");
            sender.connection.disconnect(Component.literal("Error de protocolo. [" + e.code() + "]"));
        }
    }

    /** Encola el evento para el próximo tick del hilo del servidor (nunca corre en el acto ni en otro hilo). */
    private void later(MinecraftServer s, ScriptHost.Event event, ScriptHost.Player who, Optional<String> text) {
        s.tell(new net.minecraft.server.TickTask(s.getTickCount(), () -> host.fire(event, who, text)));
    }

    @Override
    public ResourceLocation getFabricId() {
        return ResourceLocation.fromNamespaceAndPath("sam", "scripts");
    }

    /** Cada carga de datapacks: se leen los scripts y se vuelven a cargar todos. */
    @Override
    public void onResourceManagerReload(ResourceManager manager) {
        var found = new LinkedHashMap<String, Map<String, byte[]>>();
        var owner = new HashMap<String, String>();
        var conflicts = new HashSet<String>();
        for (var entry : manager.listResources(FOLDER, location -> true).entrySet()) {
            var path = entry.getKey().getPath().substring(FOLDER.length() + 1);
            var slash = path.indexOf('/');
            if (slash < 0) {
                continue;
            }
            var script = path.substring(0, slash);
            var namespace = entry.getKey().getNamespace();
            if (!owner.computeIfAbsent(script, s -> namespace).equals(namespace)) {
                conflicts.add(script);
                continue;
            }
            try (var in = entry.getValue().open()) {
                var bytes = in.readNBytes(MAX_FILE_BYTES + 1);
                if (bytes.length > MAX_FILE_BYTES) {
                    log.error("Script {}: {} supera los {} KiB; el script no carga", script, path, MAX_FILE_BYTES / 1024);
                    conflicts.add(script);
                    continue;
                }
                found.computeIfAbsent(script, s -> new LinkedHashMap<>()).put(path.substring(slash + 1), bytes);
            } catch (IOException e) {
                log.error("Script {}: no se pudo leer {}: {}", script, path, e.getMessage());
                conflicts.add(script);
            }
        }
        for (var script : conflicts) {
            if (found.remove(script) != null && owner.containsKey(script)) {
                log.error("Script {}: no carga (definido en dos datapacks o con un archivo ilegible)", script);
            }
        }
        folders = found;
        reload();
    }

    /** Vuelve a leer el trust store y carga los scripts de la última lectura de datapacks. */
    private void reload() {
        TrustStore trust;
        try {
            trust = TrustStore.load(keys);
        } catch (IOException e) {
            log.error("No se pudo leer el trust store {}: {}. No corre ningún script.", keys, e.getMessage());
            host.load(List.of());
            delivery.update(List.of(), List.of());
            return;
        }
        trust.problems().forEach(problem -> log.warn("Trust store: {}", problem));
        trust.pending().forEach(p -> log.warn("Clave de firma {} ({}) pendiente: confírmala desde la consola con "
            + "«sam scripts trust confirm {}»", p.keyId().hex(), p.file(), p.keyId().hex()));
        var catalog = ScriptCatalog.build(folders, trust.active(), devMode);
        // Los nombres que ya tiene el servidor no se pueden usar (si todavía no arrancó, se revisa al instalar)
        var current = server;
        if (current != null) {
            host.reserveCommands(current.getCommands().getDispatcher().getRoot().getChildren().stream()
                .map(com.mojang.brigadier.tree.CommandNode::getName).filter(name -> !ownedHere(current, name)).toList());
        }
        catalog.warnings().forEach(log::warn);
        catalog.rejected().forEach(r -> log.error("Script {} rechazado: {}", r.id(), r.reason()));
        host.load(catalog.server());
        delivery.update(catalog.client(), trust.entries());
        for (var status : host.status()) {
            status.errors().forEach(error -> log.error("Script {}: {}", status.id(), error));
        }
        log.info("Scripts de SAM: {} cargados, {} rechazados, {} de cliente ofrecidos", host.status().stream()
            .filter(s -> s.state() == ScriptHost.State.RUNNING).count(), catalog.rejected().size()
                + host.status().stream().filter(s -> s.state() != ScriptHost.State.RUNNING).count(), delivery.offered());
    }

    // ===== Comandos (RF-LUA-07) =====

    private int list(CommandSourceStack source) {
        var status = host.status();
        if (status.isEmpty()) {
            source.sendSuccess(() -> Component.literal("No hay scripts cargados."), false);
        }
        for (var s : status) {
            source.sendSuccess(() -> Component.literal(s.id() + ": " + state(s.state()) + (s.errors().isEmpty() ? ""
                : " (" + s.errors().size() + " errores, ver /sam scripts errors " + s.id() + ")")), false);
        }
        return status.size();
    }

    private int errors(CommandSourceStack source, String id) {
        var status = host.status().stream().filter(s -> s.id().equals(id)).findFirst();
        if (status.isEmpty()) {
            source.sendFailure(Component.literal("No hay un script " + id));
            return 0;
        }
        if (status.get().errors().isEmpty()) {
            source.sendSuccess(() -> Component.literal(id + " no tiene errores."), false);
        }
        status.get().errors().forEach(e -> source.sendSuccess(() -> Component.literal(e), false));
        return status.get().errors().size();
    }

    private int reloadCommand(CommandSourceStack source) {
        reload();
        installCommands(source.getServer());
        source.sendSuccess(() -> Component.literal("Scripts recargados (detalles en el log del servidor)."), true);
        return 1;
    }

    private int trustList(CommandSourceStack source) {
        try {
            var trust = TrustStore.load(keys);
            trust.active().forEach(k -> source.sendSuccess(() -> Component.literal("activa: " + k.keyId().hex()), false));
            trust.pending().forEach(p -> source.sendSuccess(() -> Component.literal("pendiente: " + p.keyId().hex() + " (" + p.file() + ")"),
                false));
            return trust.active().size();
        } catch (IOException e) {
            source.sendFailure(Component.literal("No se pudo leer el trust store: " + e.getMessage()));
            return 0;
        }
    }

    /** Solo desde la consola real del servidor: ni jugadores ni RCON (RS-SIG-03, RS-ADM-01). */
    private int trustConfirm(CommandSourceStack source, String keyId) {
        // Solo la consola real: una función de datapack también corre con el servidor como origen (SamConsole)
        if (!dev.sam.server.SamConsole.isConsole(source)) {
            source.sendFailure(Component.literal("Solo se puede confirmar una clave desde la consola del servidor."));
            return 0;
        }
        try {
            if (!TrustStore.confirm(keys, KeyId.of(keyId))) {
                source.sendFailure(Component.literal("No hay una clave pendiente con key_id " + keyId));
                return 0;
            }
        } catch (IllegalArgumentException | IOException e) {
            source.sendFailure(Component.literal("No se pudo confirmar: " + e.getMessage()));
            return 0;
        }
        dev.sam.server.SamAudit.event("scripts.clave", "consola", "", "clave de firma " + keyId + " confirmada");
        reload();
        installCommands(source.getServer());
        source.sendSuccess(() -> Component.literal("Clave " + keyId + " confirmada; scripts recargados."), true);
        return 1;
    }

    // ===== Comandos de los scripts (capacidad commands, RF-LUA-03) =====

    private boolean ownedHere(MinecraftServer s, String name) {
        return installedOn == s.getCommands().getDispatcher() && installed.contains(name);
    }

    /**
     * Agrega al árbol de comandos los que registraron los scripts y se lo reenvía a los jugadores. Un nombre
     * que ya tiene el servidor (vanilla u otro mod) no se pisa: se informa y queda sin registrar.
     */
    private void installCommands(MinecraftServer s) {
        var dispatcher = s.getCommands().getDispatcher();
        if (installedOn != dispatcher) {
            installedOn = dispatcher;
            installed.clear();
        }
        for (var command : host.commands()) {
            var name = command.name();
            if (installed.contains(name)) {
                continue;
            }
            if (dispatcher.getRoot().getChild(name) != null) {
                log.error("Script {}: /{} ya existe en el servidor; no se registra", command.script(), name);
                continue;
            }
            var level = command.permission();
            var node = command.node();
            // Con nodo, manda el sistema de permisos (SAM o LuckPerms); lo indefinido cae en el nivel de OP
            dispatcher.register(Commands.literal(name).requires(source -> node.isPresent()
                    ? me.lucko.fabric.api.permissions.v0.Permissions.check(source, node.get(), level) : source.hasPermission(level))
                .executes(c -> runScriptCommand(name, c.getSource(), ""))
                .then(Commands.argument("args", StringArgumentType.greedyString())
                    .executes(c -> runScriptCommand(name, c.getSource(), StringArgumentType.getString(c, "args")))));
            installed.add(name);
        }
        for (var player : s.getPlayerList().getPlayers()) {
            s.getCommands().sendCommands(player);
        }
    }

    private int runScriptCommand(String name, CommandSourceStack source, String args) {
        var who = Optional.ofNullable(source.getPlayer()).map(SamScripts::player);
        var outcome = host.runCommand(name, who, args);
        if (outcome.error().isPresent()) {
            // Al jugador, solo la primera línea (sin el stack de Lua); el detalle queda en /sam scripts errors
            source.sendFailure(Component.literal("/" + name + ": " + outcome.error().get().lines().findFirst().orElse("")));
            return 0;
        }
        outcome.value().ifPresent(reply -> source.sendSuccess(() -> Component.literal(reply), false));
        return 1;
    }

    private static String state(ScriptHost.State state) {
        return switch (state) {
            case RUNNING -> "corriendo";
            case SUSPENDED -> "SUSPENDIDO (se pasó de sus límites)";
            case FAILED -> "no cargó";
        };
    }

    private static ScriptHost.Player player(ServerPlayer player) {
        return new ScriptHost.Player(player.getGameProfile().getName(), player.getUUID().toString());
    }

    /** {@code 32MB}, {@code 512KB} o bytes. */
    static long memory(String value) {
        var text = value.strip().toUpperCase(java.util.Locale.ROOT);
        if (text.endsWith("MB")) {
            return Long.parseLong(text.substring(0, text.length() - 2).strip()) * 1024 * 1024;
        }
        if (text.endsWith("KB")) {
            return Long.parseLong(text.substring(0, text.length() - 2).strip()) * 1024;
        }
        return Long.parseLong(text);
    }

    /** Lo que un script puede pedirle al servidor real. */
    private final class Bridge implements ScriptHost.Bridge {

        @Override
        public List<ScriptHost.Player> players() {
            var current = server;
            return current == null ? List.of() : current.getPlayerList().getPlayers().stream().map(SamScripts::player).toList();
        }

        @Override
        public void tell(String player, String text) {
            var current = server;
            var target = current == null ? null : current.getPlayerList().getPlayerByName(player);
            if (target != null) {
                target.sendSystemMessage(Component.literal(text));
            }
        }

        @Override
        public void broadcast(String text) {
            var current = server;
            if (current != null) {
                current.getPlayerList().broadcastSystemMessage(Component.literal(text), false);
            }
        }

        @Override
        public void log(String script, String text) {
            log.info("[script {}] {}", script, text);
        }

        @Override
        public boolean has(String player, String node) {
            var current = server;
            var target = current == null ? null : current.getPlayerList().getPlayerByName(player);
            // Las variantes con Entity de fabric-permissions-api 0.3.x llaman a un método de 1.21.2+: se usa
            // siempre la del origen de comandos del jugador
            return target != null && me.lucko.fabric.api.permissions.v0.Permissions.check(target.createCommandSourceStack(), node, false);
        }

        @Override
        public Optional<String> meta(String player, String key) {
            var current = server;
            var target = current == null ? null : current.getPlayerList().getPlayerByName(player);
            return target == null ? Optional.empty() : me.lucko.fabric.api.permissions.v0.Options.get(target.createCommandSourceStack(), key);
        }

        @Override
        public Optional<ScriptHost.Position> position(String player) {
            var current = server;
            var target = current == null ? null : current.getPlayerList().getPlayerByName(player);
            if (target == null) {
                return Optional.empty();
            }
            return Optional.of(new ScriptHost.Position(target.getX(), target.getY(), target.getZ(), target.getYRot(), target.getXRot(),
                target.level().dimension().location().toString(), target.getHealth()));
        }

        @Override
        public boolean teleport(String player, ScriptHost.Position to) {
            var current = server;
            var target = current == null ? null : current.getPlayerList().getPlayerByName(player);
            var key = ResourceLocation.tryParse(to.dimension());
            var level = current == null || key == null ? null
                : current.getLevel(net.minecraft.resources.ResourceKey.create(net.minecraft.core.registries.Registries.DIMENSION, key));
            if (target == null || level == null) {
                return false;
            }
            target.teleportTo(level, to.x(), to.y(), to.z(), to.yaw(), to.pitch());
            return true;
        }

        @Override
        public boolean shareMedia(String id, String from, String to) {
            return media.share(id, from, to);
        }

        @Override
        public Optional<dev.sam.common.lua.ScriptStore> store(String script) {
            return SamScripts.this.store(script);
        }

        @Override
        public boolean send(String script, String player, String channel, byte[] data) {
            var current = server;
            var target = current == null ? null : current.getPlayerList().getPlayerByName(player);
            if (target == null || !delivery.accepted(target.getGameProfile().getName(), script)
                    || !net.fabricmc.fabric.api.networking.v1.ServerPlayNetworking.canSend(target, LUA_MSG)) {
                return false;
            }
            var buf = io.netty.buffer.Unpooled.buffer();
            new dev.sam.common.proto.scripts.LuaMessage(script, channel, data).write(new dev.sam.common.proto.SamWriter(buf));
            net.fabricmc.fabric.api.networking.v1.ServerPlayNetworking.send(target,
                new dev.sam.server.auth.SamPayload(LUA_MSG, io.netty.buffer.ByteBufUtil.getBytes(buf)));
            return true;
        }
    }
}
