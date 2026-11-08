package dev.sam.common.lua;

import static org.squiddev.cobalt.ValueFactory.valueOf;

import java.util.ArrayList;
import java.util.Collection;
import java.util.EnumMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.TreeMap;
import java.util.function.Supplier;

import org.squiddev.cobalt.Constants;
import org.squiddev.cobalt.LuaError;
import org.squiddev.cobalt.LuaState;
import org.squiddev.cobalt.LuaTable;
import org.squiddev.cobalt.LuaValue;
import org.squiddev.cobalt.function.LuaFunction;
import org.squiddev.cobalt.function.RegisteredFunction;

import dev.sam.common.scripts.ScriptManifest;

/**
 * Los scripts del servidor (RF-LUA-02/03) con la API v0 (PROTOCOLO.md 8.3): todo bajo la tabla {@code sam};
 * una función de una capacidad no declarada no existe (RS-LUA-04). Los errores quedan aislados por script
 * y se registran; un script que se pasa del tiempo o de la memoria se suspende (RS-LUA-03). Nada de
 * Minecraft: el servidor real se conecta por {@link Bridge}. Corre en el hilo del servidor.
 */
public final class ScriptHost {

    static final int MAX_TASKS = 256;
    static final int MAX_HANDLERS = 16;
    static final int MAX_TICKS = 72_000;
    static final int MAX_TEXT = 256;
    static final int MAX_COMMANDS = 16;
    private static final java.util.regex.Pattern COMMAND = java.util.regex.Pattern.compile("[a-z][a-z0-9_]{0,31}");
    private static final int MAX_LOG = 512;
    static final int MAX_HUD = 64;
    static final int MAX_SENT = 32;
    private static final int MAX_NODE = 128;
    /** Un nodo de permiso sin comodín (docs/PERMISOS.md, sección 1). */
    private static final java.util.regex.Pattern NODE = java.util.regex.Pattern.compile("[a-z0-9_-]+(\\.[a-z0-9_-]+)*");
    private static final int MAX_IMAGE = 512;
    private static final int MAX_TAB = 200;
    private static final int MAX_KEYS = 8;
    private static final int MAX_MENU = 4;
    private static final int MAX_URL = 512;
    private static final int MAX_MENU_LABEL = 32;
    private static final int MAX_TITLE = 64;
    private static final int MAX_SHORT = 64;
    private static final int MAX_WIDGETS = 64;
    private static final int MIN_WIDTH = 64;
    private static final int MAX_WIDTH = 400;
    private static final int MIN_HEIGHT = 32;
    private static final int MAX_HEIGHT = 300;
    private static final java.util.regex.Pattern KEY = java.util.regex.Pattern.compile("[a-z0-9]|f[1-9]|f1[0-2]");
    /** Los títulos de las pantallas de SAM (RS-LUA-07): un script no puede imitarlos. */
    private static final java.util.Set<String> PROTECTED_TITLES = java.util.Set.of("crear cuenta", "iniciar sesión",
        "scripts del servidor", "opciones de cuenta", "activar 2fa");
    private static final int MAX_OFFSET = 4096;
    private static final java.util.regex.Pattern HUD_ID = java.util.regex.Pattern.compile("[a-z0-9_]{1,32}");
    private static final int MAX_ERRORS = 20;

    /** Dónde se ancla un texto del HUD (API de cliente v0). */
    public enum Anchor {
        TOP_LEFT, TOP, TOP_RIGHT, LEFT, CENTER, RIGHT, BOTTOM_LEFT, BOTTOM, BOTTOM_RIGHT;

        String luaName() {
            return name().toLowerCase(Locale.ROOT);
        }
    }

    /** Un texto del HUD de un script: datos que el render dibuja sin ejecutar Lua. */
    public record HudText(String script, String id, String text, Anchor anchor, int x, int y, int color) {
    }

    /** Los textos del HUD de los scripts que están corriendo, en orden de carga y de creación. */
    public synchronized List<HudText> hud() {
        return scripts.values().stream().filter(l -> l.state == State.RUNNING).flatMap(l -> l.hud.values().stream())
            .filter(HudText.class::isInstance).map(HudText.class::cast).toList();
    }

    /** Un jugador como lo ve Lua: solo copias de valores, nunca objetos de Minecraft (RS-LUA-02c). */
    public record Player(String name, String uuid) {
    }

    /** Lo que los scripts pueden pedirle al servidor. */
    public interface Bridge {
        List<Player> players();

        void tell(String player, String text);

        void broadcast(String text);

        void log(String script, String text);

        /**
         * Envía un mensaje a la parte de cliente del script en el juego de un jugador ({@code sam:lua_msg}).
         *
         * @return si el jugador está en línea y aceptó el script
         */
        default boolean send(String script, String player, String channel, byte[] data) {
            return false;
        }

        /** Si un jugador en línea tiene un permiso (RF-PERM-07); lo indefinido es {@code false}. */
        default boolean has(String player, String node) {
            return false;
        }

        /** Una meta de un jugador en línea (RF-PERM-07). */
        default Optional<String> meta(String player, String key) {
            return Optional.empty();
        }

        /** Los datos guardados de ese script ({@code storage}); vacío si no hay dónde guardarlos. */
        default Optional<ScriptStore> store(String script) {
            return Optional.empty();
        }
    }

    /**
     * Entrega un mensaje que llegó por {@code sam:lua_msg} al {@code sam.receive} de ese canal.
     *
     * @param from quien lo envió (en el servidor), vacío en el cliente
     * @return si había un script corriendo que lo esperaba
     * @throws dev.sam.common.proto.ProtocolException si los datos no son un {@code LuaData} válido
     */
    public synchronized boolean deliver(String script, Optional<Player> from, String channel, byte[] data) {
        var loaded = scripts.get(script);
        if (loaded == null || loaded.state != State.RUNNING) {
            return false;
        }
        var receiver = loaded.receivers.get(channel);
        if (receiver == null) {
            return false;
        }
        var value = LuaData.decode(data);
        run(loaded, () -> from.isPresent() ? loaded.script.invoke(receiver, playerTable(from.get()), value)
            : loaded.script.invoke(receiver, value));
        return true;
    }

    /** Un script ya verificado (firma o modo desarrollo): su manifest y sus fuentes. */
    public record Package(ScriptManifest manifest, Map<String, String> sources, Map<String, byte[]> assets) {

        public Package(ScriptManifest manifest, Map<String, String> sources) {
            this(manifest, sources, Map.of());
        }
    }

    /** Lo que los scripts del cliente le piden al juego. */
    public interface ClientBridge {
        void log(String script, String text);

        /** {@code sam:lua_msg} hacia la parte de servidor del script. */
        default void send(String script, String channel, byte[] data) {
        }

        /** @return si se abrió (nunca sobre una pantalla de SAM ni de vanilla) */
        default boolean openScreen(String script, ScreenSpec spec) {
            return false;
        }

        /** Cierra la pantalla de ese script, si es la que está abierta. @return si lo era */
        default boolean closeScreen(String script) {
            return false;
        }

        /** @return si la tecla quedó asignada (el jugador la puede cambiar; no se pisa una acción del juego) */
        default boolean bindKey(String script, String id, String key) {
            return false;
        }

        /** Pide confirmar y abrir un link (capacidad {@code links}); nunca lo abre sin confirmación. @return si se pidió */
        default boolean openUrl(String script, String url) {
            return false;
        }

        /** Los datos de la partida de la lista cerrada (RS-LUA-10); vacío fuera del mundo. */
        default Optional<GameState> game() {
            return Optional.empty();
        }
    }

    /** Un espacio de la barra rápida. */
    public record Item(String id, int count) {
    }

    /**
     * Lo único que un script del cliente puede leer de la partida (RS-LUA-10, RN-28, PROTOCOLO.md 8.3). Agregar
     * un campo es un cambio de la especificación con revisión de seguridad (RN-24).
     */
    public record GameState(String name, double health, double maxHealth, int food, double x, double y, double z, String dimension,
            List<Item> hotbar, int selected, List<String> players, int guiScale, int width, int height) {
    }

    /** Una imagen del HUD de un script: los bytes ya pasaron {@link PngInfo#check}. */
    public record HudImage(String script, String id, String path, byte[] png, Anchor anchor, int x, int y, int w, int h) {

        public HudImage {
            png = png.clone();
        }

        @Override
        public byte[] png() {
            return png.clone();
        }
    }

    /** El host del cliente: solo las capacidades del cliente (API de cliente v0, PROTOCOLO.md 8.3). */
    public static ScriptHost client(ClientBridge bridge, ScriptLimits limits) {
        return new ScriptHost(new Bridge() {
            @Override
            public List<Player> players() {
                return List.of();
            }

            @Override
            public void tell(String player, String text) {
                throw new UnsupportedOperationException("chat no existe en el cliente");
            }

            @Override
            public void broadcast(String text) {
                throw new UnsupportedOperationException("chat no existe en el cliente");
            }

            @Override
            public void log(String script, String text) {
                bridge.log(script, text);
            }
        }, limits, bridge);
    }

    /** Un evento de la pantalla de un script para su {@code sam.screen.on}. @return si lo esperaba */
    public synchronized boolean screenEvent(String script, ScreenSpec.Event event) {
        var loaded = scripts.get(script);
        if (loaded == null || loaded.state != State.RUNNING || loaded.screenHandler == null) {
            return false;
        }
        var table = new LuaTable();
        table.rawset("type", LuaSandbox.lua(event.type()));
        if (event.id() != null) {
            table.rawset("id", LuaSandbox.lua(event.id()));
        }
        if (event.value() instanceof Boolean flag) {
            table.rawset("value", valueOf(flag));
        } else if (event.value() instanceof String text) {
            table.rawset("value", LuaSandbox.lua(text));
        }
        var handler = loaded.screenHandler;
        run(loaded, () -> loaded.script.invoke(handler, table));
        return true;
    }

    /** El jugador apretó la tecla de {@code sam.key(id, ...)} (la que tenga asignada). @return si el script la registró */
    public synchronized boolean keyPressed(String script, String id) {
        var loaded = scripts.get(script);
        var handler = loaded == null || loaded.state != State.RUNNING ? null : loaded.keys.get(id);
        if (handler == null) {
            return false;
        }
        run(loaded, () -> loaded.script.invoke(handler));
        return true;
    }

    /** Una entrada de un plugin en el botón de Opciones de cuenta (capacidad {@code menu}). */
    public record MenuEntry(String script, String id, String label, int order, Optional<byte[]> icon) {
    }

    private record MenuItem(String label, int order, Optional<byte[]> icon, LuaFunction function) {
    }

    /** Las entradas de los scripts que están corriendo, por {@code order} y texto. */
    public synchronized List<MenuEntry> menuEntries() {
        return scripts.values().stream().filter(l -> l.state == State.RUNNING)
            .flatMap(l -> l.menu.entrySet().stream().map(e -> new MenuEntry(l.id(), e.getKey(), e.getValue().label(),
                e.getValue().order(), e.getValue().icon())))
            .sorted(java.util.Comparator.comparingInt(MenuEntry::order).thenComparing(MenuEntry::label)).toList();
    }

    /** El jugador eligió una entrada del menú. @return si el script la tenía */
    public synchronized boolean menuClicked(String script, String id) {
        var loaded = scripts.get(script);
        var item = loaded == null || loaded.state != State.RUNNING ? null : loaded.menu.get(id);
        if (item == null) {
            return false;
        }
        run(loaded, () -> loaded.script.invoke(item.function()));
        return true;
    }

    /** Las imágenes del HUD de los scripts que están corriendo. */
    public synchronized List<HudImage> hudImages() {
        return scripts.values().stream().filter(l -> l.state == State.RUNNING).flatMap(l -> l.hud.values().stream())
            .filter(HudImage.class::isInstance).map(HudImage.class::cast).toList();
    }

    public enum Event {
        JOIN, QUIT, CHAT;

        String luaName() {
            return name().toLowerCase(Locale.ROOT);
        }
    }

    public enum State {
        RUNNING, SUSPENDED, FAILED
    }

    public record Status(String id, State state, List<String> errors) {
    }

    /** Un comando registrado por un script ({@code sam.command}): su nombre, nivel de permiso y dueño. */
    public record Command(String name, int permission, String script, Optional<String> node) {

        /** Un comando sin nodo: manda el nivel de OP. */
        public Command(String name, int permission, String script) {
            this(name, permission, script, Optional.empty());
        }
    }

    private record CommandEntry(Command spec, Loaded owner, LuaFunction function) {
    }

    private record Task(int id, long due, int every, LuaFunction function) {
    }

    private final class Loaded {
        final ScriptManifest manifest;
        final LuaSandbox.Script script;
        State state = State.RUNNING;
        final List<String> errors = new ArrayList<>();
        final Map<Event, List<LuaFunction>> handlers = new EnumMap<>(Event.class);
        final Map<Integer, Task> tasks = new TreeMap<>();
        /** {@link HudText} o {@link HudImage}, por id. */
        final Map<String, Record> hud = new LinkedHashMap<>();
        final Map<String, byte[]> assets;
        LuaFunction screenHandler;
        final java.util.Set<String> keyIds = new java.util.HashSet<>();
        final Map<String, LuaFunction> keys = new java.util.HashMap<>();
        final Map<String, MenuItem> menu = new LinkedHashMap<>();
        final Map<String, LuaFunction> receivers = new java.util.HashMap<>();
        int sent;
        int nextTask = 1;

        Loaded(Package pack) {
            this.manifest = pack.manifest();
            this.assets = pack.assets();
            this.script = LuaSandbox.load(manifest.id(), pack.sources(), limits);
        }

        String id() {
            return manifest.id();
        }
    }

    private final Bridge bridge;
    private final ScriptLimits limits;
    /** En el cliente solo existen las capacidades del cliente, y en el servidor las del servidor. */
    private final boolean client;
    /** Solo en el cliente: el juego (mensajes al servidor, pantallas, teclas). */
    private final ClientBridge ui;
    private final Map<String, Loaded> scripts = new LinkedHashMap<>();
    private final Map<String, CommandEntry> commands = new LinkedHashMap<>();
    private java.util.Set<String> reserved = java.util.Set.of();
    private long tick;

    static {
        // Inicializa el codec (y los buffers de Netty) fuera de la ventana de tiempo de un script: la
        // primera vez tarda más que una llamada entera y suspendería al script que envía primero
        try {
            LuaData.decode(LuaData.encode(Constants.TRUE));
        } catch (LuaError e) {
            throw new ExceptionInInitializerError(e);
        }
    }

    /** El host del servidor. */
    public ScriptHost(Bridge bridge, ScriptLimits limits) {
        this(bridge, limits, null);
    }

    private ScriptHost(Bridge bridge, ScriptLimits limits, ClientBridge ui) {
        this.bridge = bridge;
        this.limits = limits;
        this.client = ui != null;
        this.ui = ui;
    }

    /** Descarta todo lo cargado y carga estos scripts (RF-LUA-02: errores aislados por script). */
    public synchronized void load(List<Package> packages) {
        scripts.clear();
        commands.clear();
        for (var pack : packages) {
            var loaded = new Loaded(pack);
            scripts.put(loaded.id(), loaded);
            var outcome = loaded.script.start(state -> installApi(loaded, state));
            if (outcome.error().isPresent()) {
                loaded.state = State.FAILED;
                closeScreen(loaded);
                record(loaded, outcome.error().get());
                commands.values().removeIf(entry -> entry.owner() == loaded);
            }
        }
    }

    public synchronized void fire(Event event, Player player, Optional<String> text) {
        for (var loaded : List.copyOf(scripts.values())) {
            for (var handler : List.copyOf(loaded.handlers.getOrDefault(event, List.of()))) {
                if (loaded.state != State.RUNNING) {
                    break;
                }
                var playerTable = playerTable(player);
                run(loaded, () -> text.isPresent() ? loaded.script.invoke(handler, playerTable, LuaSandbox.lua(text.get()))
                    : loaded.script.invoke(handler, playerTable));
            }
        }
    }

    /** Un tick del servidor: corre las tareas que vencen ({@code sam.after}, {@code sam.every}). */
    public synchronized void tick() {
        tick++;
        scripts.values().forEach(loaded -> loaded.sent = 0);
        for (var loaded : List.copyOf(scripts.values())) {
            var due = loaded.tasks.values().stream().filter(task -> task.due() <= tick).toList();
            for (var task : due) {
                if (loaded.state != State.RUNNING || !loaded.tasks.containsKey(task.id())) {
                    continue;
                }
                if (task.every() > 0) {
                    loaded.tasks.put(task.id(), new Task(task.id(), tick + task.every(), task.every(), task.function()));
                } else {
                    loaded.tasks.remove(task.id());
                }
                run(loaded, () -> loaded.script.invoke(task.function()));
            }
        }
    }

    /** Llama a una función global de un script (para {@code /sam scripts} y las pruebas). */
    public synchronized LuaSandbox.Outcome call(String id, String function) {
        var loaded = scripts.get(id);
        if (loaded == null) {
            return LuaSandbox.Outcome.failed("no hay un script " + id);
        }
        if (loaded.state == State.SUSPENDED) {
            return LuaSandbox.Outcome.failed("el script está suspendido");
        }
        if (loaded.state == State.FAILED) {
            return LuaSandbox.Outcome.failed("el script no cargó");
        }
        return run(loaded, () -> loaded.script.call(function));
    }

    /** Los nombres de comando que ya tiene el servidor (vanilla, otros mods, sam): ningún script puede usarlos. */
    public synchronized void reserveCommands(Collection<String> names) {
        reserved = java.util.Set.copyOf(names);
    }

    /** Los comandos de los scripts que están corriendo, en orden de registro. */
    public synchronized List<Command> commands() {
        return commands.values().stream().filter(e -> e.owner().state == State.RUNNING).map(CommandEntry::spec).toList();
    }

    /**
     * Ejecuta un comando de un script.
     *
     * @param player quien lo ejecutó, o vacío si fue la consola
     * @param args el texto después del nombre
     * @return el valor que devolvió el script (la respuesta) o el error
     */
    public synchronized LuaSandbox.Outcome runCommand(String name, Optional<Player> player, String args) {
        var entry = commands.get(name);
        if (entry == null || entry.owner().state != State.RUNNING) {
            return LuaSandbox.Outcome.failed("el comando /" + name + " no está disponible");
        }
        var argv = new LuaTable();
        var words = args.strip().isEmpty() ? new String[0] : args.strip().split("\\s+");
        for (var i = 0; i < words.length; i++) {
            argv.rawset(i + 1, LuaSandbox.lua(words[i]));
        }
        LuaValue who = player.isPresent() ? playerTable(player.get()) : Constants.NIL;
        return run(entry.owner(), () -> entry.owner().script.invoke(entry.function(), who, LuaSandbox.lua(args), argv));
    }

    public synchronized List<Status> status() {
        return scripts.values().stream().map(l -> new Status(l.id(), l.state, List.copyOf(l.errors))).toList();
    }

    private LuaSandbox.Outcome run(Loaded loaded, Supplier<LuaSandbox.Outcome> call) {
        var outcome = call.get();
        outcome.error().ifPresent(error -> record(loaded, error));
        if (outcome.exceeded()) {
            loaded.state = State.SUSPENDED;
            closeScreen(loaded);
        }
        return outcome;
    }

    private static void record(Loaded loaded, String error) {
        loaded.errors.add(error);
        if (loaded.errors.size() > MAX_ERRORS) {
            loaded.errors.removeFirst();
        }
    }

    // ===== La API v0 (PROTOCOLO.md 8.3): cada función revisada contra RS-LUA-00 =====

    private void installApi(Loaded loaded, LuaState state) {
        var sam = new LuaTable();
        var functions = new ArrayList<RegisteredFunction>();
        functions.add(RegisteredFunction.of("log", (s, text) -> {
            bridge.log(loaded.id(), truncate(string(text), MAX_LOG));
            return Constants.NIL;
        }));
        if (!client && loaded.manifest.has("events")) {
            functions.add(RegisteredFunction.of("on", (s, name, fn) -> on(loaded, string(name), fn.checkFunction())));
        }
        if (loaded.manifest.has("scheduler")) {
            functions.add(RegisteredFunction.of("after", (s, ticks, fn) -> schedule(loaded, ticks.checkInteger(), fn.checkFunction(), false)));
            functions.add(RegisteredFunction.of("every", (s, ticks, fn) -> schedule(loaded, ticks.checkInteger(), fn.checkFunction(), true)));
            functions.add(RegisteredFunction.of("cancel", (s, id) -> {
                loaded.tasks.remove(id.checkInteger());
                return Constants.NIL;
            }));
        }
        if (!client && loaded.manifest.has("players")) {
            functions.add(RegisteredFunction.of("players", s -> {
                var list = new LuaTable();
                var players = bridge.players();
                for (var i = 0; i < players.size(); i++) {
                    list.rawset(i + 1, playerTable(players.get(i)));
                }
                return list;
            }));
        }
        if (!client && loaded.manifest.has("chat")) {
            functions.add(RegisteredFunction.of("tell", (s, player, text) -> {
                bridge.tell(string(player), plain(string(text)));
                return Constants.NIL;
            }));
            functions.add(RegisteredFunction.of("broadcast", (s, text) -> {
                bridge.broadcast(plain(string(text)));
                return Constants.NIL;
            }));
        }
        if (!client && loaded.manifest.has("permissions")) {
            functions.add(RegisteredFunction.of("has", (s, player, node) -> valueOf(bridge.has(string(player), string(node)))));
            functions.add(RegisteredFunction.of("meta", (s, player, key) ->
                bridge.meta(string(player), string(key)).<LuaValue>map(LuaSandbox::lua).orElse(Constants.NIL)));
        }
        if (!client && loaded.manifest.has("commands")) {
            functions.add(RegisteredFunction.ofV("command", (s, args) -> command(loaded, args)));
        }
        if (loaded.manifest.has("messages")) {
            functions.add(RegisteredFunction.ofV("send", (s, args) -> send(loaded, args)));
            functions.add(RegisteredFunction.of("receive", (s, channel, fn) ->
                valueOf(loaded.receivers.put(channel(channel), fn.checkFunction()) != null)));
        }
        RegisteredFunction.bind(sam, functions.toArray(RegisteredFunction[]::new));
        sam.rawset("side", LuaSandbox.lua(client ? "client" : "server"));
        if (loaded.manifest.has("storage")) {
            // En el cliente no hay dónde guardar: su puente nunca da un almacén
            var store = bridge.store(loaded.id());
            if (store.isPresent()) {
                sam.rawset("store", storeTable(store.get()));
            }
        }
        if (client && loaded.manifest.has("game")) {
            var game = new LuaTable();
            RegisteredFunction.bind(game, new RegisteredFunction[] {
                RegisteredFunction.of("state", s -> ui.game().<LuaValue>map(ScriptHost::gameTable).orElse(Constants.NIL))});
            sam.rawset("game", game);
        }
        if (client && loaded.manifest.has("screens")) {
            var screen = new LuaTable();
            RegisteredFunction.bind(screen, new RegisteredFunction[] {
                RegisteredFunction.of("open", (s, def) -> valueOf(ui.openScreen(loaded.id(), screenSpec(loaded, def.checkTable())))),
                RegisteredFunction.of("close", s -> valueOf(ui.closeScreen(loaded.id()))),
                RegisteredFunction.of("on", (s, fn) -> {
                    var replaced = loaded.screenHandler != null;
                    loaded.screenHandler = fn.checkFunction();
                    return valueOf(replaced);
                })});
            sam.rawset("screen", screen);
        }
        if (client && loaded.manifest.has("menu")) {
            var menu = new LuaTable();
            RegisteredFunction.bind(menu, new RegisteredFunction[] {
                RegisteredFunction.ofV("add", (s, args) -> menuAdd(loaded, args)),
                RegisteredFunction.of("remove", (s, id) -> valueOf(loaded.menu.remove(string(id)) != null))});
            sam.rawset("menu", menu);
        }
        if (client && loaded.manifest.has("links")) {
            RegisteredFunction.bind(sam, new RegisteredFunction[] {
                RegisteredFunction.of("open_url", (s, url) -> valueOf(ui.openUrl(loaded.id(), link(string(url)))))});
        }
        if (client && loaded.manifest.has("keybinds")) {
            RegisteredFunction.bind(sam, new RegisteredFunction[] {RegisteredFunction.ofV("key", (s, args) -> key(loaded, args))});
        }
        if (client && loaded.manifest.has("hud")) {
            var hud = new LuaTable();
            RegisteredFunction.bind(hud, new RegisteredFunction[] {
                RegisteredFunction.ofV("text", (s, args) -> hudText(loaded, args)),
                RegisteredFunction.ofV("image", (s, args) -> hudImage(loaded, args)),
                RegisteredFunction.of("remove", (s, id) -> valueOf(loaded.hud.remove(string(id)) != null)),
                RegisteredFunction.of("clear", s -> {
                    var removed = loaded.hud.size();
                    loaded.hud.clear();
                    return valueOf(removed);
                })});
            sam.rawset("hud", hud);
        }
        state.globals().rawset("sam", sam);
    }

    private LuaValue on(Loaded loaded, String name, LuaFunction fn) throws LuaError {
        var event = java.util.Arrays.stream(Event.values()).filter(e -> e.luaName().equals(name)).findFirst()
            .orElseThrow(() -> new LuaError("evento desconocido \"" + name + "\" (join, quit o chat)"));
        var list = loaded.handlers.computeIfAbsent(event, e -> new ArrayList<>());
        if (list.size() >= MAX_HANDLERS) {
            throw new LuaError("como mucho " + MAX_HANDLERS + " manejadores por evento");
        }
        list.add(fn);
        return Constants.NIL;
    }

    private org.squiddev.cobalt.Varargs command(Loaded loaded, org.squiddev.cobalt.Varargs args) throws LuaError {
        var name = string(args.arg(1));
        var fn = args.arg(2).checkFunction();
        var options = args.arg(3);
        var permission = 0;
        Optional<String> node = Optional.empty();
        if (!options.isNil()) {
            var level = options.checkTable().rawget("permission");
            var required = options.checkTable().rawget("node");
            // Con node, lo indefinido cae en este nivel: por defecto 2 (operadores), nunca "todos" sin pedirlo
            permission = level.isNil() ? (required.isNil() ? 0 : 2) : level.checkInteger();
            if (!required.isNil()) {
                if (!loaded.manifest.has("permissions")) {
                    throw new LuaError("node requiere la capacidad permissions");
                }
                var text = string(required);
                if (text.length() > MAX_NODE || !NODE.matcher(text).matches()) {
                    throw new LuaError("nodo inválido \"" + text + "\"");
                }
                node = Optional.of(text);
            }
        }
        if (!COMMAND.matcher(name).matches()) {
            throw new LuaError("nombre de comando inválido \"" + name + "\": [a-z][a-z0-9_], hasta 32");
        }
        if (permission < 0 || permission > 4) {
            throw new LuaError("el permiso debe estar entre 0 y 4");
        }
        if (reserved.contains(name)) {
            throw new LuaError("/" + name + " ya existe en el servidor");
        }
        var taken = commands.get(name);
        if (taken != null) {
            throw new LuaError("/" + name + " ya lo registró el script " + taken.owner().id());
        }
        if (commands.values().stream().filter(e -> e.owner() == loaded).count() >= MAX_COMMANDS) {
            throw new LuaError("como mucho " + MAX_COMMANDS + " comandos por script");
        }
        commands.put(name, new CommandEntry(new Command(name, permission, loaded.id(), node), loaded, fn));
        return Constants.NONE;
    }

    /** {@code sam.send(canal, datos)} en el cliente; {@code sam.send(jugador, canal, datos)} en el servidor. */
    private org.squiddev.cobalt.Varargs send(Loaded loaded, org.squiddev.cobalt.Varargs args) throws LuaError {
        var first = client ? 1 : 2;
        var channel = channel(args.arg(first));
        var data = LuaData.encode(args.arg(first + 1));
        if (++loaded.sent > MAX_SENT) {
            throw new LuaError("como mucho " + MAX_SENT + " mensajes por tick");
        }
        if (client) {
            ui.send(loaded.id(), channel, data);
            return Constants.NIL;
        }
        return valueOf(bridge.send(loaded.id(), string(args.arg(1)), channel, data));
    }

    private static String channel(LuaValue value) throws LuaError {
        var channel = string(value);
        if (!HUD_ID.matcher(channel).matches()) {
            throw new LuaError("canal inválido \"" + channel + "\": [a-z0-9_], hasta 32");
        }
        return channel;
    }

    /** {@code sam.hud.text(id, texto[, {anchor, x, y, color}])} (API de cliente v0). */
    private org.squiddev.cobalt.Varargs hudText(Loaded loaded, org.squiddev.cobalt.Varargs args) throws LuaError {
        var id = string(args.arg(1));
        var text = plain(string(args.arg(2)));
        var options = args.arg(3).isNil() ? new LuaTable() : args.arg(3).checkTable();
        if (!HUD_ID.matcher(id).matches()) {
            throw new LuaError("id de HUD inválido \"" + id + "\": [a-z0-9_], hasta 32");
        }
        var anchor = anchor(options.rawget("anchor"));
        var x = offset(options.rawget("x"));
        var y = offset(options.rawget("y"));
        var color = color(options.rawget("color"));
        checkRoom(loaded, id);
        loaded.hud.put(id, new HudText(loaded.id(), id, text, anchor, x, y, color));
        return Constants.NONE;
    }

    /** {@code sam.hud.image(id, ruta[, {anchor, x, y, w, h}])}. */
    private org.squiddev.cobalt.Varargs hudImage(Loaded loaded, org.squiddev.cobalt.Varargs args) throws LuaError {
        var id = string(args.arg(1));
        if (!HUD_ID.matcher(id).matches()) {
            throw new LuaError("id de HUD inválido \"" + id + "\": [a-z0-9_], hasta 32");
        }
        var path = string(args.arg(2));
        var png = image(loaded, path);
        var info = PngInfo.check(png);
        var options = args.arg(3).isNil() ? new LuaTable() : args.arg(3).checkTable();
        var anchor = anchor(options.rawget("anchor"));
        var x = offset(options.rawget("x"));
        var y = offset(options.rawget("y"));
        var w = imageSide(options.rawget("w"), info.width());
        var h = imageSide(options.rawget("h"), info.height());
        checkRoom(loaded, id);
        loaded.hud.put(id, new HudImage(loaded.id(), id, path, png, anchor, x, y, w, h));
        return Constants.NONE;
    }

    private static void checkRoom(Loaded loaded, String id) throws LuaError {
        if (!loaded.hud.containsKey(id) && loaded.hud.size() >= MAX_HUD) {
            throw new LuaError("como mucho " + MAX_HUD + " textos por script");
        }
    }

    private static Anchor anchor(LuaValue value) throws LuaError {
        if (value.isNil()) {
            return Anchor.TOP_LEFT;
        }
        var name = string(value);
        return java.util.Arrays.stream(Anchor.values()).filter(a -> a.luaName().equals(name)).findFirst()
            .orElseThrow(() -> new LuaError("ancla desconocida \"" + name + "\""));
    }

    private static int color(LuaValue value) throws LuaError {
        var color = value.isNil() ? 0xFFFFFF : value.checkInteger();
        if (color < 0 || color > 0xFFFFFF) {
            throw new LuaError("color debe ser 0xRRGGBB");
        }
        return color;
    }

    /** Los bytes de un PNG del propio script, ya revisados (RN-29). */
    private static byte[] image(Loaded loaded, String path) throws LuaError {
        var png = loaded.assets.get(path);
        if (png == null) {
            throw new LuaError("no hay una imagen \"" + path + "\" en el script");
        }
        try {
            PngInfo.check(png);
        } catch (IllegalArgumentException e) {
            throw new LuaError(path + ": " + e.getMessage());
        }
        return png;
    }

    private static int imageSide(LuaValue value, int natural) throws LuaError {
        var side = value.isNil() ? natural : value.checkInteger();
        if (side < 1 || side > MAX_IMAGE) {
            throw new LuaError("w y h de una imagen deben estar entre 1 y " + MAX_IMAGE);
        }
        return side;
    }

    // ===== storage (servidor) y game (cliente) =====

    private static LuaTable storeTable(ScriptStore store) {
        var table = new LuaTable();
        RegisteredFunction.bind(table, new RegisteredFunction[] {
            RegisteredFunction.of("get", (s, key) -> {
                var value = store.get(string(key));
                return value.isPresent() ? LuaData.decode(value.get()) : Constants.NIL;
            }),
            RegisteredFunction.of("set", (s, key, value) -> {
                var name = string(key);
                var data = value.isNil() ? Optional.<byte[]>empty() : Optional.of(LuaData.encode(value));
                var existed = store.get(name).isPresent();
                try {
                    store.set(name, data);
                } catch (IllegalArgumentException e) {
                    throw new LuaError(e.getMessage());
                }
                return valueOf(existed);
            }),
            RegisteredFunction.of("keys", s -> {
                var list = new LuaTable();
                var keys = store.keys();
                for (var i = 0; i < keys.size(); i++) {
                    list.rawset(i + 1, LuaSandbox.lua(keys.get(i)));
                }
                return list;
            })});
        return table;
    }

    /** Una copia nueva de los datos de la partida para Lua (RS-LUA-02c). */
    private static LuaTable gameTable(GameState state) {
        var table = new LuaTable();
        table.rawset("name", LuaSandbox.lua(state.name()));
        table.rawset("health", valueOf(state.health()));
        table.rawset("max_health", valueOf(state.maxHealth()));
        table.rawset("food", valueOf(state.food()));
        table.rawset("x", valueOf(state.x()));
        table.rawset("y", valueOf(state.y()));
        table.rawset("z", valueOf(state.z()));
        table.rawset("dimension", LuaSandbox.lua(state.dimension()));
        var hotbar = new LuaTable();
        for (var i = 0; i < state.hotbar().size(); i++) {
            var slot = new LuaTable();
            slot.rawset("id", LuaSandbox.lua(state.hotbar().get(i).id()));
            slot.rawset("count", valueOf(state.hotbar().get(i).count()));
            hotbar.rawset(i + 1, slot);
        }
        table.rawset("hotbar", hotbar);
        table.rawset("selected", valueOf(state.selected()));
        var players = new LuaTable();
        var names = state.players().stream().limit(MAX_TAB).toList();
        for (var i = 0; i < names.size(); i++) {
            players.rawset(i + 1, LuaSandbox.lua(names.get(i)));
        }
        table.rawset("players", players);
        var gui = new LuaTable();
        gui.rawset("scale", valueOf(state.guiScale()));
        gui.rawset("width", valueOf(state.width()));
        gui.rawset("height", valueOf(state.height()));
        table.rawset("gui", gui);
        return table;
    }

    // ===== Pantallas (screens) y teclas (keybinds) =====

    private void closeScreen(Loaded loaded) {
        if (client) {
            ui.closeScreen(loaded.id());
        }
    }

    /** Un link {@code http(s)} con host, de hasta 512 caracteres y sin espacios ni caracteres de control. */
    private static String link(String url) throws LuaError {
        try {
            var uri = new java.net.URI(url);
            var scheme = uri.getScheme() == null ? "" : uri.getScheme().toLowerCase(Locale.ROOT);
            if (url.length() <= MAX_URL && (scheme.equals("http") || scheme.equals("https")) && uri.getHost() != null) {
                return url;
            }
        } catch (java.net.URISyntaxException e) {
            // cae al error de abajo
        }
        throw new LuaError("link inválido: solo http(s)://, con host y hasta " + MAX_URL + " caracteres");
    }

    /** {@code sam.menu.add(id, texto, fn[, {icon, order}])}: devuelve si reemplazó una entrada. */
    private org.squiddev.cobalt.Varargs menuAdd(Loaded loaded, org.squiddev.cobalt.Varargs args) throws LuaError {
        var id = string(args.arg(1));
        if (!HUD_ID.matcher(id).matches()) {
            throw new LuaError("id de menú inválido \"" + id + "\": [a-z0-9_], hasta 32");
        }
        var label = text(args.arg(2), MAX_MENU_LABEL, "el texto");
        if (label.isBlank()) {
            throw new LuaError("el texto no puede estar vacío");
        }
        var fn = args.arg(3).checkFunction();
        var options = args.arg(4).isNil() ? new LuaTable() : args.arg(4).checkTable();
        var order = range(options.rawget("order"), 100, 0, 999, "order");
        Optional<byte[]> icon = options.rawget("icon").isNil() ? Optional.empty()
            : Optional.of(image(loaded, string(options.rawget("icon"))));
        if (!loaded.menu.containsKey(id) && loaded.menu.size() >= MAX_MENU) {
            throw new LuaError("como mucho " + MAX_MENU + " entradas de menú por script");
        }
        return valueOf(loaded.menu.put(id, new MenuItem(label, order, icon, fn)) != null);
    }

    /** {@code sam.key(id, tecla, fn)}: devuelve si el juego la asignó. */
    private org.squiddev.cobalt.Varargs key(Loaded loaded, org.squiddev.cobalt.Varargs args) throws LuaError {
        var id = string(args.arg(1));
        var key = string(args.arg(2));
        var fn = args.arg(3).checkFunction();
        if (!HUD_ID.matcher(id).matches()) {
            throw new LuaError("id de tecla inválido \"" + id + "\": [a-z0-9_], hasta 32");
        }
        if (!KEY.matcher(key).matches()) {
            throw new LuaError("tecla desconocida \"" + key + "\" (a-z, 0-9 o f1-f12)");
        }
        if (loaded.keyIds.contains(id)) {
            throw new LuaError("la tecla \"" + id + "\" ya está registrada");
        }
        if (loaded.keyIds.size() >= MAX_KEYS) {
            throw new LuaError("como mucho " + MAX_KEYS + " teclas por script");
        }
        loaded.keyIds.add(id);
        // La función queda aunque la tecla no se asigne: el jugador puede elegirle otra después
        loaded.keys.put(id, fn);
        return valueOf(ui.bindKey(loaded.id(), id, key));
    }

    /** La pantalla declarativa de {@code sam.screen.open(def)} (PROTOCOLO.md 8.3), validada entera. */
    private static ScreenSpec screenSpec(Loaded loaded, LuaTable def) throws LuaError {
        var title = text(def.rawget("title"), MAX_TITLE, "el título");
        if (PROTECTED_TITLES.contains(title.strip().toLowerCase(Locale.ROOT))) {
            throw new LuaError("título reservado para las pantallas de SAM");
        }
        var width = range(def.rawget("width"), 0, MIN_WIDTH, MAX_WIDTH, "width");
        var height = range(def.rawget("height"), 0, MIN_HEIGHT, MAX_HEIGHT, "height");
        var list = def.rawget("widgets").checkTable();
        if (list.length() > MAX_WIDGETS) {
            throw new LuaError("como mucho " + MAX_WIDGETS + " widgets");
        }
        var widgets = new ArrayList<ScreenSpec.Widget>();
        var ids = new java.util.HashSet<String>();
        for (var i = 1; i <= list.length(); i++) {
            var w = list.rawget(i).checkTable();
            var type = string(w.rawget("type"));
            var x = w.rawget("x").isNil() ? 0 : w.rawget("x").checkInteger();
            var y = w.rawget("y").isNil() ? 0 : w.rawget("y").checkInteger();
            if (x < 0 || x > width || y < 0 || y > height) {
                throw new LuaError("x e y deben estar dentro del panel");
            }
            widgets.add(switch (type) {
                case "label" -> new ScreenSpec.Label(x, y, text(w.rawget("text"), MAX_TEXT, "el texto"), color(w.rawget("color")));
                case "button" -> new ScreenSpec.Button(widgetId(w, ids), x, y, text(w.rawget("text"), MAX_SHORT, "el texto"),
                    range(w.rawget("w"), 80, 16, 400, "w"), range(w.rawget("h"), 20, 12, 40, "h"));
                case "text_field" -> {
                    var id = widgetId(w, ids);
                    var width2 = range(w.rawget("w"), 120, 16, 400, "w");
                    var max = range(w.rawget("max"), 64, 1, 256, "max");
                    var value = w.rawget("value").isNil() ? "" : plainText(w.rawget("value"));
                    if (value.length() > max) {
                        throw new LuaError("value supera max");
                    }
                    yield new ScreenSpec.TextField(id, x, y, width2, max, value);
                }
                case "checkbox" -> new ScreenSpec.Checkbox(widgetId(w, ids), x, y, text(w.rawget("text"), MAX_SHORT, "el texto"),
                    w.rawget("checked").toBoolean());
                case "image" -> {
                    var path = string(w.rawget("path"));
                    var png = image(loaded, path);
                    var info = PngInfo.check(png);
                    yield new ScreenSpec.Image(path, png, x, y, imageSide(w.rawget("w"), info.width()),
                        imageSide(w.rawget("h"), info.height()));
                }
                default -> throw new LuaError("widget de tipo desconocido \"" + type + "\"");
            });
        }
        return new ScreenSpec(title, width, height, widgets);
    }

    private static String widgetId(LuaTable widget, java.util.Set<String> ids) throws LuaError {
        var id = string(widget.rawget("id"));
        if (!HUD_ID.matcher(id).matches()) {
            throw new LuaError("id de widget inválido \"" + id + "\": [a-z0-9_], hasta 32");
        }
        if (!ids.add(id)) {
            throw new LuaError("id de widget repetido \"" + id + "\"");
        }
        return id;
    }

    /** Texto plano (sin §) de hasta {@code max} caracteres. */
    private static String text(LuaValue value, int max, String what) throws LuaError {
        var text = plainText(value);
        if (text.length() > max) {
            throw new LuaError(what + " supera los " + max + " caracteres");
        }
        return text;
    }

    private static String plainText(LuaValue value) throws LuaError {
        return string(value).replaceAll("§.?", "");
    }

    private static int range(LuaValue value, int fallback, int min, int max, String name) throws LuaError {
        var number = value.isNil() ? fallback : value.checkInteger();
        if (number < min || number > max) {
            throw new LuaError(name + " debe estar entre " + min + " y " + max);
        }
        return number;
    }

    private static int offset(LuaValue value) throws LuaError {
        var offset = value.isNil() ? 0 : value.checkInteger();
        if (offset < -MAX_OFFSET || offset > MAX_OFFSET) {
            throw new LuaError("x e y deben estar entre -" + MAX_OFFSET + " y " + MAX_OFFSET);
        }
        return offset;
    }

    private LuaValue schedule(Loaded loaded, int ticks, LuaFunction fn, boolean repeat) throws LuaError {
        if (ticks < 1 || ticks > MAX_TICKS) {
            throw new LuaError("los ticks deben estar entre 1 y " + MAX_TICKS);
        }
        if (loaded.tasks.size() >= MAX_TASKS) {
            throw new LuaError("como mucho " + MAX_TASKS + " tareas pendientes");
        }
        var id = loaded.nextTask++;
        loaded.tasks.put(id, new Task(id, tick + ticks, repeat ? ticks : 0, fn));
        return valueOf(id);
    }

    /** Texto plano: sin códigos de formato (§x) y como mucho {@value #MAX_TEXT} caracteres. */
    private static String plain(String text) throws LuaError {
        if (text.length() > MAX_TEXT) {
            throw new LuaError("el texto supera los " + MAX_TEXT + " caracteres");
        }
        return text.replaceAll("§.?", "");
    }

    /** Un argumento de texto, leído como UTF-8. */
    private static String string(LuaValue value) throws LuaError {
        return LuaSandbox.text(value.checkLuaString());
    }

    private static String truncate(String text, int max) {
        return text.length() > max ? text.substring(0, max) + "…" : text;
    }

    private static LuaTable playerTable(Player player) {
        var table = new LuaTable();
        table.rawset("name", LuaSandbox.lua(player.name()));
        table.rawset("uuid", LuaSandbox.lua(player.uuid()));
        return table;
    }
}
