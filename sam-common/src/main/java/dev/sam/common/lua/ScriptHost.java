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

    /** El host del cliente: solo las capacidades del cliente (API de cliente v0, PROTOCOLO.md 8.3). */
    public static ScriptHost client(java.util.function.BiConsumer<String, String> log, ScriptLimits limits) {
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
                log.accept(script, text);
            }
        }, limits, true);
    }

    /** Los textos del HUD de los scripts que están corriendo, en orden de carga y de creación. */
    public synchronized List<HudText> hud() {
        return scripts.values().stream().filter(l -> l.state == State.RUNNING).flatMap(l -> l.hud.values().stream()).toList();
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
    }

    /** Un script ya verificado (firma o modo desarrollo): su manifest y sus fuentes. */
    public record Package(ScriptManifest manifest, Map<String, String> sources) {
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
    public record Command(String name, int permission, String script) {
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
        final Map<String, HudText> hud = new LinkedHashMap<>();
        int nextTask = 1;

        Loaded(Package pack) {
            this.manifest = pack.manifest();
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
    private final Map<String, Loaded> scripts = new LinkedHashMap<>();
    private final Map<String, CommandEntry> commands = new LinkedHashMap<>();
    private java.util.Set<String> reserved = java.util.Set.of();
    private long tick;

    /** El host del servidor. */
    public ScriptHost(Bridge bridge, ScriptLimits limits) {
        this(bridge, limits, false);
    }

    private ScriptHost(Bridge bridge, ScriptLimits limits, boolean client) {
        this.bridge = bridge;
        this.limits = limits;
        this.client = client;
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
        if (!client && loaded.manifest.has("commands")) {
            functions.add(RegisteredFunction.ofV("command", (s, args) -> command(loaded, args)));
        }
        RegisteredFunction.bind(sam, functions.toArray(RegisteredFunction[]::new));
        if (client && loaded.manifest.has("hud")) {
            var hud = new LuaTable();
            RegisteredFunction.bind(hud, new RegisteredFunction[] {
                RegisteredFunction.ofV("text", (s, args) -> hudText(loaded, args)),
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
        if (!options.isNil()) {
            var level = options.checkTable().rawget("permission");
            permission = level.isNil() ? 0 : level.checkInteger();
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
        commands.put(name, new CommandEntry(new Command(name, permission, loaded.id()), loaded, fn));
        return Constants.NONE;
    }

    /** {@code sam.hud.text(id, texto[, {anchor, x, y, color}])} (API de cliente v0). */
    private org.squiddev.cobalt.Varargs hudText(Loaded loaded, org.squiddev.cobalt.Varargs args) throws LuaError {
        var id = string(args.arg(1));
        var text = plain(string(args.arg(2)));
        var options = args.arg(3).isNil() ? new LuaTable() : args.arg(3).checkTable();
        if (!HUD_ID.matcher(id).matches()) {
            throw new LuaError("id de HUD inválido \"" + id + "\": [a-z0-9_], hasta 32");
        }
        var anchorName = options.rawget("anchor");
        var anchor = Anchor.TOP_LEFT;
        if (!anchorName.isNil()) {
            var name = string(anchorName);
            anchor = java.util.Arrays.stream(Anchor.values()).filter(a -> a.luaName().equals(name)).findFirst()
                .orElseThrow(() -> new LuaError("ancla desconocida \"" + name + "\""));
        }
        var x = offset(options.rawget("x"));
        var y = offset(options.rawget("y"));
        var colorValue = options.rawget("color");
        var color = colorValue.isNil() ? 0xFFFFFF : colorValue.checkInteger();
        if (color < 0 || color > 0xFFFFFF) {
            throw new LuaError("color debe ser 0xRRGGBB");
        }
        if (!loaded.hud.containsKey(id) && loaded.hud.size() >= MAX_HUD) {
            throw new LuaError("como mucho " + MAX_HUD + " textos por script");
        }
        loaded.hud.put(id, new HudText(loaded.id(), id, text, anchor, x, y, color));
        return Constants.NONE;
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
