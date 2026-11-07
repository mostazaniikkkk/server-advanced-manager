package dev.sam.common.lua;

import static org.squiddev.cobalt.ValueFactory.valueOf;

import java.util.ArrayList;
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
    private static final int MAX_LOG = 512;
    private static final int MAX_ERRORS = 20;

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

    private record Task(int id, long due, int every, LuaFunction function) {
    }

    private final class Loaded {
        final ScriptManifest manifest;
        final LuaSandbox.Script script;
        State state = State.RUNNING;
        final List<String> errors = new ArrayList<>();
        final Map<Event, List<LuaFunction>> handlers = new EnumMap<>(Event.class);
        final Map<Integer, Task> tasks = new TreeMap<>();
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
    private final Map<String, Loaded> scripts = new LinkedHashMap<>();
    private long tick;

    public ScriptHost(Bridge bridge, ScriptLimits limits) {
        this.bridge = bridge;
        this.limits = limits;
    }

    /** Descarta todo lo cargado y carga estos scripts (RF-LUA-02: errores aislados por script). */
    public synchronized void load(List<Package> packages) {
        scripts.clear();
        for (var pack : packages) {
            var loaded = new Loaded(pack);
            scripts.put(loaded.id(), loaded);
            var outcome = loaded.script.start(state -> installApi(loaded, state));
            if (outcome.error().isPresent()) {
                loaded.state = State.FAILED;
                record(loaded, outcome.error().get());
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
        if (loaded.manifest.has("events")) {
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
        if (loaded.manifest.has("players")) {
            functions.add(RegisteredFunction.of("players", s -> {
                var list = new LuaTable();
                var players = bridge.players();
                for (var i = 0; i < players.size(); i++) {
                    list.rawset(i + 1, playerTable(players.get(i)));
                }
                return list;
            }));
        }
        if (loaded.manifest.has("chat")) {
            functions.add(RegisteredFunction.of("tell", (s, player, text) -> {
                bridge.tell(string(player), plain(string(text)));
                return Constants.NIL;
            }));
            functions.add(RegisteredFunction.of("broadcast", (s, text) -> {
                bridge.broadcast(plain(string(text)));
                return Constants.NIL;
            }));
        }
        RegisteredFunction.bind(sam, functions.toArray(RegisteredFunction[]::new));
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
