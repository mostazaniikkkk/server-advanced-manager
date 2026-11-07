package dev.sam.common.lua;

import static org.squiddev.cobalt.ValueFactory.valueOf;
import static org.squiddev.cobalt.ValueFactory.varargsOf;

import java.io.ByteArrayInputStream;
import java.lang.management.ManagementFactory;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.function.LongSupplier;
import java.util.regex.Pattern;

import org.squiddev.cobalt.Constants;
import org.squiddev.cobalt.LuaError;
import org.squiddev.cobalt.LuaState;
import org.squiddev.cobalt.LuaString;
import org.squiddev.cobalt.LuaTable;
import org.squiddev.cobalt.LuaThread;
import org.squiddev.cobalt.LuaValue;
import org.squiddev.cobalt.Varargs;
import org.squiddev.cobalt.compiler.CompileException;
import org.squiddev.cobalt.compiler.LoadState;
import org.squiddev.cobalt.function.LuaFunction;
import org.squiddev.cobalt.function.RegisteredFunction;
import org.squiddev.cobalt.interrupt.InterruptAction;
import org.squiddev.cobalt.lib.BaseLib;
import org.squiddev.cobalt.lib.MathLib;
import org.squiddev.cobalt.lib.StringLib;
import org.squiddev.cobalt.lib.TableLib;
import org.squiddev.cobalt.lib.Utf8Lib;

/**
 * La sandbox de Lua de SAM (RS-LUA-00 a 03, RS-LUA-06), igual en servidor y cliente. Cada script tiene su
 * propio estado de Cobalt (sus propios globales). Lista blanca: la base sin {@code getfenv}, {@code setfenv}
 * ni {@code loadstring}, más {@code string} (Cobalt no trae {@code dump}; {@code rep} va acotado), {@code table},
 * {@code math} y {@code utf8}; un {@code time()} propio; {@code load} solo de texto y {@code require} solo de
 * módulos del mismo script. Cada llamada tiene un tope de tiempo y uno aproximado de memoria (los bytes que
 * asigna el hilo mientras corre el script, RN-25).
 */
public final class LuaSandbox {

    private static final Pattern MODULE = Pattern.compile("[A-Za-z0-9_]+(\\.[A-Za-z0-9_]+)*");
    private static final List<String> REMOVED = List.of("getfenv", "setfenv", "loadstring");
    private static final long CHECK_EVERY_MS = 2;
    private static final ScheduledExecutorService WATCHDOG = Executors.newSingleThreadScheduledExecutor(runnable -> {
        var thread = new Thread(runnable, "SAM Lua vigilante");
        thread.setDaemon(true);
        return thread;
    });
    /** {@code require} en Lua: el cargador Java solo compila; ejecutar y cachear se hace aquí. */
    private static final String PRELUDE = """
        local compile = ...
        local cache = {}
        require = function(name)
          local cached = cache[name]
          if cached ~= nil then return cached end
          local result = compile(name)()
          if result == nil then result = true end
          cache[name] = result
          return result
        end
        """;

    private LuaSandbox() {
    }

    /**
     * El resultado de ejecutar algo: el primer valor devuelto (como texto; vacío si es nil) o el error.
     *
     * @param exceeded el error fue por pasarse del tiempo o de la memoria (RS-LUA-03: se suspende)
     */
    public record Outcome(Optional<String> value, Optional<String> error, boolean exceeded) {

        static Outcome ok(String value) {
            return new Outcome(Optional.of(value), Optional.empty(), false);
        }

        public static Outcome failed(String error) {
            return new Outcome(Optional.empty(), Optional.of(error), false);
        }
    }

    /** @param files rutas relativas dentro del script ({@code main.lua}, {@code util.lua}, {@code ui/menu.lua}) */
    public static Script load(String id, Map<String, String> files, ScriptLimits limits) {
        return load(id, files, limits, System::nanoTime, LuaSandbox::allocated);
    }

    /** Con el reloj y el medidor de memoria inyectados (pruebas de los bordes). */
    static Script load(String id, Map<String, String> files, ScriptLimits limits, LongSupplier nanos, LongSupplier allocation) {
        return new Script(id, Map.copyOf(files), limits, nanos, allocation);
    }

    /** Un script cargado: su propio estado de Lua. No es seguro entre hilos: cada llamada se sincroniza. */
    public static final class Script {

        private final String id;
        private final Map<String, String> files;
        private final ScriptLimits limits;
        private final LuaState state;
        private final LongSupplier nanos;
        private final LongSupplier allocation;
        private volatile long deadline;
        private volatile long allocationStart;
        private volatile boolean exceeded;

        private Script(String id, Map<String, String> files, ScriptLimits limits, LongSupplier nanos, LongSupplier allocation) {
            this.id = id;
            this.files = files;
            this.limits = limits;
            this.nanos = nanos;
            this.allocation = allocation;
            this.state = LuaState.builder().interruptHandler(this::interrupted).build();
        }

        public String id() {
            return id;
        }

        /** El estado de Lua del script, para que la API de SAM instale sus funciones (nunca objetos Java). */
        public LuaState state() {
            return state;
        }

        /** Instala la sandbox y ejecuta {@code main.lua}. */
        public Outcome start() {
            return start(state -> { });
        }

        /**
         * Instala la sandbox, después la API de SAM ({@code api}, antes de que corra nada del script) y
         * ejecuta {@code main.lua}.
         */
        public synchronized Outcome start(java.util.function.Consumer<LuaState> api) {
            try {
                install();
            } catch (LuaError | CompileException e) {
                throw new IllegalStateException("la sandbox de Lua no se pudo preparar", e);
            }
            api.accept(state);
            var main = files.get("main.lua");
            if (main == null) {
                return Outcome.failed("falta main.lua");
            }
            try {
                return guarded(compile("@main.lua", main, state.globals()), Constants.NONE);
            } catch (CompileException | LuaError e) {
                return Outcome.failed(e.getMessage());
            }
        }

        /** Llama a una función global del script con los límites de una invocación. */
        public synchronized Outcome call(String function, LuaValue... args) {
            var fn = state.globals().rawget(function);
            if (!(fn instanceof LuaFunction lua)) {
                return Outcome.failed("el script no define la función " + function);
            }
            return guarded(lua, varargsOf(args));
        }

        /** Llama a una función del script que la API guardó (un manejador de eventos, una tarea). */
        public synchronized Outcome invoke(LuaFunction function, LuaValue... args) {
            return guarded(function, varargsOf(args));
        }

        private Outcome guarded(LuaFunction function, Varargs args) {
            arm();
            var alarm = WATCHDOG.scheduleAtFixedRate(state::interrupt, CHECK_EVERY_MS, CHECK_EVERY_MS, TimeUnit.MILLISECONDS);
            try {
                var first = LuaThread.runMain(state, function, args).first();
                // nil (o nada) es "sin valor": un comando sin respuesta, por ejemplo
                return first.isNil() ? new Outcome(Optional.empty(), Optional.empty(), false) : Outcome.ok(text(first));
            } catch (LuaError e) {
                // Cobalt ya convierte en LuaError las excepciones Java de la API y el desborde de pila
                return new Outcome(Optional.empty(), Optional.of(e.getMessage()), exceeded);
            } finally {
                alarm.cancel(false);
            }
        }

        /** Empieza una invocación: su plazo y su punto de partida de memoria. */
        void arm() {
            exceeded = false;
            deadline = nanos.getAsLong() + limits.perCall().toNanos();
            allocationStart = allocation.getAsLong();
        }

        private InterruptAction interrupted() throws LuaError {
            checkLimits();
            return InterruptAction.CONTINUE;
        }

        /** Lo que revisa el vigilante: tiempo y memoria de la invocación en curso. */
        void checkLimits() throws LuaError {
            if (nanos.getAsLong() > deadline) {
                exceeded = true;
                throw new LuaError("el script superó su tiempo (" + limits.perCall().toMillis() + " ms)");
            }
            // Si la JVM no informa la memoria del hilo devuelve siempre -1: la diferencia es 0 y solo vale el tiempo
            if (allocation.getAsLong() - allocationStart > limits.allocationBytes()) {
                exceeded = true;
                throw new LuaError("el script superó su memoria (" + limits.allocationBytes() / (1024 * 1024) + " MiB)");
            }
        }

        private void install() throws LuaError, CompileException {
            BaseLib.add(state);
            StringLib.add(state);
            TableLib.add(state);
            MathLib.add(state);
            Utf8Lib.add(state);
            var globals = state.globals();
            for (var name : REMOVED) {
                globals.rawset(name, Constants.NIL);
            }
            var string = (LuaTable) globals.rawget("string");
            RegisteredFunction.bind(string, new RegisteredFunction[] {RegisteredFunction.ofV("rep", this::rep)});
            // La metatabla de los strings no se puede leer ni cambiar
            state.stringMetatable.rawset("__metatable", Constants.FALSE);
            RegisteredFunction.bind(globals, new RegisteredFunction[] {
                RegisteredFunction.ofV("load", this::loadText),
                // En lugar de os.time: los segundos de la hora del servidor
                RegisteredFunction.of("time", s -> valueOf((double) (System.currentTimeMillis() / 1000))),
            });
            var compiler = RegisteredFunction.of("compile", this::compileModule).create();
            var prelude = compile("=sam", PRELUDE, globals);
            LuaThread.runMain(state, prelude, compiler);
        }

        /** {@code string.rep} con tope: el resultado no puede superar {@code maxStringBytes}. */
        private Varargs rep(LuaState s, Varargs args) throws LuaError {
            var text = args.arg(1).checkLuaString();
            var times = args.arg(2).checkLong();
            var separator = args.arg(3).isNil() ? LuaString.valueOf("") : args.arg(3).checkLuaString();
            if (times <= 0) {
                return LuaString.valueOf("");
            }
            var length = text.length() * times + separator.length() * (times - 1);
            if (length > limits.maxStringBytes()) {
                throw new LuaError("string.rep: resultado demasiado largo (" + length + " bytes, máximo " + limits.maxStringBytes() + ")");
            }
            var out = new byte[(int) length];
            var at = 0;
            for (var i = 0; i < times; i++) {
                if (i > 0) {
                    separator.copyTo(0, out, at, separator.length());
                    at += separator.length();
                }
                text.copyTo(0, out, at, text.length());
                at += text.length();
            }
            return LuaString.valueOf(out);
        }

        /** {@code load} solo de texto, con el entorno del script salvo que se pase una tabla propia. */
        private Varargs loadText(LuaState s, Varargs args) throws LuaError {
            var chunk = args.arg(1);
            if (!(chunk instanceof LuaString text)) {
                return varargsOf(Constants.NIL, valueOf("load solo acepta texto"));
            }
            var source = text.toString();
            if (source.startsWith("\u001b")) {
                return varargsOf(Constants.NIL, valueOf("load no acepta bytecode"));
            }
            var name = args.arg(2).isNil() ? "=(load)" : args.arg(2).toString();
            var env = args.arg(4) instanceof LuaTable table ? table : s.globals();
            try {
                return compile(name, source, env);
            } catch (CompileException e) {
                return varargsOf(Constants.NIL, valueOf(e.getMessage()));
            }
        }

        /** El cargador de {@code require}: solo módulos de este script, por nombre ({@code ui.menu} → {@code ui/menu.lua}). */
        private LuaValue compileModule(LuaState s, LuaValue name) throws LuaError {
            var module = name.checkString();
            var source = MODULE.matcher(module).matches() ? files.get(module.replace('.', '/') + ".lua") : null;
            if (source == null) {
                throw new LuaError("el módulo " + module + " no existe en este script");
            }
            try {
                return compile("@" + module.replace('.', '/') + ".lua", source, s.globals());
            } catch (CompileException e) {
                throw new LuaError(e.getMessage());
            }
        }

        /** @param name el nombre del chunk como en Lua: {@code @archivo.lua} o {@code =texto} */
        private LuaFunction compile(String name, String source, LuaTable env) throws CompileException, LuaError {
            return LoadState.load(state, new ByteArrayInputStream(source.getBytes(StandardCharsets.UTF_8)), name, env);
        }
    }

    /**
     * Un valor de Lua como texto Java. Los strings de Lua son bytes: se leen como UTF-8 (el
     * {@code toString} de Cobalt los lee como Latin-1 y rompe los acentos).
     */
    public static String text(LuaValue value) {
        if (value instanceof LuaString string) {
            var bytes = new byte[string.length()];
            string.copyTo(0, bytes, 0, bytes.length);
            return new String(bytes, StandardCharsets.UTF_8);
        }
        return value.toString();
    }

    /** Texto Java como string de Lua, en UTF-8. */
    public static LuaString lua(String text) {
        return LuaString.valueOf(text.getBytes(StandardCharsets.UTF_8));
    }

    /** Los bytes que asignó este hilo (com.sun.management, presente en HotSpot y OpenJ9); -1 si no lo informa. */
    private static long allocated() {
        return ((com.sun.management.ThreadMXBean) ManagementFactory.getThreadMXBean()).getCurrentThreadAllocatedBytes();
    }
}
