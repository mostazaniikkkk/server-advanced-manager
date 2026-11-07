package dev.sam.common.lua;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.Map;

import org.junit.jupiter.api.Test;

/**
 * La sandbox de Lua (RS-LUA-00 a RS-LUA-03, RS-LUA-06, RN-24/25): lista blanca de librerías, sin IO, red,
 * OS ni Java; {@code load} solo de texto; {@code require} solo dentro del script; límites de tiempo y de
 * memoria por llamada. Batería de scripts maliciosos (RS-LUA-02d): todos fallan de forma controlada.
 */
class LuaSandboxTest {

    private static final ScriptLimits LIMITES = new ScriptLimits(Duration.ofMillis(250), 16L * 1024 * 1024, 64 * 1024);

    private static LuaSandbox.Script script(String main) {
        return script(Map.of("main.lua", main));
    }

    private static LuaSandbox.Script script(Map<String, String> files) {
        return LuaSandbox.load("prueba", files, LIMITES);
    }

    /** Ejecuta {@code main.lua} (que define {@code f}) y devuelve lo que retorna {@code f()} como texto. */
    private static LuaSandbox.Outcome f(String main) {
        var script = script(main);
        assertThat(script.start().error()).as("main.lua debe cargar").isEmpty();
        return script.call("f");
    }

    @Test
    void soloEstanLasLibreriasDeLaListaBlanca() {
        var presentes = f("""
            function f()
              local nombres = {}
              for k in pairs(_G) do nombres[#nombres + 1] = k end
              table.sort(nombres)
              return table.concat(nombres, ",")
            end""");
        assertThat(presentes.value()).contains(
            "_G,_VERSION,assert,error,f,getmetatable,ipairs,load,math,next,pairs,pcall,rawequal,rawget,rawlen,rawset,"
                + "require,select,setmetatable,string,table,time,tonumber,tostring,type,unpack,utf8,xpcall");
    }

    @Test
    void nadaQueToqueArchivosRedOSOJava() {
        var intentos = new LinkedHashMap<String, String>();
        intentos.put("io", "return io.open('x.txt', 'w')");
        intentos.put("os", "return os.execute('calc')");
        intentos.put("os.time", "return os.time()");
        intentos.put("debug", "return debug.getinfo(1)");
        intentos.put("package", "return package.loadlib('x', 'y')");
        intentos.put("luajava", "return luajava.bindClass('java.lang.Runtime')");
        intentos.put("dofile", "return dofile('main.lua')");
        intentos.put("loadfile", "return loadfile('main.lua')");
        intentos.put("loadstring", "return loadstring('return 1')()");
        intentos.put("getfenv", "return getfenv(0)");
        intentos.put("setfenv", "return setfenv(1, {})");
        intentos.put("string.dump", "return string.dump(function() end)");
        intentos.put("collectgarbage", "return collectgarbage('count')");
        intentos.put("coroutine", "return coroutine.create(function() end)");
        intentos.put("require de librería", "return require('os')");
        intentos.put("require fuera del script", "return require('../otro/main')");
        for (var intento : intentos.entrySet()) {
            var resultado = f("function f() " + intento.getValue() + " end");
            assertThat(resultado.error()).as(intento.getKey()).isPresent();
        }
    }

    @Test
    void loadSoloAceptaTextoYUsaElEntornoDelScript() {
        assertThat(f("secreto = 7 function f() return load('return secreto')() end").value()).contains("7");
        // Un chunk binario (bytecode) se rechaza aunque se pida modo "b"
        assertThat(f("function f() return load('\\27Lua' .. string.rep('x', 40), 'x', 'b') end").value()).contains("nil");
        assertThat(f("function f() local fn, err = load('\\27Lua' .. string.rep('x', 40)) return err ~= nil end").value())
            .contains("true");
        // Un entorno pedido explícitamente sí se respeta (es una tabla del propio script)
        assertThat(f("function f() return load('return x', 'c', 't', {x = 5})() end").value()).contains("5");
    }

    @Test
    void requireCargaModulosDelMismoScriptUnaSolaVez() {
        var files = Map.of("main.lua", """
            local util = require('util')
            local otra = require('util')
            function f() return util.doble(21) .. ":" .. tostring(util == otra) .. ":" .. contador end
            """, "util.lua", """
            contador = (contador or 0) + 1
            return { doble = function(n) return n * 2 end }
            """);
        var s = script(files);
        assertThat(s.start().error()).isEmpty();
        assertThat(s.call("f").value()).contains("42:true:1");
        assertThat(script(Map.of("main.lua", "require('no_existe')")).start().error()).hasValueSatisfying(
            e -> assertThat(e).contains("no_existe"));
    }

    @Test
    void cadaScriptTieneSusPropiosGlobales() {
        var a = script("compartido = 'a' function f() return compartido end");
        var b = script("function f() return tostring(compartido) end");
        a.start();
        b.start();
        assertThat(a.call("f").value()).contains("a");
        assertThat(b.call("f").value()).contains("nil");
        // Ni siquiera la metatabla de los strings se comparte ni se puede cambiar
        var c = script("function f() return tostring(getmetatable('')) end");
        c.start();
        assertThat(c.call("f").value()).contains("false");
    }

    @Test
    void unLoopInfinitoSeCortaPorTiempo() {
        var inicio = System.nanoTime();
        var resultado = f("function f() while true do end end");
        var ms = (System.nanoTime() - inicio) / 1_000_000;
        assertThat(resultado.error()).hasValueSatisfying(e -> assertThat(e).contains("tiempo"));
        assertThat(ms).isLessThan(2_000);
        // El script sigue usable después
        var s = script("n = 0 function f() n = n + 1 return n end function g() while true do end end");
        s.start();
        assertThat(s.call("g").error()).isPresent();
        assertThat(s.call("f").value()).contains("1");
    }

    @Test
    void agotarLaMemoriaSeCortaAntesDeDanarAlServidor() {
        var resultado = f("""
            function f()
              local t = {}
              for i = 1, 1e9 do t[i] = {i, i, i, i} end
            end""");
        assertThat(resultado.error()).hasValueSatisfying(e -> assertThat(e).containsAnyOf("memoria", "tiempo"));
        assertThat(f("function f() return string.rep('x', 1e9) end").error())
            .hasValueSatisfying(e -> assertThat(e).contains("demasiado largo"));
        assertThat(f("function f() return #string.rep('ab', 1000, ',') end").value()).contains("2999");
    }

    @Test
    void unaRecursionInfinitaEsUnErrorDeLuaNoDeLaJvm() {
        assertThat(f("local function r() return 1 + r() end function f() return r() end").error()).isPresent();
    }

    @Test
    void unErrorEnMainOEnUnaFuncionQuedaAisladoYSinRutas() {
        var roto = script("error('roto')");
        assertThat(roto.start().error()).hasValueSatisfying(e -> assertThat(e).contains("roto").doesNotContain(":\\").doesNotContain("/home"));
        assertThat(script("esto no es lua").start().error()).isPresent();
        var s = script("function f() error({}) end");
        s.start();
        assertThat(s.call("f").error()).isPresent();
        assertThat(s.call("no_existe").error()).hasValueSatisfying(e -> assertThat(e).contains("no_existe"));
    }

    @Test
    void unScriptLegitimoQueTardaUnPocoTermina() {
        // Más que el intervalo del vigilante (2 ms) pero muy por debajo del tope
        assertThat(f("function f() local n = 0 for i = 1, 2e5 do n = n + i end return n end").value()).contains("20000100000");
        assertThat(f("function f() local t = {} for i = 1, 2e4 do t[i] = {i} end return #t end").value()).contains("20000");
    }

    @Test
    void elTopeDeMemoriaEsIndependienteDelDeTiempo() {
        var poca = new ScriptLimits(Duration.ofSeconds(5), 2L * 1024 * 1024, 64 * 1024);
        var s = LuaSandbox.load("glotón", Map.of("main.lua", "function f() local t = {} for i = 1, 1e8 do t[i] = {i, i} end end"), poca);
        s.start();
        assertThat(s.call("f").error()).hasValueSatisfying(e -> assertThat(e).contains("memoria").contains("(2 MiB)"));
    }

    @Test
    void losTopesSeCumplenJustoEnElBorde() throws Exception {
        var reloj = new long[] {1_000};
        var memoria = new long[] {500};
        var s = LuaSandbox.load("borde", Map.of("main.lua", ""), new ScriptLimits(Duration.ofNanos(100), 2L * 1024 * 1024, 10),
            () -> reloj[0], () -> memoria[0]);
        s.arm();
        reloj[0] = 1_100;
        s.checkLimits();
        reloj[0] = 1_101;
        org.assertj.core.api.Assertions.assertThatThrownBy(s::checkLimits).hasMessageContaining("tiempo (0 ms)");
        reloj[0] = 1_000;
        memoria[0] = 500 + 2L * 1024 * 1024;
        s.checkLimits();
        memoria[0]++;
        org.assertj.core.api.Assertions.assertThatThrownBy(s::checkLimits).hasMessageContaining("memoria (2 MiB)");
        // Si la JVM no informa la memoria (siempre -1), solo vale el tiempo
        memoria[0] = -1;
        s.arm();
        s.checkLimits();
    }

    @Test
    void stringRepRespetaElTopeJustoYElSeparador() {
        assertThat(f("function f() return string.rep('ab', 3, ',') end").value()).contains("ab,ab,ab");
        assertThat(f("function f() return string.rep('ab', 3) end").value()).contains("ababab");
        assertThat(f("function f() return '[' .. string.rep('x', 0, ',') .. string.rep('x', -1) .. ']' end").value()).contains("[]");
        assertThat(f("function f() return #string.rep('x', 64 * 1024) end").value()).contains("65536");
        assertThat(f("function f() return string.rep('x', 64 * 1024 + 1) end").error()).isPresent();
    }

    @Test
    void loadExplicaPorQueNoCarga() {
        assertThat(f("function f() local fn, err = load(function() return 'x' end) return err end").value())
            .contains("load solo acepta texto");
        assertThat(f("function f() local fn, err = load('\\27Lua') return err end").value()).contains("load no acepta bytecode");
        assertThat(f("function f() local fn, err = load('esto no compila') return tostring(fn) .. ':' .. tostring(err ~= nil) end")
            .value()).contains("nil:true");
        assertThat(f("function f() return select(2, pcall(load('error(\"x\")', 'mi_chunk'))) end").value())
            .hasValueSatisfying(v -> assertThat(v).contains("mi_chunk"));
        assertThat(f("function f() return select(2, pcall(load('error(\"x\")'))) end").value())
            .hasValueSatisfying(v -> assertThat(v).contains("(load)"));
    }

    @Test
    void requireSoloAceptaNombresDeModuloYLosErroresDicenElArchivo() {
        var files = Map.of("main.lua", "function f() return require('a-b') end function g() return require('util').roto() end",
            "a-b.lua", "return 1", "util.lua", "return { roto = function() error('falló') end }");
        var s = script(files);
        s.start();
        assertThat(s.call("f").error()).hasValueSatisfying(e -> assertThat(e).contains("a-b").contains("no existe"));
        assertThat(s.call("g").error()).hasValueSatisfying(e -> assertThat(e).contains("util.lua"));
        assertThat(script(Map.of("otro.lua", "")).start().error()).contains("falta main.lua");
    }

    @Test
    void unaFallaInternaDeLaApiNoTumbaAlServidor() {
        var s = script("function f() return romper() end function g() return desbordar() end");
        assertThat(s.id()).isEqualTo("prueba");
        s.start();
        org.squiddev.cobalt.function.RegisteredFunction.bind(s.state().globals(), new org.squiddev.cobalt.function.RegisteredFunction[] {
            org.squiddev.cobalt.function.RegisteredFunction.of("romper", st -> {
                throw new IllegalStateException("x");
            }),
            org.squiddev.cobalt.function.RegisteredFunction.of("desbordar", st -> {
                throw new StackOverflowError();
            })});
        // Cobalt la convierte en un error de Lua del propio script; el servidor sigue
        assertThat(s.call("f").error()).hasValueSatisfying(e -> assertThat(e).contains("IllegalStateException"));
        assertThat(s.call("g").error()).hasValueSatisfying(e -> assertThat(e).contains("StackOverflowError"));
    }

    @Test
    void timeEsElDeSamEnSegundos() {
        var antes = System.currentTimeMillis() / 1000;
        var t = Long.parseLong(f("function f() return time() end").value().orElseThrow());
        assertThat(t).isBetween(antes, antes + 2);
    }
}
