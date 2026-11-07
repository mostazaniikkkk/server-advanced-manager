package dev.sam.common.lua;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;

import dev.sam.common.scripts.ScriptManifest;

/**
 * Lo que los scripts del cliente piden a la interfaz (API de cliente v0, PROTOCOLO.md 8.3): pantallas
 * declarativas, teclas e imágenes del propio script. El host valida; el juego decide si se puede (por
 * ejemplo, nunca sobre una pantalla de SAM) y dibuja.
 */
class ClientUiTest {

    private static final ScriptLimits LIMITES = new ScriptLimits(Duration.ofMillis(200), 16L * 1024 * 1024, 64 * 1024);
    private static final byte[] ICONO = PngInfoTest.png(16, 8, 0);

    /** El juego de mentira: guarda lo que le piden y responde lo que la prueba quiera. */
    private static final class Juego implements ScriptHost.ClientBridge {
        final List<String> log = new ArrayList<>();
        final List<ScreenSpec> abiertas = new ArrayList<>();
        final List<String> cerradas = new ArrayList<>();
        final List<String> teclas = new ArrayList<>();
        boolean sePuedeAbrir = true;

        @Override
        public void log(String script, String text) {
            log.add(text);
        }

        @Override
        public boolean openScreen(String script, ScreenSpec spec) {
            if (sePuedeAbrir) {
                abiertas.add(spec);
            }
            return sePuedeAbrir;
        }

        @Override
        public boolean closeScreen(String script) {
            cerradas.add(script);
            return true;
        }

        @Override
        public boolean bindKey(String script, String id, String key) {
            teclas.add(script + "." + id + "=" + key);
            return !key.equals("w");
        }
    }

    private final Juego juego = new Juego();
    private final ScriptHost host = ScriptHost.client(juego, LIMITES);

    private static ScriptHost.Package script(String id, String main, String... capacidades) {
        var assets = new LinkedHashMap<String, byte[]>();
        assets.put("assets/icono.png", ICONO);
        assets.put("assets/roto.png", new byte[] {1, 2, 3});
        return new ScriptHost.Package(new ScriptManifest(id, "1.0", ScriptManifest.Side.CLIENT, List.of(), List.of(capacidades), false),
            Map.of("main.lua", main), assets);
    }

    private ScriptHost.Status estado() {
        return host.status().getFirst();
    }

    @Test
    void unaPantallaDeclarativaSeAbreYRecibeSusEventos() {
        host.load(List.of(script("menu", """
            sam.log(tostring(sam.screen.on(function() end)))
            sam.log(tostring(sam.screen.on(function(e) sam.log(e.type .. ":" .. tostring(e.id) .. ":" .. tostring(e.value)) end)))
            sam.log(tostring(sam.screen.open({
              title = "Tienda", width = 200, height = 120,
              widgets = {
                {type = "label", x = 4, y = 4, text = "§aHola", color = 0xFFAA00},
                {type = "label", text = "sin posición"},
                {type = "button", id = "comprar", x = 4, y = 20, text = "Comprar"},
                {type = "text_field", id = "cantidad", x = 4, y = 44, w = 60, max = 3, value = "1"},
                {type = "checkbox", id = "regalo", x = 4, y = 70, text = "Es un regalo", checked = true},
                {type = "image", path = "assets/icono.png", x = 150, y = 4},
                {type = "image", path = "assets/icono.png", x = 150, y = 40, w = 32, h = 32},
              }})))
            sam.log(tostring(sam.screen.close()))
            """, "screens")));
        assertThat(estado().state()).isEqualTo(ScriptHost.State.RUNNING);
        assertThat(juego.log).containsExactly("false", "true", "true", "true");
        assertThat(juego.cerradas).containsExactly("menu");
        var pantalla = juego.abiertas.getFirst();
        assertThat(pantalla.title()).isEqualTo("Tienda");
        assertThat(pantalla.width()).isEqualTo(200);
        assertThat(pantalla.height()).isEqualTo(120);
        assertThat(pantalla.widgets()).hasSize(7);
        assertThat(pantalla.widgets().get(0)).isEqualTo(new ScreenSpec.Label(4, 4, "Hola", 0xFFAA00));
        assertThat(pantalla.widgets().get(1)).isEqualTo(new ScreenSpec.Label(0, 0, "sin posición", 0xFFFFFF));
        assertThat(pantalla.widgets().get(2)).isEqualTo(new ScreenSpec.Button("comprar", 4, 20, "Comprar", 80, 20));
        assertThat(pantalla.widgets().get(3)).isEqualTo(new ScreenSpec.TextField("cantidad", 4, 44, 60, 3, "1"));
        assertThat(pantalla.widgets().get(4)).isEqualTo(new ScreenSpec.Checkbox("regalo", 4, 70, "Es un regalo", true));
        var imagen = (ScreenSpec.Image) pantalla.widgets().get(5);
        assertThat(List.of(imagen.path(), imagen.x(), imagen.y(), imagen.w(), imagen.h())).containsExactly("assets/icono.png", 150, 4, 16, 8);
        assertThat(imagen.png()).isEqualTo(ICONO);
        var grande = (ScreenSpec.Image) pantalla.widgets().get(6);
        assertThat(List.of(grande.w(), grande.h())).containsExactly(32, 32);
        // Los eventos de su pantalla
        assertThat(host.screenEvent("menu", ScreenSpec.Event.click("comprar"))).isTrue();
        assertThat(host.screenEvent("menu", ScreenSpec.Event.change("cantidad", "12"))).isTrue();
        assertThat(host.screenEvent("menu", ScreenSpec.Event.change("regalo", false))).isTrue();
        assertThat(host.screenEvent("menu", ScreenSpec.Event.closed())).isTrue();
        assertThat(juego.log).containsExactly("false", "true", "true", "true", "click:comprar:nil", "change:cantidad:12", "change:regalo:false",
            "close:nil:nil");
        assertThat(host.screenEvent("otro", ScreenSpec.Event.closed())).isFalse();
    }

    @Test
    void conElPuenteMinimoNadaSeAbreNiSeAsigna() {
        var log = new ArrayList<String>();
        var minimo = ScriptHost.client((s, text) -> log.add(text), LIMITES);
        minimo.load(List.of(script("m", """
            sam.log(tostring(sam.screen.open({title = 'x', width = 64, height = 32, widgets = {}})) .. ","
              .. tostring(sam.screen.close()) .. "," .. tostring(sam.key("k", "k", function() end)))
            """, "screens", "keybinds")));
        assertThat(log).containsExactly("false,false,false");
        assertThat(minimo.keyPressed("m", "k")).isFalse();
    }

    @Test
    void enElServidorNoHayPantallasNiTeclas() {
        var log = new ArrayList<String>();
        var servidor = new ScriptHost(new ScriptHost.Bridge() {
            @Override
            public List<ScriptHost.Player> players() {
                return List.of();
            }

            @Override
            public void tell(String player, String text) {
            }

            @Override
            public void broadcast(String text) {
            }

            @Override
            public void log(String s, String text) {
                log.add(text);
            }
        }, LIMITES);
        servidor.load(List.of(script("srv", "sam.log(type(sam.screen) .. ',' .. type(sam.key))", "screens", "keybinds")));
        assertThat(log).containsExactly("nil,nil");
    }

    @Test
    void unScriptQueFallaAlCargarCierraSuPantalla() {
        host.load(List.of(script("roto", "sam.screen.open({title = 'x', width = 64, height = 32, widgets = {}}) error('falla')",
            "screens")));
        assertThat(juego.cerradas).containsExactly("roto");
    }

    @Test
    void sinEventosNiPermisoNoHayNada() {
        host.load(List.of(script("menu", "sam.log(tostring(sam.screen.open({title = 'x', width = 64, height = 32, widgets = {}})))",
            "screens"), script("nada", "sam.log(type(sam.screen) .. ',' .. type(sam.key))")));
        assertThat(host.screenEvent("menu", ScreenSpec.Event.closed())).isFalse();
        juego.sePuedeAbrir = false;
        host.load(List.of(script("menu", "sam.log(tostring(sam.screen.open({title = 'x', width = 400, height = 300, widgets = {}})))",
            "screens")));
        assertThat(juego.log).containsExactly("true", "nil,nil", "false");
    }

    @Test
    void unaPantallaInvalidaEsUnErrorDelScript() {
        var casos = new LinkedHashMap<String, String>();
        casos.put("{title = 'Iniciar sesión', width = 100, height = 100, widgets = {}}", "título reservado para las pantallas de SAM");
        casos.put("{title = ' opciones de cuenta ', width = 100, height = 100, widgets = {}}", "título reservado");
        casos.put("{title = string.rep('t', 65), width = 100, height = 100, widgets = {}}", "el título supera los 64 caracteres");
        casos.put("{title = 't', width = 63, height = 100, widgets = {}}", "width debe estar entre 64 y 400");
        casos.put("{title = 't', width = 401, height = 100, widgets = {}}", "width debe estar entre 64 y 400");
        casos.put("{title = 't', width = 100, height = 31, widgets = {}}", "height debe estar entre 32 y 300");
        casos.put("{title = 't', width = 100, height = 301, widgets = {}}", "height debe estar entre 32 y 300");
        casos.put("{title = 't', width = 100, height = 100, widgets = {{type = 'video', x = 0, y = 0}}}", "widget de tipo desconocido \"video\"");
        casos.put("{title = 't', width = 100, height = 100, widgets = {{type = 'label', x = 101, y = 0, text = 'a'}}}", "x e y deben estar dentro del panel");
        casos.put("{title = 't', width = 100, height = 100, widgets = {{type = 'label', x = 0, y = -1, text = 'a'}}}", "x e y deben estar dentro del panel");
        casos.put("{title = 't', width = 100, height = 100, widgets = {{type = 'label', x = -1, y = 0, text = 'a'}}}", "x e y deben estar dentro del panel");
        casos.put("{title = 't', width = 100, height = 100, widgets = {{type = 'label', x = 0, y = 101, text = 'a'}}}", "x e y deben estar dentro del panel");
        casos.put("{title = 't', width = 100, height = 100, widgets = {{type = 'button', id = 'A', x = 0, y = 0, text = 'a'}}}", "id de widget inválido \"A\"");
        casos.put("{title = 't', width = 100, height = 100, widgets = {{type = 'button', id = 'a', x = 0, y = 0, text = 'a'}, "
            + "{type = 'checkbox', id = 'a', x = 0, y = 0, text = 'b'}}}", "id de widget repetido \"a\"");
        casos.put("{title = 't', width = 100, height = 100, widgets = {{type = 'button', id = 'a', x = 0, y = 0, text = string.rep('b', 65)}}}",
            "el texto supera los 64 caracteres");
        casos.put("{title = 't', width = 100, height = 100, widgets = {{type = 'button', id = 'a', x = 0, y = 0, text = 'b', w = 15}}}", "w debe estar entre 16 y 400");
        casos.put("{title = 't', width = 100, height = 100, widgets = {{type = 'button', id = 'a', x = 0, y = 0, text = 'b', w = 401}}}", "w debe estar entre 16 y 400");
        casos.put("{title = 't', width = 100, height = 100, widgets = {{type = 'button', id = 'a', x = 0, y = 0, text = 'b', h = 11}}}", "h debe estar entre 12 y 40");
        casos.put("{title = 't', width = 100, height = 100, widgets = {{type = 'button', id = 'a', x = 0, y = 0, text = 'b', h = 41}}}", "h debe estar entre 12 y 40");
        casos.put("{title = 't', width = 100, height = 100, widgets = {{type = 'text_field', id = 'a', x = 0, y = 0, max = 0}}}", "max debe estar entre 1 y 256");
        casos.put("{title = 't', width = 100, height = 100, widgets = {{type = 'text_field', id = 'a', x = 0, y = 0, max = 257}}}", "max debe estar entre 1 y 256");
        casos.put("{title = 't', width = 100, height = 100, widgets = {{type = 'text_field', id = 'a', x = 0, y = 0, max = 2, value = 'abc'}}}",
            "value supera max");
        casos.put("{title = 't', width = 100, height = 100, widgets = {{type = 'checkbox', id = 'a', x = 0, y = 0, text = string.rep('b', 65)}}}",
            "el texto supera los 64 caracteres");
        casos.put("{title = 't', width = 100, height = 100, widgets = {{type = 'label', x = 0, y = 0, text = string.rep('b', 257)}}}",
            "el texto supera los 256 caracteres");
        casos.put("{title = 't', width = 100, height = 100, widgets = {{type = 'label', x = 0, y = 0, text = 'b', color = 0x1000000}}}",
            "color debe ser 0xRRGGBB");
        casos.put("{title = 't', width = 100, height = 100, widgets = {{type = 'image', path = 'assets/no.png', x = 0, y = 0}}}",
            "no hay una imagen \"assets/no.png\" en el script");
        casos.put("{title = 't', width = 100, height = 100, widgets = {{type = 'image', path = 'assets/roto.png', x = 0, y = 0}}}",
            "assets/roto.png: no es un PNG");
        casos.put("{title = 't', width = 100, height = 100, widgets = {{type = 'image', path = 'assets/icono.png', x = 0, y = 0, w = 0}}}",
            "w y h de una imagen deben estar entre 1 y 512");
        casos.put("{title = 't', width = 100, height = 100, widgets = {{type = 'image', path = 'assets/icono.png', x = 0, y = 0, h = 513}}}",
            "w y h de una imagen deben estar entre 1 y 512");
        var muchos = new StringBuilder("{title = 't', width = 100, height = 100, widgets = {");
        for (var i = 0; i < 65; i++) {
            muchos.append("{type = 'label', x = 0, y = 0, text = 'a'},");
        }
        casos.put(muchos + "}}", "como mucho 64 widgets");
        for (var caso : casos.entrySet()) {
            host.load(List.of(script("s", "sam.screen.open(" + caso.getKey() + ")", "screens")));
            assertThat(estado().state()).as(caso.getKey()).isEqualTo(ScriptHost.State.FAILED);
            assertThat(estado().errors().getFirst()).as(caso.getKey()).contains(caso.getValue());
        }
        assertThat(juego.abiertas).isEmpty();
        // Los topes justos valen
        var justos = new StringBuilder("{title = string.rep('t', 64), width = 64, height = 300, widgets = {"
            + "{type = 'button', id = string.rep('a', 32), x = 64, y = 300, text = string.rep('b', 64), w = 16, h = 12},"
            + "{type = 'button', id = 'b', x = 0, y = 0, text = 'b', w = 400, h = 40},"
            + "{type = 'text_field', id = 'c', x = 0, y = 0, max = 1, value = 'x'},"
            + "{type = 'text_field', id = 'd', x = 0, y = 0, max = 256},"
            + "{type = 'image', path = 'assets/icono.png', x = 0, y = 0, w = 1, h = 512},"
            + "{type = 'image', path = 'assets/icono.png', x = 0, y = 0, w = 512, h = 1},");
        for (var i = 0; i < 58; i++) {
            justos.append("{type = 'label', x = 0, y = 0, text = string.rep('l', 256), color = 0xFFFFFF},");
        }
        host.load(List.of(script("s", "sam.screen.open(" + justos + "}})", "screens")));
        assertThat(estado().errors()).isEmpty();
        var abierta = juego.abiertas.getFirst();
        assertThat(abierta.widgets()).hasSize(64);
        assertThat(abierta.widgets().get(2)).isEqualTo(new ScreenSpec.TextField("c", 0, 0, 120, 1, "x"));
        assertThat(abierta.widgets().get(3)).isEqualTo(new ScreenSpec.TextField("d", 0, 0, 120, 256, ""));
        var otraPantalla = "{title = 't', width = 400, height = 32, widgets = {{type = 'checkbox', id = 'a', x = 400, y = 32, text = 'b'}}}";
        host.load(List.of(script("s", "sam.screen.open(" + otraPantalla + ")", "screens")));
        assertThat(juego.abiertas.get(1).widgets().getFirst()).isEqualTo(new ScreenSpec.Checkbox("a", 400, 32, "b", false));
    }

    @Test
    void lasTeclasSeAsignanSiElJuegoLasDa() {
        host.load(List.of(script("k", """
            sam.log(tostring(sam.key("menu", "m", function() sam.log("menú") end)))
            sam.log(tostring(sam.key("avanzar", "w", function() sam.log("nunca") end)))
            sam.key("f", "f12", function() sam.log("efe") end)
            sam.key("d", "0", function() end)
            """, "keybinds")));
        assertThat(juego.teclas).containsExactly("k.menu=m", "k.avanzar=w", "k.f=f12", "k.d=0");
        assertThat(juego.log).containsExactly("true", "false");
        assertThat(host.keyPressed("k", "menu")).isTrue();
        assertThat(host.keyPressed("k", "avanzar")).isFalse();
        assertThat(host.keyPressed("k", "nada")).isFalse();
        assertThat(host.keyPressed("otro", "menu")).isFalse();
        assertThat(juego.log).last().isEqualTo("menú");
        var casos = Map.of(
            "sam.key('M', 'm', function() end)", "id de tecla inválido \"M\"",
            "sam.key('a', 'ctrl', function() end)", "tecla desconocida \"ctrl\" (a-z, 0-9 o f1-f12)",
            "sam.key('a', 'f13', function() end)", "tecla desconocida \"f13\"",
            "sam.key('a', 'f0', function() end)", "tecla desconocida \"f0\"",
            "sam.key('a', 'm', function() end) sam.key('a', 'n', function() end)", "la tecla \"a\" ya está registrada",
            "for i = 1, 9 do sam.key('t' .. i, tostring(i), function() end) end", "como mucho 8 teclas por script");
        for (var caso : casos.entrySet()) {
            host.load(List.of(script("s", caso.getKey(), "keybinds")));
            assertThat(estado().state()).as(caso.getKey()).isEqualTo(ScriptHost.State.FAILED);
            assertThat(estado().errors().getFirst()).as(caso.getKey()).contains(caso.getValue());
        }
        host.load(List.of(script("s", "for i = 1, 8 do sam.key('t' .. i, tostring(i), function() end) end sam.key('f', 'f1', function() end)",
            "keybinds")));
        assertThat(estado().errors().getFirst()).contains("como mucho 8 teclas por script");
        host.load(List.of(script("s", "for i = 1, 8 do assert(sam.key('t' .. i, tostring(i), function() end)) end", "keybinds")));
        assertThat(estado().errors()).isEmpty();
    }

    @Test
    void elHudTambienDibujaImagenesDelScript() {
        host.load(List.of(script("hud", """
            sam.hud.image("logo", "assets/icono.png", {anchor = "top_right", x = -2, y = 2})
            sam.hud.image("grande", "assets/icono.png", {w = 64, h = 32})
            sam.hud.text("t", "texto")
            """, "hud")));
        assertThat(estado().errors()).isEmpty();
        assertThat(host.hud()).extracting(ScriptHost.HudText::id).containsExactly("t");
        var imagenes = host.hudImages();
        assertThat(imagenes).extracting(ScriptHost.HudImage::id).containsExactly("logo", "grande");
        var logo = imagenes.getFirst();
        assertThat(List.of(logo.script(), logo.path(), logo.anchor(), logo.x(), logo.y(), logo.w(), logo.h()))
            .containsExactly("hud", "assets/icono.png", ScriptHost.Anchor.TOP_RIGHT, -2, 2, 16, 8);
        assertThat(logo.png()).isEqualTo(ICONO);
        assertThat(List.of(imagenes.get(1).w(), imagenes.get(1).h())).containsExactly(64, 32);
        var casos = Map.of(
            "sam.hud.image('a', 'assets/no.png')", "no hay una imagen \"assets/no.png\" en el script",
            "sam.hud.image('a', 'assets/roto.png')", "assets/roto.png: no es un PNG",
            "sam.hud.image('a', 'assets/icono.png', {w = 513})", "w y h de una imagen deben estar entre 1 y 512",
            "sam.hud.image('A', 'assets/icono.png')", "id de HUD inválido",
            "for i = 1, 64 do sam.hud.text('t' .. i, 'x') end sam.hud.image('i', 'assets/icono.png')", "como mucho 64 textos por script");
        for (var caso : casos.entrySet()) {
            host.load(List.of(script("s", caso.getKey(), "hud")));
            assertThat(estado().state()).as(caso.getKey()).isEqualTo(ScriptHost.State.FAILED);
            assertThat(estado().errors().getFirst()).as(caso.getKey()).contains(caso.getValue());
        }
        // Un texto y una imagen con el mismo id se reemplazan
        host.load(List.of(script("s", "sam.hud.text('a', 'x') sam.hud.image('a', 'assets/icono.png')", "hud")));
        assertThat(host.hud()).isEmpty();
        assertThat(host.hudImages()).hasSize(1);
    }

    @Test
    void unScriptQueSeSuspendeCierraSuPantallaYSoltaSusTeclas() {
        host.load(List.of(script("lento", """
            sam.screen.open({title = 'x', width = 100, height = 100, widgets = {}})
            sam.screen.on(function(e) while true do end end)
            sam.key("k", "k", function() end)
            sam.hud.image("i", "assets/icono.png")
            """, "screens", "keybinds", "hud")));
        assertThat(host.hudImages()).hasSize(1);
        assertThat(host.screenEvent("lento", ScreenSpec.Event.click("a"))).isTrue();
        assertThat(estado().state()).isEqualTo(ScriptHost.State.SUSPENDED);
        assertThat(juego.cerradas).containsExactly("lento");
        assertThat(host.keyPressed("lento", "k")).isFalse();
        assertThat(host.hudImages()).isEmpty();
        assertThat(host.screenEvent("lento", ScreenSpec.Event.closed())).isFalse();
    }
}
