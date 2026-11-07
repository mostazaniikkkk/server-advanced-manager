package dev.sam.client.scripts;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayDeque;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Properties;

import org.lwjgl.glfw.GLFW;
import org.slf4j.Logger;

import com.mojang.blaze3d.platform.InputConstants;
import com.mojang.blaze3d.platform.NativeImage;

import dev.sam.client.ProtectedScreen;
import dev.sam.client.net.SamClientNet;
import dev.sam.client.net.SamPayload;
import dev.sam.common.lua.ScreenSpec;
import dev.sam.common.lua.ScriptHost;
import dev.sam.common.lua.ScriptLimits;
import dev.sam.common.proto.ProtocolException;
import dev.sam.common.proto.SamWriter;
import dev.sam.common.proto.scripts.LuaMessage;
import io.netty.buffer.ByteBufUtil;
import io.netty.buffer.Unpooled;
import net.fabricmc.fabric.api.client.event.lifecycle.v1.ClientTickEvents;
import net.fabricmc.fabric.api.client.keybinding.v1.KeyBindingHelper;
import net.fabricmc.fabric.api.client.networking.v1.ClientPlayConnectionEvents;
import net.fabricmc.fabric.api.client.networking.v1.ClientPlayNetworking;
import net.fabricmc.fabric.api.client.rendering.v1.HudRenderCallback;
import net.minecraft.client.Minecraft;
import net.minecraft.client.gui.GuiGraphics;
import net.minecraft.client.renderer.texture.DynamicTexture;
import net.minecraft.network.chat.Component;
import net.minecraft.resources.ResourceLocation;

/**
 * Los scripts aceptados corren en el juego (API de cliente v0, PROTOCOLO.md 8.3): se cargan al entrar al
 * mundo y se descargan al salir (RF-LUA-09b). Lo que piden (mensajes, pantallas, teclas, imágenes) pasa por
 * aquí. Mientras hay una pantalla de SAM abierta no reciben nada (RS-LUA-08): ni ticks, ni teclas, ni
 * mensajes (esperan, hasta 64). Lua solo corre en el hilo del juego y nunca dentro del render.
 */
final class ClientScriptRuntime implements ScriptHost.ClientBridge {

    /**
     * Lo mismo que el servidor por defecto (RS-LUA-03): 50 ms por llamada. Lua corre en el tick, nunca en el
     * render, así que el peor caso de un script que se pasa es un tirón de un tick antes de suspenderlo; con
     * 10 ms, la primera ejecución de un script normal fallaba con la JVM todavía fría.
     */
    private static final ScriptLimits LIMITS = new ScriptLimits(Duration.ofMillis(50), 32L * 1024 * 1024, 64 * 1024);
    private static final int MAX_WAITING = 64;

    private record Waiting(String script, String channel, byte[] data) {
    }

    private record Bound(String script, String id) {
    }

    private final Logger log;
    private final Path keysFile;
    private final ScriptHost host;
    private boolean running;
    private final ArrayDeque<Waiting> waiting = new ArrayDeque<>();
    /** Código GLFW → tecla de script, y si estaba apretada en el tick anterior. */
    private final Map<Integer, Bound> keys = new LinkedHashMap<>();
    private final Map<Integer, Boolean> down = new HashMap<>();
    /** Las imágenes ya subidas a la GPU en esta conexión (null si no se pudieron decodificar). */
    private final Map<String, ResourceLocation> textures = new HashMap<>();
    private int nextTexture;
    /** script-keys.properties en memoria: se lee al entrar y se guarda después de cargar, nunca dentro de Lua. */
    private final Properties keyChoices = new Properties();
    private boolean keyChoicesChanged;

    ClientScriptRuntime(Logger log, Path keysFile) {
        this.log = log;
        this.keysFile = keysFile;
        this.host = ScriptHost.client(this, LIMITS);
    }

    void install() {
        ClientPlayConnectionEvents.JOIN.register((handler, sender, client) -> client.execute(this::start));
        ClientPlayConnectionEvents.DISCONNECT.register((handler, client) -> client.execute(this::stop));
        ClientTickEvents.END_CLIENT_TICK.register(this::tick);
        HudRenderCallback.EVENT.register((graphics, delta) -> renderHud(graphics));
    }

    private void start() {
        var accepted = SamClientScripts.accepted();
        loadKeyChoices();
        // Las clases del envío se cargan aquí y no dentro de la primera llamada de un script
        new LuaMessage("warm", "up", new byte[] {0}).write(new SamWriter(Unpooled.buffer()));
        ClientPlayNetworking.canSend(SamClientScripts.LUA_MSG);
        host.load(accepted.stream().map(r -> r.script()).toList());
        saveKeyChoices();
        running = !accepted.isEmpty();
        for (var status : host.status()) {
            log.info("Script {} del servidor: {}", status.id(), status.state());
            status.errors().forEach(error -> log.warn("Script {}: {}", status.id(), error));
        }
    }

    private void stop() {
        running = false;
        var minecraft = Minecraft.getInstance();
        if (minecraft.screen instanceof ScriptScreen) {
            minecraft.setScreen(null);
        }
        host.load(List.of());
        waiting.clear();
        keys.clear();
        down.clear();
        textures.values().stream().filter(t -> t != null).forEach(minecraft.getTextureManager()::release);
        textures.clear();
    }

    /** Con una pantalla de SAM abierta los scripts no reciben nada (RS-LUA-08). */
    private static boolean blocked() {
        return Minecraft.getInstance().screen instanceof ProtectedScreen;
    }

    private void tick(Minecraft minecraft) {
        if (!running || blocked()) {
            return;
        }
        while (!waiting.isEmpty()) {
            var message = waiting.poll();
            deliver(message.script(), message.channel(), message.data());
        }
        host.tick();
        // Teclas: solo en el mundo, sin pantalla abierta, al apretarlas (no mientras se mantienen)
        var window = minecraft.getWindow().getWindow();
        for (var entry : keys.entrySet()) {
            var pressed = minecraft.screen == null && InputConstants.isKeyDown(window, entry.getKey());
            if (pressed && !down.getOrDefault(entry.getKey(), false)) {
                host.keyPressed(entry.getValue().script(), entry.getValue().id());
            }
            down.put(entry.getKey(), pressed);
        }
    }

    /** Un {@code sam:lua_msg} del servidor (en el hilo del juego). */
    void receive(LuaMessage message) {
        if (!running) {
            return;
        }
        if (blocked()) {
            if (waiting.size() < MAX_WAITING) {
                waiting.add(new Waiting(message.script(), message.channel(), message.data()));
            } else {
                log.warn("Mensaje del script {} descartado: hay {} esperando a que cierres la pantalla de SAM", message.script(), MAX_WAITING);
            }
            return;
        }
        deliver(message.script(), message.channel(), message.data());
    }

    private void deliver(String script, String channel, byte[] data) {
        try {
            host.deliver(script, Optional.empty(), channel, data);
        } catch (ProtocolException e) {
            log.error("Mensaje mal formado del script {}: {}", script, e.getMessage());
            var connection = Minecraft.getInstance().getConnection();
            if (connection != null) {
                connection.getConnection().disconnect(Component.literal("Error de protocolo. [" + e.code() + "]"));
            }
        }
    }

    /** Un evento de una pantalla de script: se entrega en el próximo paso del juego, nunca en medio del render. */
    void screenEvent(String script, ScreenSpec.Event event) {
        Minecraft.getInstance().tell(() -> {
            if (running) {
                host.screenEvent(script, event);
            }
        });
    }

    // ===== ScriptHost.ClientBridge =====

    @Override
    public void log(String script, String text) {
        log.info("[script {}] {}", script, text);
    }

    @Override
    public void send(String script, String channel, byte[] data) {
        if (ClientPlayNetworking.canSend(SamClientScripts.LUA_MSG)) {
            var buf = Unpooled.buffer();
            new LuaMessage(script, channel, data).write(new SamWriter(buf));
            ClientPlayNetworking.send(new SamPayload(SamClientScripts.LUA_MSG, ByteBufUtil.getBytes(buf)));
        }
    }

    @Override
    public boolean openScreen(String script, ScreenSpec spec) {
        var minecraft = Minecraft.getInstance();
        // Solo en el mundo, sin pantalla o sobre otra de script: nunca sobre una de SAM ni de vanilla (RS-LUA-07)
        if (minecraft.level == null || minecraft.screen != null && !(minecraft.screen instanceof ScriptScreen)) {
            return false;
        }
        // Se abre en el próximo paso: no se cambia de pantalla mientras corre Lua
        minecraft.tell(() -> {
            if (running && (minecraft.screen == null || minecraft.screen instanceof ScriptScreen)) {
                minecraft.setScreen(new ScriptScreen(this, script, spec));
            }
        });
        return true;
    }

    @Override
    public boolean closeScreen(String script) {
        var minecraft = Minecraft.getInstance();
        if (minecraft.screen instanceof ScriptScreen screen && screen.script().equals(script)) {
            minecraft.tell(() -> {
                if (minecraft.screen instanceof ScriptScreen current && current.script().equals(script)) {
                    minecraft.setScreen(null);
                }
            });
            return true;
        }
        return false;
    }

    @Override
    public boolean bindKey(String script, String id, String key) {
        var name = keyName(script, id, key);
        if (name.equals("none")) {
            return false;
        }
        var code = glfw(name);
        if (code < 0) {
            log.warn("Tecla \"{}\" inválida para {}.{} en {}", name, script, id, keysFile);
            return false;
        }
        var input = InputConstants.Type.KEYSYM.getOrCreate(code);
        for (var mapping : Minecraft.getInstance().options.keyMappings) {
            if (KeyBindingHelper.getBoundKeyOf(mapping).equals(input)) {
                log.info("El script {} pidió la tecla {} para \"{}\", pero ya la usa {}: no se asigna", script, name, id, mapping.getName());
                return false;
            }
        }
        if (keys.containsKey(code)) {
            log.info("El script {} pidió la tecla {}, pero ya la tiene otro script: no se asigna", script, name);
            return false;
        }
        keys.put(code, new Bound(script, id));
        return true;
    }

    /** La tecla que eligió el jugador en script-keys.properties; la primera vez se agrega la del script. */
    private String keyName(String script, String id, String fallback) {
        var server = SamClientNet.lastVerified().map(s -> s.hex().substring(0, 16)).orElse("local");
        var entry = server + "." + script + "." + id;
        var chosen = keyChoices.getProperty(entry);
        if (chosen != null) {
            return chosen.strip().toLowerCase(java.util.Locale.ROOT);
        }
        keyChoices.setProperty(entry, fallback);
        keyChoicesChanged = true;
        return fallback;
    }

    private void loadKeyChoices() {
        keyChoices.clear();
        keyChoicesChanged = false;
        if (Files.exists(keysFile)) {
            try (var in = Files.newBufferedReader(keysFile)) {
                keyChoices.load(in);
            } catch (IOException e) {
                log.warn("No se pudo leer {}: {}", keysFile, e.getMessage());
            }
        }
    }

    private void saveKeyChoices() {
        if (!keyChoicesChanged) {
            return;
        }
        try {
            Files.createDirectories(keysFile.getParent());
            try (var out = Files.newBufferedWriter(keysFile)) {
                keyChoices.store(out, "Teclas de los scripts de servidor: <servidor>.<script>.<id>=<tecla> (a-z, 0-9, f1-f12 o none)");
            }
        } catch (IOException e) {
            log.warn("No se pudo guardar {}: {}", keysFile, e.getMessage());
        }
    }

    /** {@code a}..{@code z}, {@code 0}..{@code 9} o {@code f1}..{@code f12}; -1 si no es ninguna. */
    static int glfw(String name) {
        if (name.length() == 1 && name.charAt(0) >= 'a' && name.charAt(0) <= 'z') {
            return GLFW.GLFW_KEY_A + (name.charAt(0) - 'a');
        }
        if (name.length() == 1 && name.charAt(0) >= '0' && name.charAt(0) <= '9') {
            return GLFW.GLFW_KEY_0 + (name.charAt(0) - '0');
        }
        if (name.matches("f([1-9]|1[0-2])")) {
            return GLFW.GLFW_KEY_F1 + Integer.parseInt(name.substring(1)) - 1;
        }
        return -1;
    }

    // ===== Dibujo =====

    /** Una imagen de un script, subida a la GPU la primera vez (RN-29: la decodifica NativeImage de vanilla). */
    void drawImage(GuiGraphics graphics, String script, String path, byte[] png, int x, int y, int w, int h) {
        var key = script + "/" + path;
        if (!textures.containsKey(key)) {
            ResourceLocation location = null;
            try {
                var image = NativeImage.read(png);
                location = ResourceLocation.fromNamespaceAndPath("sam", "script_image/" + nextTexture++);
                Minecraft.getInstance().getTextureManager().register(location, new DynamicTexture(image));
            } catch (IOException | RuntimeException e) {
                log.warn("La imagen {} del script {} no se pudo decodificar: {}", path, script, e.getMessage());
            }
            textures.put(key, location);
        }
        var location = textures.get(key);
        if (location != null) {
            graphics.blit(location, x, y, 0, 0, w, h, w, h);
        }
    }

    private void renderHud(GuiGraphics graphics) {
        var minecraft = Minecraft.getInstance();
        if (!running || minecraft.screen != null || minecraft.options.hideGui) {
            return;
        }
        var font = minecraft.font;
        var width = graphics.guiWidth();
        var height = graphics.guiHeight();
        for (var text : host.hud()) {
            var x = anchorX(text.anchor(), width, font.width(text.text()));
            var y = anchorY(text.anchor(), height, font.lineHeight);
            graphics.drawString(font, text.text(), x + text.x(), y + text.y(), 0xFF000000 | text.color());
        }
        for (var image : host.hudImages()) {
            var x = anchorX(image.anchor(), width, image.w());
            var y = anchorY(image.anchor(), height, image.h());
            drawImage(graphics, image.script(), image.path(), image.png(), x + image.x(), y + image.y(), image.w(), image.h());
        }
    }

    private static int anchorX(ScriptHost.Anchor anchor, int width, int size) {
        return switch (anchor) {
            case TOP_LEFT, LEFT, BOTTOM_LEFT -> 2;
            case TOP, CENTER, BOTTOM -> (width - size) / 2;
            case TOP_RIGHT, RIGHT, BOTTOM_RIGHT -> width - size - 2;
        };
    }

    private static int anchorY(ScriptHost.Anchor anchor, int height, int size) {
        return switch (anchor) {
            case TOP_LEFT, TOP, TOP_RIGHT -> 2;
            case LEFT, CENTER, RIGHT -> (height - size) / 2;
            case BOTTOM_LEFT, BOTTOM, BOTTOM_RIGHT -> height - size - 2;
        };
    }
}
