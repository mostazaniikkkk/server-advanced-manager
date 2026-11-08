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
    private final MediaClient media;
    private boolean running;
    private final ArrayDeque<Waiting> waiting = new ArrayDeque<>();
    /** Código GLFW → tecla de script, y si estaba apretada en el tick anterior. */
    private final Map<Integer, Bound> keys = new LinkedHashMap<>();
    private final Map<Integer, Boolean> down = new HashMap<>();
    /** Las imágenes ya subidas a la GPU en esta conexión (null si no se pudieron decodificar). */
    private final Map<String, ResourceLocation> textures = new HashMap<>();
    private int nextTexture;
    /** script-keys.properties en memoria: se lee al entrar y se guarda después de cargar, nunca dentro de Lua. */
    private dev.sam.common.lua.ScriptKeys keyChoices = dev.sam.common.lua.ScriptKeys.parse("");

    ClientScriptRuntime(Logger log, Path keysFile) {
        this.log = log;
        this.keysFile = keysFile;
        this.host = ScriptHost.client(this, LIMITS);
        this.media = new MediaClient(log, (script, request, id, error) -> {
            if (running) {
                host.mediaResult(script, request, id, error);
            }
        });
    }

    void install() {
        media.install();
        ClientPlayConnectionEvents.JOIN.register((handler, sender, client) -> client.execute(this::start));
        ClientPlayConnectionEvents.DISCONNECT.register((handler, client) -> client.execute(this::stop));
        ClientTickEvents.END_CLIENT_TICK.register(this::tick);
        HudRenderCallback.EVENT.register((graphics, delta) -> renderHud(graphics));
        // Las entradas de los plugins en el botón de Opciones de cuenta (capacidad menu). Elegir una cierra el
        // inventario y avisa al script en el próximo paso: así puede abrir su pantalla (no se abre sobre otra)
        dev.sam.client.account.AccountMenu.plugins(() -> !running || blocked() ? java.util.List.of() : host.menuEntries().stream()
            .map(entry -> new dev.sam.client.account.AccountMenu.Item(entry.label(), () -> {
                var minecraft = Minecraft.getInstance();
                minecraft.setScreen(null);
                minecraft.tell(() -> {
                    if (running) {
                        host.menuClicked(entry.script(), entry.id());
                    }
                });
            }, entry.icon().<dev.sam.client.account.AccountMenu.IconDrawer>map(png -> (graphics, x, y) ->
                drawImage(graphics, entry.script(), "menu:" + entry.id(), png, x, y, 12, 12)).orElse(null))).toList());
        // Menú de pausa → "Teclas de scripts", si los scripts de este servidor usan teclas
        net.fabricmc.fabric.api.client.screen.v1.ScreenEvents.AFTER_INIT.register((client, screen, width, height) -> {
            if (screen instanceof net.minecraft.client.gui.screens.PauseScreen && !keyChoices().isEmpty()) {
                net.fabricmc.fabric.api.client.screen.v1.Screens.getButtons(screen).add(
                    net.minecraft.client.gui.components.Button.builder(Component.literal("Teclas de scripts"),
                        b -> client.setScreen(new ScriptKeysScreen(screen, this))).bounds(4, height - 24, 110, 20).build());
            }
        });
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
        devKeysScreen();
        for (var status : host.status()) {
            log.info("Script {} del servidor: {}", status.id(), status.state());
            status.errors().forEach(error -> log.warn("Script {}: {}", status.id(), error));
        }
    }

    /**
     * Solo en desarrollo, {@code -Dsam.dev.keysScreen=nombre}: a los 3 s abre el menú de pausa (captura
     * {@code nombre-pausa}), después "Teclas de scripts", cambia la primera tecla a J como si el jugador la
     * apretara (captura {@code nombre}) y a los 2 s vuelve al juego.
     */
    private void devKeysScreen() {
        var name = System.getProperty("sam.dev.keysScreen");
        if (!net.fabricmc.loader.api.FabricLoader.getInstance().isDevelopmentEnvironment() || name == null) {
            return;
        }
        var minecraft = Minecraft.getInstance();
        var thread = new Thread(() -> {
            try {
                Thread.sleep(3000);
                minecraft.execute(() -> minecraft.setScreen(new net.minecraft.client.gui.screens.PauseScreen(true)));
                Thread.sleep(500);
                minecraft.execute(() -> net.minecraft.client.Screenshot.grab(minecraft.gameDirectory, name + "-pausa.png",
                    minecraft.getMainRenderTarget(), m -> log.info("[dev] Captura: {}", m.getString())));
                Thread.sleep(300);
                minecraft.execute(() -> {
                    log.info("[dev] Abre Teclas de scripts");
                    var screen = new ScriptKeysScreen(minecraft.screen, this);
                    minecraft.setScreen(screen);
                    screen.devRebindFirst(GLFW.GLFW_KEY_J);
                });
                Thread.sleep(2000);
                minecraft.execute(() -> net.minecraft.client.Screenshot.grab(minecraft.gameDirectory, name + ".png",
                    minecraft.getMainRenderTarget(), m -> log.info("[dev] Captura: {}", m.getString())));
                Thread.sleep(300);
                minecraft.execute(() -> {
                    log.info("[dev] Cierra Teclas de scripts");
                    minecraft.setScreen(null);
                });
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }, "SAM dev keys");
        thread.setDaemon(true);
        thread.start();
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
        media.clear();
    }

    /** Con una pantalla de SAM abierta los scripts no reciben nada (RS-LUA-08). */
    private static boolean blocked() {
        return Minecraft.getInstance().screen instanceof ProtectedScreen;
    }

    private void tick(Minecraft minecraft) {
        media.tick();
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
    public Optional<ScriptHost.GameState> game() {
        var minecraft = Minecraft.getInstance();
        var player = minecraft.player;
        var connection = minecraft.getConnection();
        if (player == null || minecraft.level == null || connection == null) {
            return Optional.empty();
        }
        var inventory = player.getInventory();
        var hotbar = new java.util.ArrayList<ScriptHost.Item>();
        for (var slot = 0; slot < 9; slot++) {
            var stack = inventory.getItem(slot);
            hotbar.add(new ScriptHost.Item(net.minecraft.core.registries.BuiltInRegistries.ITEM.getKey(stack.getItem()).toString(),
                stack.getCount()));
        }
        var players = connection.getOnlinePlayers().stream().map(info -> info.getProfile().getName()).sorted().toList();
        var window = minecraft.getWindow();
        return Optional.of(new ScriptHost.GameState(player.getGameProfile().getName(), player.getHealth(), player.getMaxHealth(),
            player.getFoodData().getFoodLevel(), player.getX(), player.getY(), player.getZ(),
            minecraft.level.dimension().location().toString(), hotbar, inventory.selected + 1, players, (int) window.getGuiScale(),
            window.getGuiScaledWidth(), window.getGuiScaledHeight()));
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
    public boolean requestMedia(String script, int request, String source) {
        var minecraft = Minecraft.getInstance();
        // Como una pantalla de script: en el mundo, sin pantalla o sobre la del script; nunca sobre una de SAM
        if (minecraft.level == null || minecraft.screen != null && !(minecraft.screen instanceof ScriptScreen)) {
            return false;
        }
        minecraft.tell(() -> {
            if (source.equals("capture")) {
                media.capture(script, request);
            } else {
                media.pick(script, request);
            }
        });
        return true;
    }

    @Override
    public boolean fetchMedia(String script, int request, String id) {
        if (Minecraft.getInstance().level == null) {
            return false;
        }
        Minecraft.getInstance().tell(() -> media.fetch(script, request, id));
        return true;
    }

    /** Dibuja una imagen de un jugador si ya está; si no, un recuadro. */
    void drawMedia(GuiGraphics graphics, String id, int x, int y, int w, int h) {
        var png = media.cached(id);
        if (png.isPresent()) {
            drawImage(graphics, "media", id, png.get(), x, y, w, h);
        } else {
            graphics.fill(x, y, x + w, y + h, 0xFF202028);
            graphics.renderOutline(x, y, w, h, 0xFF4A4A55);
            graphics.drawCenteredString(Minecraft.getInstance().font, "🖼", x + w / 2, y + h / 2 - 4, 0xFFA0A0A0);
        }
    }

    @Override
    public boolean openUrl(String script, String url) {
        var minecraft = Minecraft.getInstance();
        // Igual que una pantalla de script: en el mundo, sin pantalla o sobre la de un script; nunca sobre una de SAM
        if (minecraft.level == null || minecraft.screen != null && !(minecraft.screen instanceof ScriptScreen)) {
            return false;
        }
        minecraft.tell(() -> {
            var previous = minecraft.screen;
            if (previous instanceof ScriptScreen own) {
                // Vuelve a ella después: para el script su pantalla no se cerró
                own.coveredByChild();
            }
            log.info("El script {} pide abrir {}", script, url);
            minecraft.setScreen(new net.minecraft.client.gui.screens.ConfirmLinkScreen(accepted -> {
                if (accepted) {
                    net.minecraft.Util.getPlatform().openUri(url);
                }
                minecraft.setScreen(previous);
            }, url, true));
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
        var name = keyChoices.choose(server(), script, id, key);
        if (name.equals(dev.sam.common.lua.ScriptKeys.NONE)) {
            return false;
        }
        var problem = conflict(name);
        if (problem.isPresent()) {
            log.info("El script {} pidió la tecla {} para \"{}\", pero {}: no se asigna", script, name, id, problem.get());
            return false;
        }
        keys.put(glfw(name), new Bound(script, id));
        return true;
    }

    private static String server() {
        return SamClientNet.lastVerified().map(s -> s.hex().substring(0, 16)).orElse("local");
    }

    private void loadKeyChoices() {
        var text = "";
        if (Files.exists(keysFile)) {
            try {
                text = Files.readString(keysFile);
            } catch (IOException e) {
                log.warn("No se pudo leer {}: {}", keysFile, e.getMessage());
            }
        }
        keyChoices = dev.sam.common.lua.ScriptKeys.parse(text);
    }

    private void saveKeyChoices() {
        if (!keyChoices.dirty()) {
            return;
        }
        try {
            Files.createDirectories(keysFile.getParent());
            Files.writeString(keysFile, keyChoices.text());
            keyChoices.saved();
        } catch (IOException e) {
            log.warn("No se pudo guardar {}: {}", keysFile, e.getMessage());
        }
    }

    /** Las teclas de los scripts de este servidor, para la pantalla "Teclas de scripts". */
    List<dev.sam.common.lua.ScriptKeys.Choice> keyChoices() {
        return running ? keyChoices.of(server()) : List.of();
    }

    /**
     * El jugador eligió otra tecla (o {@code none}) desde la pantalla "Teclas de scripts": vale en el acto.
     *
     * @return el motivo si no se puede usar
     */
    Optional<String> rebind(String script, String id, String key) {
        keys.values().removeIf(bound -> bound.script().equals(script) && bound.id().equals(id));
        if (!key.equals(dev.sam.common.lua.ScriptKeys.NONE)) {
            var problem = conflict(key);
            if (problem.isPresent()) {
                // Vuelve a la que tenía
                var previous = keyChoices.choose(server(), script, id, key);
                if (!previous.equals(dev.sam.common.lua.ScriptKeys.NONE) && conflict(previous).isEmpty()) {
                    keys.put(glfw(previous), new Bound(script, id));
                }
                return problem;
            }
            keys.put(glfw(key), new Bound(script, id));
        }
        keyChoices.set(server(), script, id, key);
        saveKeyChoices();
        return Optional.empty();
    }

    /** Si la tecla ya la usa una acción del juego, de otro mod o de otro script. */
    private Optional<String> conflict(String name) {
        var code = glfw(name);
        var input = InputConstants.Type.KEYSYM.getOrCreate(code);
        for (var mapping : Minecraft.getInstance().options.keyMappings) {
            if (KeyBindingHelper.getBoundKeyOf(mapping).equals(input)) {
                return Optional.of("ya la usa «" + Component.translatable(mapping.getName()).getString() + "»");
            }
        }
        var other = keys.get(code);
        if (other != null) {
            return Optional.of("ya la usa el script " + other.script() + " (" + other.id() + ")");
        }
        return Optional.empty();
    }

    /** El nombre de una tecla de GLFW si un script la puede usar; vacío si no. */
    static Optional<String> name(int code) {
        if (code >= GLFW.GLFW_KEY_A && code <= GLFW.GLFW_KEY_Z) {
            return Optional.of(String.valueOf((char) ('a' + code - GLFW.GLFW_KEY_A)));
        }
        if (code >= GLFW.GLFW_KEY_0 && code <= GLFW.GLFW_KEY_9) {
            return Optional.of(String.valueOf((char) ('0' + code - GLFW.GLFW_KEY_0)));
        }
        if (code >= GLFW.GLFW_KEY_F1 && code <= GLFW.GLFW_KEY_F12) {
            return Optional.of("f" + (code - GLFW.GLFW_KEY_F1 + 1));
        }
        return Optional.empty();
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
                // Por InputStream (memoria del heap): read(byte[]) copia al MemoryStack de LWJGL, de 64 KB, y una
                // imagen más grande tumba el juego con "Out of stack space"
                var image = NativeImage.read(new java.io.ByteArrayInputStream(png));
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
