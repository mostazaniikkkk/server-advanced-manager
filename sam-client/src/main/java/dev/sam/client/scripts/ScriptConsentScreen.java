package dev.sam.client.scripts;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import dev.sam.client.SamClient;
import dev.sam.common.scripts.ClientDelivery;
import dev.sam.common.scripts.ScriptCatalog;
import net.fabricmc.fabric.api.networking.v1.PacketSender;
import net.fabricmc.loader.api.FabricLoader;
import net.minecraft.client.Screenshot;
import net.minecraft.client.gui.GuiGraphics;
import net.minecraft.client.gui.components.Button;
import net.minecraft.client.gui.components.Checkbox;
import net.minecraft.client.gui.screens.Screen;
import net.minecraft.network.Connection;
import net.minecraft.network.chat.Component;

/**
 * La pantalla de consentimiento de scripts (RS-LUA-05, protegida por RS-LUA-07): qué scripts quiere correr
 * el servidor en este cliente, quién los firmó y qué pueden hacer. El jugador elige cuáles acepta.
 */
final class ScriptConsentScreen extends Screen implements dev.sam.client.ProtectedScreen {

    private static final int PANEL_WIDTH = 320;
    private static final int ROW = 30;
    private static final int WHITE = 0xFFFFFF;
    private static final int GRAY = 0xA0A0A0;
    private static final int DARK_GRAY = 0x707070;
    private static final int RED = 0xFF5555;
    private static final int YELLOW = 0xFFDD55;
    private static final int SAM_BLUE = 0xFF3C7DD9;

    /** Lo que se le explica al jugador de cada capacidad (las desconocidas se muestran tal cual). */
    private static final Map<String, String> CAPABILITIES = Map.of(
        "hud", "dibujar en tu pantalla (HUD)",
        "screens", "abrir ventanas propias",
        "keybinds", "registrar teclas",
        "messages", "hablar con su parte del servidor");

    private final List<ClientDelivery.Ready> ready;
    private final List<ScriptCatalog.Rejected> failed;
    private final PacketSender sender;
    private final Connection connection;
    private final Set<String> chosen = new LinkedHashSet<>();
    private int first;
    private int visibleRows;
    private int panelTop;
    private int panelHeight;
    private int listTop;
    private boolean answered;
    private int ticks;

    ScriptConsentScreen(List<ClientDelivery.Ready> ready, List<ScriptCatalog.Rejected> failed, PacketSender sender, Connection connection) {
        super(Component.literal("Scripts del servidor"));
        this.ready = ready;
        this.failed = failed;
        this.sender = sender;
        this.connection = connection;
        ready.forEach(r -> chosen.add(id(r)));
    }

    private static String id(ClientDelivery.Ready r) {
        return r.script().manifest().id();
    }

    private int rows() {
        return ready.size() + failed.size();
    }

    @Override
    protected void init() {
        visibleRows = Math.max(1, Math.min(rows(), (height - 120) / ROW));
        panelHeight = 58 + visibleRows * ROW + 30;
        panelTop = Math.max(4, (height - panelHeight) / 2);
        listTop = panelTop + 50;
        var left = (width - PANEL_WIDTH) / 2 + 10;
        first = Math.max(0, Math.min(first, rows() - visibleRows));
        for (var i = first; i < Math.min(ready.size(), first + visibleRows); i++) {
            var script = ready.get(i);
            var y = listTop + (i - first) * ROW;
            addRenderableWidget(Checkbox.builder(Component.literal(id(script) + " " + script.script().manifest().version()), font)
                .pos(left, y).selected(chosen.contains(id(script)))
                .onValueChange((box, value) -> {
                    if (value) {
                        chosen.add(id(script));
                    } else {
                        chosen.remove(id(script));
                    }
                }).build());
        }
        var buttonsY = panelTop + panelHeight - 26;
        var third = (PANEL_WIDTH - 28) / 3;
        addRenderableWidget(Button.builder(Component.literal("Aceptar elegidos"), b -> answer(selected()))
            .bounds(left, buttonsY, third, 20).build());
        addRenderableWidget(Button.builder(Component.literal("Rechazar todos"), b -> answer(List.of()))
            .bounds(left + third + 4, buttonsY, third, 20).build());
        addRenderableWidget(Button.builder(Component.literal("Salir"), b -> sender.disconnect(Component.literal("Saliste en el consentimiento de scripts")))
            .bounds(left + 2 * (third + 4), buttonsY, third, 20).build());
    }

    private List<ClientDelivery.Ready> selected() {
        return ready.stream().filter(r -> chosen.contains(id(r))).toList();
    }

    private void answer(List<ClientDelivery.Ready> accepted) {
        if (answered) {
            return;
        }
        answered = true;
        SamClientScripts.consent(sender, accepted);
        clearWidgets();
    }

    @Override
    public boolean mouseScrolled(double mouseX, double mouseY, double horizontal, double vertical) {
        var before = first;
        first = Math.max(0, Math.min(rows() - visibleRows, first - (int) Math.signum(vertical)));
        if (first != before && !answered) {
            rebuildWidgets();
        }
        return true;
    }

    @Override
    public boolean shouldCloseOnEsc() {
        return false;
    }

    @Override
    public void renderBackground(GuiGraphics graphics, int mouseX, int mouseY, float delta) {
        super.renderBackground(graphics, mouseX, mouseY, delta);
        var left = (width - PANEL_WIDTH) / 2;
        graphics.fill(left, panelTop, left + PANEL_WIDTH, panelTop + panelHeight, 0xD0101014);
        graphics.renderOutline(left, panelTop, PANEL_WIDTH, panelHeight, 0xFF4A4A55);
    }

    @Override
    public void render(GuiGraphics graphics, int mouseX, int mouseY, float delta) {
        super.render(graphics, mouseX, mouseY, delta);
        var center = width / 2;
        var left = (width - PANEL_WIDTH) / 2 + 10;
        // Marca de SAM: una pantalla de un script no la puede dibujar (RS-LUA-07)
        var right = (width + PANEL_WIDTH) / 2;
        graphics.fill(right - 34, panelTop + 4, right - 4, panelTop + 14, SAM_BLUE);
        graphics.drawCenteredString(font, "SAM", right - 19, panelTop + 5, WHITE);
        graphics.drawCenteredString(font, title, center, panelTop + 8, WHITE);
        if (answered) {
            graphics.drawCenteredString(font, "Respuesta enviada. Entrando al mundo…", center, panelTop + 24, GRAY);
            return;
        }
        graphics.drawCenteredString(font, "Este servidor quiere ejecutar scripts en tu juego.", center, panelTop + 22, GRAY);
        graphics.drawCenteredString(font, "Solo corren mientras estés conectado aquí.", center, panelTop + 33, DARK_GRAY);
        for (var i = first; i < Math.min(rows(), first + visibleRows); i++) {
            var y = listTop + (i - first) * ROW;
            if (i < ready.size()) {
                var script = ready.get(i);
                var manifest = script.script().manifest();
                // A la derecha, dentro del panel: requerido y quién lo firmó
                var tag = (manifest.required() ? "requerido · " : "") + "firmado por " + script.signer();
                var labelEnd = left + 24 + font.width(id(script) + " " + manifest.version());
                tag = font.plainSubstrByWidth(tag, left + PANEL_WIDTH - 20 - labelEnd - 8);
                graphics.drawString(font, tag, left + PANEL_WIDTH - 20 - font.width(tag), y + 6,
                    manifest.required() ? YELLOW : DARK_GRAY);
                var caps = manifest.capabilities().isEmpty() ? "sin permisos especiales"
                    : "Puede: " + String.join(", ", manifest.capabilities().stream().map(c -> CAPABILITIES.getOrDefault(c, c)).toList());
                graphics.drawString(font, font.plainSubstrByWidth(caps, PANEL_WIDTH - 44), left + 24, y + 19, GRAY);
            } else {
                var rejected = failed.get(i - ready.size());
                graphics.drawString(font, "✖ " + rejected.id() + ": no pasó la verificación", left, y + 4, RED);
                graphics.drawString(font, font.plainSubstrByWidth(rejected.reason(), PANEL_WIDTH - 44), left + 12, y + 16, DARK_GRAY);
            }
        }
        if (rows() > visibleRows) {
            graphics.drawCenteredString(font, (first + 1) + "–" + (first + visibleRows) + " de " + rows() + " (rueda para ver más)",
                center, listTop + visibleRows * ROW - 4, DARK_GRAY);
        }
    }

    @Override
    public void tick() {
        super.tick();
        // Lo mismo que hace la ConnectScreen con la conexión mientras está abierta
        if (connection.isConnected()) {
            connection.tick();
        } else {
            connection.handleDisconnection();
        }
        ticks++;
        if (!FabricLoader.getInstance().isDevelopmentEnvironment()) {
            return;
        }
        // Prueba de punta a punta: -Dsam.dev.scriptsScreenshot=nombre captura a los 30 ticks y
        // -Dsam.dev.scriptsConsent=all|none responde a los 40
        var name = System.getProperty("sam.dev.scriptsScreenshot");
        if (name != null && ticks == 30) {
            Screenshot.grab(minecraft.gameDirectory, name + ".png", minecraft.getMainRenderTarget(),
                message -> SamClient.LOGGER.info("[dev] Captura: {}", message.getString()));
        }
        var auto = System.getProperty("sam.dev.scriptsConsent");
        if (auto != null && ticks == 40) {
            answer(auto.equals("all") ? new ArrayList<>(ready) : List.of());
        }
    }
}
