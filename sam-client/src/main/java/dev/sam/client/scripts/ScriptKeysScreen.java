package dev.sam.client.scripts;

import java.util.List;
import java.util.Locale;

import org.lwjgl.glfw.GLFW;

import dev.sam.client.ProtectedScreen;
import dev.sam.common.lua.ScriptKeys;
import net.minecraft.client.gui.GuiGraphics;
import net.minecraft.client.gui.components.Button;
import net.minecraft.client.gui.screens.Screen;
import net.minecraft.network.chat.Component;

/**
 * "Teclas de scripts" (RF-LUA-06e, PROTOCOLO.md 8.3): las teclas de los scripts de este servidor y la que
 * eligió el jugador para cada una. Es una pantalla de SAM: ningún script la ve ni la abre (RS-LUA-07/08).
 */
final class ScriptKeysScreen extends Screen implements ProtectedScreen {

    private static final int WIDTH = 300;
    private static final int ROW = 24;
    private static final int WHITE = 0xFFFFFF;
    private static final int GRAY = 0xA0A0A0;
    private static final int RED = 0xFF5555;
    private static final int GREEN = 0x55FF55;
    private static final int SAM_BLUE = 0xFF3C7DD9;

    private final Screen parent;
    private final ClientScriptRuntime runtime;
    private List<ScriptKeys.Choice> choices = List.of();
    /** La fila que espera una tecla, o -1. */
    private int listening = -1;
    private Component status = Component.empty();
    private int statusColor = GRAY;
    private int top;

    ScriptKeysScreen(Screen parent, ClientScriptRuntime runtime) {
        super(Component.literal("Teclas de scripts"));
        this.parent = parent;
        this.runtime = runtime;
    }

    @Override
    protected void init() {
        choices = runtime.keyChoices();
        var rows = Math.min(choices.size(), (height - 90) / ROW);
        top = Math.max(30, (height - (rows * ROW + 60)) / 2);
        var left = (width - WIDTH) / 2;
        for (var i = 0; i < rows; i++) {
            var row = i;
            var choice = choices.get(i);
            var label = listening == i ? "> ? <" : choice.key().toUpperCase(Locale.ROOT).replace("NONE", "Ninguna");
            addRenderableWidget(Button.builder(Component.literal(label), b -> listen(row))
                .bounds(left + WIDTH - 90, top + i * ROW, 90, 20).build());
        }
        addRenderableWidget(Button.builder(Component.literal("Listo"), b -> onClose())
            .bounds((width - 100) / 2, top + rows * ROW + 26, 100, 20).build());
    }

    private void listen(int row) {
        listening = row;
        status = Component.literal("Aprieta la tecla nueva (Supr: ninguna, Esc: cancelar)");
        statusColor = GRAY;
        rebuildWidgets();
    }

    @Override
    public boolean keyPressed(int key, int scanCode, int modifiers) {
        if (listening < 0) {
            return super.keyPressed(key, scanCode, modifiers);
        }
        var choice = choices.get(listening);
        if (key == GLFW.GLFW_KEY_ESCAPE) {
            status = Component.empty();
        } else {
            var name = key == GLFW.GLFW_KEY_DELETE || key == GLFW.GLFW_KEY_BACKSPACE ? java.util.Optional.of(ScriptKeys.NONE)
                : ClientScriptRuntime.name(key);
            if (name.isEmpty()) {
                status = Component.literal("Esa tecla no se puede usar: a-z, 0-9 o F1-F12");
                statusColor = RED;
                return true;
            }
            var problem = runtime.rebind(choice.script(), choice.id(), name.get());
            status = Component.literal(problem.map(p -> "No se cambió: " + p).orElse("Listo: " + choice.id() + " → "
                + name.get().toUpperCase(Locale.ROOT).replace("NONE", "ninguna")));
            statusColor = problem.isPresent() ? RED : GREEN;
        }
        listening = -1;
        rebuildWidgets();
        return true;
    }

    /** Solo para la prueba de punta a punta: como si el jugador eligiera la primera fila y apretara esa tecla. */
    void devRebindFirst(int key) {
        listen(0);
        keyPressed(key, 0, 0);
    }

    @Override
    public void onClose() {
        minecraft.setScreen(parent);
    }

    @Override
    public void renderBackground(GuiGraphics graphics, int mouseX, int mouseY, float delta) {
        super.renderBackground(graphics, mouseX, mouseY, delta);
        var left = (width - WIDTH) / 2;
        var rows = Math.max(1, Math.min(choices.size(), (height - 90) / ROW));
        graphics.fill(left - 8, top - 32, left + WIDTH + 8, top + rows * ROW + 54, 0xD0101014);
        graphics.renderOutline(left - 8, top - 32, WIDTH + 16, rows * ROW + 86, 0xFF4A4A55);
    }

    @Override
    public void render(GuiGraphics graphics, int mouseX, int mouseY, float delta) {
        super.render(graphics, mouseX, mouseY, delta);
        var left = (width - WIDTH) / 2;
        // Marca de SAM: una pantalla de un script no la puede dibujar (RS-LUA-07)
        graphics.fill(left + WIDTH - 30, top - 26, left + WIDTH, top - 16, SAM_BLUE);
        graphics.drawCenteredString(font, "SAM", left + WIDTH - 15, top - 25, WHITE);
        graphics.drawCenteredString(font, title, width / 2, top - 24, WHITE);
        if (choices.isEmpty()) {
            graphics.drawCenteredString(font, "Los scripts de este servidor no usan teclas.", width / 2, top, GRAY);
        }
        var rows = Math.min(choices.size(), (height - 90) / ROW);
        for (var i = 0; i < rows; i++) {
            var choice = choices.get(i);
            graphics.drawString(font, choice.script() + " · " + choice.id(), left, top + i * ROW + 6, WHITE);
        }
        graphics.drawCenteredString(font, status, width / 2, top + rows * ROW + 8, statusColor);
    }
}
