package dev.sam.client.scripts;

import dev.sam.common.lua.ScreenSpec;
import net.minecraft.client.gui.GuiGraphics;
import net.minecraft.client.gui.components.Button;
import net.minecraft.client.gui.components.Checkbox;
import net.minecraft.client.gui.components.EditBox;
import net.minecraft.client.gui.screens.Screen;
import net.minecraft.network.chat.Component;

/**
 * Una pantalla declarada por un script (RF-LUA-06b): solo los widgets de su {@link ScreenSpec}; sus eventos
 * vuelven al script fuera del render. Lleva la marca "Interfaz del servidor" (RS-LUA-09), que se dibuja
 * después de todo lo del script y fuera de su panel: el script no la puede quitar ni tapar.
 */
final class ScriptScreen extends Screen {

    static final String MARK = "Interfaz del servidor";
    private static final int WHITE = 0xFFFFFF;

    private final ClientScriptRuntime runtime;
    private final String script;
    private final ScreenSpec spec;
    private int left;
    private int top;
    private boolean closedSent;
    /** Otra pantalla la tapa un momento (la confirmación de un link) y después vuelve: no es un cierre. */
    private boolean covered;

    ScriptScreen(ClientScriptRuntime runtime, String script, ScreenSpec spec) {
        super(Component.literal(spec.title()));
        this.runtime = runtime;
        this.script = script;
        this.spec = spec;
    }

    String script() {
        return script;
    }

    void coveredByChild() {
        covered = true;
    }

    @Override
    protected void init() {
        covered = false;
        left = (width - spec.width()) / 2;
        top = Math.max(16, (height - spec.height()) / 2);
        for (var widget : spec.widgets()) {
            switch (widget) {
                case ScreenSpec.Button b -> addRenderableWidget(Button.builder(Component.literal(b.text()),
                    pressed -> runtime.screenEvent(script, ScreenSpec.Event.click(b.id()))).bounds(left + b.x(), top + b.y(), b.w(), b.h()).build());
                case ScreenSpec.TextField f -> {
                    var box = new EditBox(font, left + f.x(), top + f.y(), f.w(), 20, Component.literal(f.id()));
                    box.setMaxLength(f.max());
                    box.setValue(f.value());
                    box.setResponder(value -> runtime.screenEvent(script, ScreenSpec.Event.change(f.id(), value)));
                    addRenderableWidget(box);
                }
                case ScreenSpec.Checkbox c -> addRenderableWidget(Checkbox.builder(Component.literal(c.text()), font)
                    .pos(left + c.x(), top + c.y()).selected(c.checked())
                    .onValueChange((box, value) -> runtime.screenEvent(script, ScreenSpec.Event.change(c.id(), value))).build());
                case ScreenSpec.Label l -> {
                    // Se dibuja en render
                }
                case ScreenSpec.Image i -> {
                    // Se dibuja en render
                }
                case ScreenSpec.Media m -> {
                    // Se dibuja en render cuando se descargó
                }
            }
        }
    }

    @Override
    public void renderBackground(GuiGraphics graphics, int mouseX, int mouseY, float delta) {
        super.renderBackground(graphics, mouseX, mouseY, delta);
        graphics.fill(left - 4, top - 16, left + spec.width() + 4, top + spec.height() + 4, 0xD0101014);
        graphics.renderOutline(left - 4, top - 16, spec.width() + 8, spec.height() + 20, 0xFF4A4A55);
    }

    @Override
    public void render(GuiGraphics graphics, int mouseX, int mouseY, float delta) {
        super.render(graphics, mouseX, mouseY, delta);
        graphics.drawCenteredString(font, title, left + spec.width() / 2, top - 12, WHITE);
        for (var widget : spec.widgets()) {
            if (widget instanceof ScreenSpec.Label l) {
                graphics.drawString(font, l.text(), left + l.x(), top + l.y(), 0xFF000000 | l.color());
            } else if (widget instanceof ScreenSpec.Image i) {
                runtime.drawImage(graphics, script, i.path(), i.png(), left + i.x(), top + i.y(), i.w(), i.h());
            } else if (widget instanceof ScreenSpec.Media m) {
                runtime.drawMedia(graphics, m.id(), left + m.x(), top + m.y(), m.w(), m.h());
            }
        }
        // La marca va al final y debajo del panel: nada del script la tapa (RS-LUA-09)
        var markWidth = font.width(MARK) + 6;
        var markX = Math.max(0, Math.min(left + spec.width() + 4, width) - markWidth);
        // Siempre dentro de la ventana, aunque el panel del script no entre (RS-LUA-09): se dibuja al final, encima
        var markY = Math.min(top + spec.height() + 6, height - 12);
        graphics.fill(markX, markY, markX + markWidth, markY + 11, 0xF0000000);
        graphics.drawString(font, MARK, markX + 3, markY + 2, 0xFFFFAA00);
    }

    @Override
    public boolean isPauseScreen() {
        return false;
    }

    @Override
    public void removed() {
        if (!closedSent && !covered) {
            closedSent = true;
            runtime.screenEvent(script, ScreenSpec.Event.closed());
        }
        super.removed();
    }
}
