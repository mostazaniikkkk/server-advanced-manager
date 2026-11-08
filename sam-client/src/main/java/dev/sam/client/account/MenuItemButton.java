package dev.sam.client.account;

import net.minecraft.client.gui.GuiGraphics;
import net.minecraft.client.gui.components.Button;
import net.minecraft.network.chat.Component;

/** Una entrada del menú desplegable de Opciones de cuenta, con el ícono del plugin a la izquierda. */
final class MenuItemButton extends Button {

    static final int WIDTH = 130;

    private final AccountMenu.Item item;

    MenuItemButton(int x, int y, AccountMenu.Item item) {
        super(x, y, WIDTH, 20, Component.literal(item.label()), b -> item.action().run(), DEFAULT_NARRATION);
        this.item = item;
    }

    @Override
    protected void renderWidget(GuiGraphics graphics, int mouseX, int mouseY, float delta) {
        super.renderWidget(graphics, mouseX, mouseY, delta);
        if (item.icon() != null) {
            item.icon().draw(graphics, getX() + 4, getY() + 4);
        }
    }
}
