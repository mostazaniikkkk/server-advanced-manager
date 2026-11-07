package dev.sam.client.account;

import net.minecraft.client.Minecraft;
import net.minecraft.client.gui.GuiGraphics;
import net.minecraft.client.gui.components.AbstractButton;
import net.minecraft.client.gui.components.PlayerFaceRenderer;
import net.minecraft.client.gui.components.Tooltip;
import net.minecraft.client.gui.narration.NarrationElementOutput;
import net.minecraft.network.chat.Component;

/** El botón de "Opciones de cuenta" (RF-AUTH-07d): la cara de la skin con una tuerca encima. */
final class AccountButton extends AbstractButton {

    static final int SIZE = 22;
    private static final Component LABEL = Component.literal("Opciones de cuenta");

    private final Runnable onPress;

    AccountButton(int x, int y, Runnable onPress) {
        super(x, y, SIZE, SIZE, LABEL);
        this.onPress = onPress;
        setTooltip(Tooltip.create(LABEL));
    }

    @Override
    public void onPress() {
        onPress.run();
    }

    @Override
    protected void renderWidget(GuiGraphics graphics, int mouseX, int mouseY, float delta) {
        var minecraft = Minecraft.getInstance();
        var border = isHoveredOrFocused() ? 0xFFFFFFFF : 0xFF4A4A55;
        graphics.fill(getX(), getY(), getX() + SIZE, getY() + SIZE, border);
        graphics.fill(getX() + 1, getY() + 1, getX() + SIZE - 1, getY() + SIZE - 1, 0xE0101014);
        var skin = minecraft.getSkinManager().getInsecureSkin(minecraft.getGameProfile());
        PlayerFaceRenderer.draw(graphics, skin, getX() + 3, getY() + 3, 16);
        // La tuerca, abajo a la derecha sobre la cara
        graphics.pose().pushPose();
        graphics.pose().translate(0, 0, 200);
        graphics.drawString(minecraft.font, "⚙", getX() + SIZE - 9, getY() + SIZE - 10, 0xFFFFDD55, true);
        graphics.pose().popPose();
    }

    @Override
    protected void updateWidgetNarration(NarrationElementOutput output) {
        defaultButtonNarrationText(output);
    }
}
