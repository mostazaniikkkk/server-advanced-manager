package dev.sam.client.auth;

import com.mojang.blaze3d.systems.RenderSystem;

import net.minecraft.client.Minecraft;
import net.minecraft.client.gui.GuiGraphics;
import net.minecraft.client.gui.components.AbstractButton;
import net.minecraft.client.gui.narration.NarrationElementOutput;
import net.minecraft.network.chat.Component;
import net.minecraft.resources.ResourceLocation;

/** "Entrar con Google": blanco, texto negro y la G en pixel art, como el botón de Google. */
public final class GoogleButton extends AbstractButton {

    private static final ResourceLocation LOGO = ResourceLocation.fromNamespaceAndPath("sam-client", "textures/gui/google.png");
    private static final int LOGO_SIZE = 12;
    private static final int GAP = 6;

    private final Runnable onPress;

    public GoogleButton(int x, int y, int width, int height, Component label, Runnable onPress) {
        super(x, y, width, height, label);
        this.onPress = onPress;
    }

    @Override
    public void onPress() {
        onPress.run();
    }

    @Override
    protected void renderWidget(GuiGraphics graphics, int mouseX, int mouseY, float delta) {
        var x = getX();
        var y = getY();
        int border;
        int fill;
        int text;
        if (!active) {
            border = 0xFFBDBDBD;
            fill = 0xFFE6E6E6;
            text = 0xFF8A8A8A;
        } else if (isHoveredOrFocused()) {
            border = 0xFF1F1F1F;
            fill = 0xFFF2F2F2;
            text = 0xFF1F1F1F;
        } else {
            border = 0xFF747775;
            fill = 0xFFFFFFFF;
            text = 0xFF1F1F1F;
        }
        graphics.fill(x, y, x + width, y + height, border);
        graphics.fill(x + 1, y + 1, x + width - 1, y + height - 1, fill);

        var font = Minecraft.getInstance().font;
        var label = getMessage();
        var contentWidth = LOGO_SIZE + GAP + font.width(label);
        var left = x + (width - contentWidth) / 2;
        RenderSystem.enableBlend();
        graphics.setColor(1, 1, 1, active ? 1 : 0.5F);
        graphics.blit(LOGO, left, y + (height - LOGO_SIZE) / 2, 0, 0, LOGO_SIZE, LOGO_SIZE, LOGO_SIZE, LOGO_SIZE);
        graphics.setColor(1, 1, 1, 1);
        RenderSystem.disableBlend();
        graphics.drawString(font, label, left + LOGO_SIZE + GAP, y + (height - 8) / 2, text, false);
    }

    @Override
    protected void updateWidgetNarration(NarrationElementOutput output) {
        defaultButtonNarrationText(output);
    }
}
