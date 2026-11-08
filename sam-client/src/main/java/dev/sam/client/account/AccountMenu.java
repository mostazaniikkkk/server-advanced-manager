package dev.sam.client.account;

import java.util.List;
import java.util.function.Supplier;

import net.minecraft.client.gui.GuiGraphics;

/**
 * Las entradas que los plugins agregan al botón de Opciones de cuenta (capacidad {@code menu},
 * docs/plugins/sam-mensajes.md). Las da el runtime de scripts; aquí solo se dibujan.
 */
public final class AccountMenu {

    /** Una entrada: su texto, qué hace al elegirla y cómo dibujar su ícono (12×12) en x, y. */
    public record Item(String label, Runnable action, IconDrawer icon) {
    }

    @FunctionalInterface
    public interface IconDrawer {
        void draw(GuiGraphics graphics, int x, int y);
    }

    private static volatile Supplier<List<Item>> plugins = List::of;

    private AccountMenu() {
    }

    /** Lo registra el runtime de scripts al iniciar el mod. */
    public static void plugins(Supplier<List<Item>> source) {
        plugins = source;
    }

    static List<Item> pluginItems() {
        return plugins.get();
    }
}
