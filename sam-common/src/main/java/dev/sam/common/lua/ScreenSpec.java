package dev.sam.common.lua;

import java.util.List;

/**
 * Una pantalla de un script (API de cliente v0, {@code screens}, PROTOCOLO.md 8.3): datos ya validados que
 * el juego dibuja; nunca código. Las posiciones son relativas a la esquina del panel, en píxeles de la GUI.
 */
public record ScreenSpec(String title, int width, int height, List<Widget> widgets) {

    public ScreenSpec {
        widgets = List.copyOf(widgets);
    }

    /** Un elemento de la pantalla. */
    public sealed interface Widget permits Label, Button, TextField, Checkbox, Image {
    }

    public record Label(int x, int y, String text, int color) implements Widget {
    }

    public record Button(String id, int x, int y, String text, int w, int h) implements Widget {
    }

    public record TextField(String id, int x, int y, int w, int max, String value) implements Widget {
    }

    public record Checkbox(String id, int x, int y, String text, boolean checked) implements Widget {
    }

    /** Una imagen del propio script: los bytes ya pasaron {@link PngInfo#check}. */
    public record Image(String path, byte[] png, int x, int y, int w, int h) implements Widget {

        public Image {
            png = png.clone();
        }

        @Override
        public byte[] png() {
            return png.clone();
        }
    }

    /** Un evento de la pantalla para {@code sam.screen.on}: {@code click}, {@code change} o {@code close}. */
    public record Event(String type, String id, Object value) {

        public static Event click(String id) {
            return new Event("click", id, null);
        }

        /** @param value el texto de un {@code text_field} o el estado de un {@code checkbox} */
        public static Event change(String id, Object value) {
            return new Event("change", id, value);
        }

        public static Event closed() {
            return new Event("close", null, null);
        }
    }
}
