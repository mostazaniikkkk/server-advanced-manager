package dev.sam.common.mc;

/**
 * Paquete de desconexión en fase login (clientbound, id 0x00): un text component JSON.
 * Lo escribe la compuerta de SAM directamente, porque está antes de los encoders de Minecraft.
 */
public final class LoginDisconnect {

    private LoginDisconnect() {
    }

    /** El frame completo (longitud + id + string), listo para escribir en el socket. */
    public static byte[] frame(String message) {
        return Wire.frame(Wire.concat(Wire.varInt(0x00), Wire.string(textComponent(message))));
    }

    /** {@code {"text":"..."}} con el escape de JSON (RFC 8259) de comillas, barras y control. */
    public static String textComponent(String message) {
        var json = new StringBuilder("{\"text\":\"");
        for (int i = 0; i < message.length(); i++) {
            char c = message.charAt(i);
            switch (c) {
                case '"' -> json.append("\\\"");
                case '\\' -> json.append("\\\\");
                case '\b' -> json.append("\\b");
                case '\f' -> json.append("\\f");
                case '\n' -> json.append("\\n");
                case '\r' -> json.append("\\r");
                case '\t' -> json.append("\\t");
                default -> {
                    if (c < 0x20) {
                        json.append(String.format("\\u%04x", (int) c));
                    } else {
                        json.append(c);
                    }
                }
            }
        }
        return json.append("\"}").toString();
    }
}
