package dev.sam.common.identity;

import java.nio.charset.StandardCharsets;
import java.util.HexFormat;
import java.util.List;
import java.util.Locale;

import dev.sam.common.crypto.Hashes;

/**
 * Huella visual del certificado del servidor (RN-42, PROTOCOLO.md 3.5, P-07).
 *
 * <pre>
 * h        = SHA-256("SAM-fp-v1" ‖ pin)            pin = SHA-256(SPKI), 32 bytes
 * palabras = 3 índices de 11 bits tomados de los 33 bits altos de h[0..5)
 * identicon = celdas de h[5..7), color de la paleta según h[7] &amp; 0x0F
 * hex      = pin[0..16) en mayúsculas, en 8 grupos de 4
 * </pre>
 *
 * @param words     las 3 palabras, inmutables
 * @param hex       huella para comparar a mano, p. ej. {@code "A1B2 C3D4 …"}
 * @param identicon ícono de 5×5
 */
public record ServerFingerprint(List<String> words, String hex, Identicon identicon) {

    public static final int PIN_LENGTH = 32;

    private static final byte[] DOMAIN = "SAM-fp-v1".getBytes(StandardCharsets.US_ASCII);
    private static final int WORD_BITS = 11;
    private static final int HEX_BYTES = 16;

    public ServerFingerprint {
        words = List.copyOf(words);
    }

    public static ServerFingerprint of(byte[] pin) {
        if (pin.length != PIN_LENGTH) {
            throw new IllegalArgumentException("El pin debe medir " + PIN_LENGTH + " bytes, no " + pin.length);
        }
        var h = Hashes.sha256(DOMAIN, pin);
        return new ServerFingerprint(words(h), hex(pin), Identicon.fromBits(uint16(h, 5), h[7]));
    }

    /** Las palabras separadas por puntos medios, p. ej. {@code "náusea · ducha · límite"}. */
    public String phrase() {
        return String.join(" · ", words);
    }

    private static List<String> words(byte[] h) {
        long bits = 0;
        for (int i = 0; i < 5; i++) {
            bits = bits << 8 | (h[i] & 0xFF);
        }
        var list = Wordlist.spanish();
        int mask = (1 << WORD_BITS) - 1;
        return List.of(
            list.get((int) (bits >>> 29) & mask),
            list.get((int) (bits >>> 18) & mask),
            list.get((int) (bits >>> 7) & mask));
    }

    private static String hex(byte[] pin) {
        var plain = HexFormat.of().formatHex(pin, 0, HEX_BYTES).toUpperCase(Locale.ROOT);
        var grouped = new StringBuilder();
        for (int i = 0; i < plain.length(); i += 4) {
            if (i > 0) {
                grouped.append(' ');
            }
            grouped.append(plain, i, i + 4);
        }
        return grouped.toString();
    }

    private static int uint16(byte[] bytes, int offset) {
        return (bytes[offset] & 0xFF) << 8 | (bytes[offset + 1] & 0xFF);
    }
}
