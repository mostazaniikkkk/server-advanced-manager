package dev.sam.client.auth;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.Optional;

import dev.sam.common.totp.Totp;

/**
 * Solo para las pruebas en el entorno de desarrollo: guarda el secreto de un 2FA recién activado y calcula
 * códigos como lo haría la app del teléfono. El jar publicado nunca lo usa (los ganchos exigen el
 * entorno de desarrollo de Loom).
 */
public final class DevTotp {

    private static final String ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

    private DevTotp() {
    }

    /** El secreto en base32 de una URI {@code otpauth://}. */
    public static String secretOf(String uri) {
        return uri.replaceAll(".*[?&]secret=([A-Z2-7]+).*", "$1");
    }

    public static void save(Path file, String base32) {
        try {
            Files.writeString(file, base32);
        } catch (IOException e) {
            throw new java.io.UncheckedIOException(e);
        }
    }

    /** El código actual; se usa el paso siguiente para no repetir el que acaba de usarse (ventana ±1). */
    public static Optional<String> code(Path file) {
        try {
            return Optional.of(codeFor(Files.readString(file).strip(), 1));
        } catch (IOException e) {
            return Optional.empty();
        }
    }

    public static String codeFor(String base32, long offset) {
        var out = new ByteArrayOutputStream();
        int buffer = 0;
        int bits = 0;
        for (var c : base32.toCharArray()) {
            buffer = (buffer << 5) | ALPHABET.indexOf(c);
            bits += 5;
            if (bits >= 8) {
                out.write((buffer >> (bits - 8)) & 0xFF);
                bits -= 8;
            }
        }
        return Totp.code(out.toByteArray(), Instant.now().getEpochSecond() / Totp.PERIOD_SECONDS + offset);
    }
}
