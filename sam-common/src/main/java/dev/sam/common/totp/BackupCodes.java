package dev.sam.common.totp;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.HexFormat;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;

/**
 * Los 10 códigos de respaldo del 2FA (RF-AUTH-04): {@code xxxx-xxxx} sin letras ambiguas (i, l, o, 0, 1),
 * de un solo uso. Se muestran una vez y solo se guarda su SHA-256.
 */
public final class BackupCodes {

    private static final char[] ALPHABET = "abcdefghjkmnpqrstuvwxyz23456789".toCharArray();
    private static final int COUNT = 10;

    private BackupCodes() {
    }

    public static List<String> generate(SecureRandom random) {
        var codes = new LinkedHashSet<String>();
        while (codes.size() < COUNT) {
            var code = new StringBuilder();
            for (var i = 0; i < 8; i++) {
                if (i == 4) {
                    code.append('-');
                }
                code.append(ALPHABET[random.nextInt(ALPHABET.length)]);
            }
            codes.add(code.toString());
        }
        return List.copyOf(codes);
    }

    public static List<String> hashes(List<String> codes) {
        return codes.stream().map(BackupCodes::hash).toList();
    }

    /** Se acepta en mayúsculas, sin el guion y con espacios alrededor. */
    static String hash(String code) {
        var normalized = code.strip().toLowerCase(Locale.ROOT).replace("-", "");
        try {
            var digest = MessageDigest.getInstance("SHA-256").digest(normalized.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(digest);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 siempre existe en la JDK", e);
        }
    }
}
