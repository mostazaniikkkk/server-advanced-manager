package dev.sam.common.totp;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Optional;
import java.util.regex.Pattern;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * TOTP (RFC 6238 con HMAC-SHA1, 6 dígitos y pasos de 30 s, lo que usan Google Authenticator, Aegis y
 * compañía). Se acepta el paso actual y uno antes o después (RF-AUTH-04); un paso igual o anterior al
 * último usado no vale, así un código interceptado no se puede repetir.
 */
public final class Totp {

    public static final int PERIOD_SECONDS = 30;
    private static final int DIGITS = 6;
    private static final int SECRET_BYTES = 20;
    private static final Pattern SIX_DIGITS = Pattern.compile("[0-9]{6}");
    private static final char[] BASE32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567".toCharArray();

    private Totp() {
    }

    /** Base32 del RFC 4648, sin relleno (como lo esperan las apps en {@code secret=}). */
    public static String base32(byte[] data) {
        var out = new StringBuilder();
        int buffer = 0;
        int bits = 0;
        for (var b : data) {
            buffer = (buffer << 8) | (b & 0xFF);
            bits += 8;
            while (bits > 4) {
                out.append(BASE32[(buffer >> (bits - 5)) & 31]);
                bits -= 5;
            }
        }
        if (bits > 0) {
            out.append(BASE32[(buffer << (5 - bits)) & 31]);
        }
        return out.toString();
    }

    public static String code(byte[] secret, long step) {
        try {
            var mac = Mac.getInstance("HmacSHA1");
            mac.init(new SecretKeySpec(secret, "HmacSHA1"));
            var hash = mac.doFinal(java.nio.ByteBuffer.allocate(8).putLong(step).array());
            var offset = hash[hash.length - 1] & 0x0F;
            var binary = ((hash[offset] & 0x7F) << 24) | ((hash[offset + 1] & 0xFF) << 16) | ((hash[offset + 2] & 0xFF) << 8)
                | (hash[offset + 3] & 0xFF);
            return String.format("%0" + DIGITS + "d", binary % 1_000_000);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("HmacSHA1 siempre existe en la JDK", e);
        }
    }

    /**
     * @return el estado actualizado si el código vale (6 dígitos o un código de respaldo); vacío si no
     */
    public static Optional<TotpState> check(TotpState state, String code, Instant now) {
        if (SIX_DIGITS.matcher(code).matches()) {
            var current = now.getEpochSecond() / PERIOD_SECONDS;
            var secret = state.secret();
            for (var step = current - 1; step <= current + 1; step++) {
                if (step > state.lastStep() && code.equals(code(secret, step))) {
                    return Optional.of(new TotpState(secret, state.backupHashes(), step));
                }
            }
            return Optional.empty();
        }
        var hash = BackupCodes.hash(code);
        if (!state.backupHashes().contains(hash)) {
            return Optional.empty();
        }
        var remaining = new ArrayList<>(state.backupHashes());
        remaining.remove(hash);
        return Optional.of(new TotpState(state.secret(), remaining, state.lastStep()));
    }

    /** La URI del QR ({@code otpauth://totp/...}), con el servidor como emisor. */
    public static String otpauthUri(String issuer, String account, byte[] secret) {
        var label = encode(issuer) + ":" + encode(account);
        return "otpauth://totp/" + label + "?secret=" + base32(secret) + "&issuer=" + encode(issuer)
            + "&algorithm=SHA1&digits=" + DIGITS + "&period=" + PERIOD_SECONDS;
    }

    public static byte[] newSecret(SecureRandom random) {
        var secret = new byte[SECRET_BYTES];
        random.nextBytes(secret);
        return secret;
    }

    private static String encode(String text) {
        return URLEncoder.encode(text, StandardCharsets.UTF_8).replace("+", "%20");
    }
}
