package dev.sam.common.proto.auth;

import java.util.Optional;
import java.util.regex.Pattern;

import dev.sam.common.auth.PasswordDerivation;
import dev.sam.common.proto.ProtocolException;
import dev.sam.common.proto.SamReader;
import dev.sam.common.proto.SamWriter;

/**
 * {@code sam:login_password}, cliente → servidor (PROTOCOLO.md 5.3): {@code k} y, con
 * {@code PASSWORD_TOTP}, el código de 6 dígitos. Como mucho {@value #MAX_BYTES} bytes (5.6).
 */
public record LoginPassword(byte[] k, Optional<String> totp) {

    public static final String ID = "login_password";
    public static final int MAX_BYTES = 512;

    private static final int TOTP_LENGTH = 6;
    private static final Pattern TOTP = Pattern.compile("[0-9]{6}");

    public LoginPassword {
        checkK(k);
        if (totp.isPresent() && !TOTP.matcher(totp.get()).matches()) {
            throw new IllegalArgumentException("el TOTP debe tener 6 dígitos");
        }
    }

    public void write(SamWriter out) {
        out.fixed(k, PasswordDerivation.KEY_LENGTH).optional(totp, (w, code) -> w.string(code, TOTP_LENGTH));
    }

    public static LoginPassword read(SamReader in) {
        var k = in.fixed(PasswordDerivation.KEY_LENGTH);
        var totp = in.optional(r -> r.string(TOTP_LENGTH));
        return ProtocolException.fromRead(() -> new LoginPassword(k, totp));
    }

    static void checkK(byte[] k) {
        if (k.length != PasswordDerivation.KEY_LENGTH) {
            throw new IllegalArgumentException("k debe tener 32 bytes");
        }
    }
}
