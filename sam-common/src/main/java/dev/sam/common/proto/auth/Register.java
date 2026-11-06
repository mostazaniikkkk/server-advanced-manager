package dev.sam.common.proto.auth;

import dev.sam.common.auth.PasswordDerivation;
import dev.sam.common.proto.SamReader;
import dev.sam.common.proto.SamWriter;

/**
 * {@code sam:register}, cliente → servidor (PROTOCOLO.md 5.3): {@code k} derivada en el cliente (6.1)
 * y el correo, siempre obligatorio. Como mucho {@value #MAX_BYTES} bytes (5.6).
 */
public record Register(byte[] k, String email) {

    public static final String ID = "register";
    public static final int MAX_BYTES = 512;

    static final int MAX_EMAIL = 254;

    public Register {
        LoginPassword.checkK(k);
    }

    public void write(SamWriter out) {
        out.fixed(k, PasswordDerivation.KEY_LENGTH).string(email, MAX_EMAIL);
    }

    public static Register read(SamReader in) {
        var k = in.fixed(PasswordDerivation.KEY_LENGTH);
        return new Register(k, in.string(MAX_EMAIL));
    }
}
