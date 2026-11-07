package dev.sam.common.proto.auth;

import dev.sam.common.proto.SamReader;
import dev.sam.common.proto.SamWriter;

/**
 * {@code sam:login_totp}, cliente → servidor (PROTOCOLO.md 5.3): el segundo paso tras {@code NEED_TOTP},
 * con el código de la app o uno de respaldo. Como mucho {@value #MAX_BYTES} bytes.
 */
public record LoginTotp(String code) {

    public static final String ID = "login_totp";
    public static final int MAX_BYTES = 512;

    private static final int MAX_CODE = 16;

    public void write(SamWriter out) {
        out.string(code, MAX_CODE);
    }

    public static LoginTotp read(SamReader in) {
        return new LoginTotp(in.string(MAX_CODE));
    }
}
