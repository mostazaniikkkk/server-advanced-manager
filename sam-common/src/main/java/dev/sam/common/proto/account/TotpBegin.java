package dev.sam.common.proto.account;

import dev.sam.common.auth.PasswordDerivation;
import dev.sam.common.proto.SamReader;
import dev.sam.common.proto.SamWriter;
import dev.sam.common.proto.auth.LoginPassword;

/** {@code sam:totp_begin}, cliente → servidor (PROTOCOLO.md 5.7, RF-AUTH-04): activar el 2FA, con {@code k}. */
public record TotpBegin(byte[] k) {

    public static final String ID = "totp_begin";
    public static final int MAX_BYTES = 512;

    public TotpBegin {
        LoginPassword.checkK(k);
    }

    public void write(SamWriter out) {
        out.fixed(k, PasswordDerivation.KEY_LENGTH);
    }

    public static TotpBegin read(SamReader in) {
        return new TotpBegin(in.fixed(PasswordDerivation.KEY_LENGTH));
    }
}
