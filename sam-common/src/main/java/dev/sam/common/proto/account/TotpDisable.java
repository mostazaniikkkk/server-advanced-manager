package dev.sam.common.proto.account;

import dev.sam.common.auth.PasswordDerivation;
import dev.sam.common.proto.SamReader;
import dev.sam.common.proto.SamWriter;
import dev.sam.common.proto.auth.LoginPassword;

/** {@code sam:totp_disable}, cliente → servidor (PROTOCOLO.md 5.7): desactivar el 2FA pide {@code k} y código. */
public record TotpDisable(byte[] k, String code) {

    public static final String ID = "totp_disable";
    public static final int MAX_BYTES = 512;

    public TotpDisable {
        LoginPassword.checkK(k);
    }

    public void write(SamWriter out) {
        out.fixed(k, PasswordDerivation.KEY_LENGTH).string(code, AccountInfo.MAX_CODE);
    }

    public static TotpDisable read(SamReader in) {
        var k = in.fixed(PasswordDerivation.KEY_LENGTH);
        return new TotpDisable(k, in.string(AccountInfo.MAX_CODE));
    }
}
