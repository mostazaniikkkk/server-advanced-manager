package dev.sam.common.proto.account;

import dev.sam.common.auth.PasswordDerivation;
import dev.sam.common.proto.SamReader;
import dev.sam.common.proto.SamWriter;
import dev.sam.common.proto.auth.LoginPassword;

/**
 * {@code sam:account_unlink}, cliente → servidor (PROTOCOLO.md 5.7, RF-OAUTH-02): {@code k} para
 * reautenticarse y el proveedor a desvincular. Como mucho {@value #MAX_BYTES} bytes.
 */
public record AccountUnlink(byte[] k, OAuthProvider provider) {

    public static final String ID = "account_unlink";
    public static final int MAX_BYTES = 512;

    public AccountUnlink {
        LoginPassword.checkK(k);
    }

    public void write(SamWriter out) {
        out.fixed(k, PasswordDerivation.KEY_LENGTH).enumValue(provider);
    }

    public static AccountUnlink read(SamReader in) {
        var k = in.fixed(PasswordDerivation.KEY_LENGTH);
        return new AccountUnlink(k, in.enumValue(OAuthProvider.class));
    }
}
