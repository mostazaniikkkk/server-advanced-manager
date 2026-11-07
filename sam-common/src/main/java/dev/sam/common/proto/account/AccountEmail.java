package dev.sam.common.proto.account;

import dev.sam.common.auth.PasswordDerivation;
import dev.sam.common.proto.SamReader;
import dev.sam.common.proto.SamWriter;
import dev.sam.common.proto.auth.LoginPassword;

/**
 * {@code sam:account_email}, cliente → servidor (PROTOCOLO.md 5.7, RF-AUTH-07b): {@code k} para
 * reautenticarse y el correo nuevo. Como mucho {@value #MAX_BYTES} bytes.
 */
public record AccountEmail(byte[] k, String email) {

    public static final String ID = "account_email";
    public static final int MAX_BYTES = 512;

    public AccountEmail {
        LoginPassword.checkK(k);
    }

    public void write(SamWriter out) {
        out.fixed(k, PasswordDerivation.KEY_LENGTH).string(email, AccountInfo.MAX_EMAIL);
    }

    public static AccountEmail read(SamReader in) {
        var k = in.fixed(PasswordDerivation.KEY_LENGTH);
        return new AccountEmail(k, in.string(AccountInfo.MAX_EMAIL));
    }
}
