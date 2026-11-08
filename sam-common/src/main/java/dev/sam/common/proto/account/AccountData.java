package dev.sam.common.proto.account;

import java.util.Optional;

import dev.sam.common.auth.PasswordDerivation;
import dev.sam.common.proto.SamReader;
import dev.sam.common.proto.SamWriter;
import dev.sam.common.proto.auth.LoginPassword;

/**
 * {@code sam:account_data}, cliente → servidor (PROTOCOLO.md 5.7, RF-AUTH-07e): exportar o borrar los datos del
 * jugador, con {@code k} y el código si la cuenta tiene 2FA.
 */
public record AccountData(Action action, byte[] k, Optional<String> code) {

    public enum Action { EXPORT, DELETE }

    public static final String ID = "account_data";
    public static final int MAX_BYTES = 512;

    public AccountData {
        LoginPassword.checkK(k);
    }

    public void write(SamWriter out) {
        out.enumValue(action).fixed(k, PasswordDerivation.KEY_LENGTH).optional(code, (w, c) -> w.string(c, AccountInfo.MAX_CODE));
    }

    public static AccountData read(SamReader in) {
        var action = in.enumValue(Action.class);
        var k = in.fixed(PasswordDerivation.KEY_LENGTH);
        return new AccountData(action, k, in.optional(r -> r.string(AccountInfo.MAX_CODE)));
    }
}
