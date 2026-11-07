package dev.sam.common.proto.account;

import dev.sam.common.proto.SamReader;
import dev.sam.common.proto.SamWriter;

/**
 * {@code sam:account_info}, servidor → cliente (PROTOCOLO.md 5.7): lo que muestra "Opciones de cuenta".
 * El correo llega enmascarado (RS-AUTH-07).
 */
public record AccountInfo(String email, boolean emailVerified, Google google) {

    public static final String ID = "account_info";

    static final int MAX_EMAIL = 254;

    /** Google en esta cuenta: el servidor no lo tiene configurado, se puede vincular o ya está vinculado. */
    public enum Google {
        UNAVAILABLE, AVAILABLE, LINKED
    }

    public void write(SamWriter out) {
        out.string(email, MAX_EMAIL).bool(emailVerified).enumValue(google);
    }

    public static AccountInfo read(SamReader in) {
        var email = in.string(MAX_EMAIL);
        var verified = in.bool();
        return new AccountInfo(email, verified, in.enumValue(Google.class));
    }
}
