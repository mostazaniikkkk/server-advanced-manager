package dev.sam.common.proto.account;

import dev.sam.common.proto.SamReader;
import dev.sam.common.proto.SamWriter;

/**
 * {@code sam:account_info}, servidor → cliente (PROTOCOLO.md 5.7): lo que muestra "Opciones de cuenta".
 * El correo llega enmascarado (RS-AUTH-07).
 */
public record AccountInfo(String email, boolean emailVerified, Google google, Totp totp) {

    public static final String ID = "account_info";

    static final int MAX_EMAIL = 254;

    /** El código de la app o de respaldo (PROTOCOLO.md 5.3/5.7). */
    static final int MAX_CODE = 16;

    /** Google en esta cuenta: el servidor no lo tiene configurado, se puede vincular o ya está vinculado. */
    public enum Google {
        UNAVAILABLE, AVAILABLE, LINKED
    }

    /** El 2FA: no disponible (el servidor no tiene SAM_DATA_KEY), apagado o activo. */
    public enum Totp {
        UNAVAILABLE, OFF, ON
    }

    public void write(SamWriter out) {
        out.string(email, MAX_EMAIL).bool(emailVerified).enumValue(google).enumValue(totp);
    }

    public static AccountInfo read(SamReader in) {
        var email = in.string(MAX_EMAIL);
        var verified = in.bool();
        var google = in.enumValue(Google.class);
        return new AccountInfo(email, verified, google, in.enumValue(Totp.class));
    }
}
