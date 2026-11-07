package dev.sam.common.auth;

import java.util.Optional;

/**
 * Una cuenta: el nick como se registró, el hash de {@code K} (PHC), el correo, si lo vinculó el
 * {@code sub} de Google (RS-OAUTH-02: nunca su correo) y, si lo activó, su 2FA cifrado (RS-AUTH-03).
 *
 * @param key el nick normalizado ({@link Nick#normalize})
 */
public record Account(String key, String nick, String passwordHash, String email, Optional<String> googleSub,
        Optional<String> totp) {

    public Account(String key, String nick, String passwordHash, String email) {
        this(key, nick, passwordHash, email, Optional.empty(), Optional.empty());
    }

    public Account(String key, String nick, String passwordHash, String email, Optional<String> googleSub) {
        this(key, nick, passwordHash, email, googleSub, Optional.empty());
    }

    /** @param sealed el 2FA cifrado ({@code TotpVault}), o vacío si no lo tiene */
    public Account withTotp(Optional<String> sealed) {
        return new Account(key, nick, passwordHash, email, googleSub, sealed);
    }

    public Account withEmail(String newEmail) {
        return new Account(key, nick, passwordHash, newEmail, googleSub, totp);
    }

    public Account withGoogleSub(Optional<String> sub) {
        return new Account(key, nick, passwordHash, email, sub, totp);
    }
}
