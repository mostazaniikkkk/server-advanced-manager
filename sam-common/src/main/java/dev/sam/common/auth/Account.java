package dev.sam.common.auth;

import java.util.Optional;

/**
 * Una cuenta: el nick como se registró, el hash de {@code K} (PHC), el correo y, si lo vinculó, el
 * {@code sub} de Google (RS-OAUTH-02: nunca su correo).
 *
 * @param key el nick normalizado ({@link Nick#normalize})
 */
public record Account(String key, String nick, String passwordHash, String email, Optional<String> googleSub) {

    public Account(String key, String nick, String passwordHash, String email) {
        this(key, nick, passwordHash, email, Optional.empty());
    }

    public Account withEmail(String newEmail) {
        return new Account(key, nick, passwordHash, newEmail, googleSub);
    }

    public Account withGoogleSub(Optional<String> sub) {
        return new Account(key, nick, passwordHash, email, sub);
    }
}
