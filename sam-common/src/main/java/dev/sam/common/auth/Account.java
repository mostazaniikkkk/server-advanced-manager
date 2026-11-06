package dev.sam.common.auth;

/**
 * Una cuenta: el nick como se registró, el hash de {@code K} (PHC) y el correo.
 *
 * @param key el nick normalizado ({@link Nick#normalize})
 */
public record Account(String key, String nick, String passwordHash, String email) {
}
