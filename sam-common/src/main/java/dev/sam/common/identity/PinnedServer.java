package dev.sam.common.identity;

import java.time.Instant;
import java.util.Objects;

/**
 * Un servidor que el jugador decidió confiar (PROTOCOLO.md 3.3, entrada de {@code servers}).
 *
 * <p>Guarda la clave pública completa y no solo su hash, para poder verificar rotaciones
 * firmadas por esa clave (PROTOCOLO.md 3.7).
 *
 * @param firstSeen cuándo se fijó por primera vez; se conserva aunque se reemplace la clave
 */
public record PinnedServer(ServerId id, ServerPublicKey key, String name, Instant firstSeen) {

    public PinnedServer {
        Objects.requireNonNull(id, "id");
        Objects.requireNonNull(key, "key");
        Objects.requireNonNull(name, "name");
        Objects.requireNonNull(firstSeen, "firstSeen");
    }

    public Pin pin() {
        return key.pin();
    }

    PinnedServer withKey(ServerPublicKey newKey) {
        return new PinnedServer(id, newKey, name, firstSeen);
    }
}
