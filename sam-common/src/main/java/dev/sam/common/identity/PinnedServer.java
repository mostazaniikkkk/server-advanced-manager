package dev.sam.common.identity;

import java.time.Instant;
import java.util.Objects;

/**
 * Un servidor que el jugador decidió confiar (PROTOCOLO.md 3.3, entrada de {@code servers}).
 *
 * @param firstSeen cuándo se fijó por primera vez; se conserva aunque se reemplace el pin
 */
public record PinnedServer(ServerId id, Pin pin, String name, Instant firstSeen) {

    public PinnedServer {
        Objects.requireNonNull(id, "id");
        Objects.requireNonNull(pin, "pin");
        Objects.requireNonNull(name, "name");
        Objects.requireNonNull(firstSeen, "firstSeen");
    }

    PinnedServer withPin(Pin newPin) {
        return new PinnedServer(id, newPin, name, firstSeen);
    }
}
