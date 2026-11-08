package dev.sam.common.totp;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

/**
 * RF-CFG-12 (H-14 de HARDENING.md): la clave de datos actual ({@code SAM_DATA_KEY}) y, durante una rotación, la
 * anterior ({@code SAM_DATA_KEY_PREVIOUS}). Se lee con cualquiera; se escribe con la actual.
 */
public record KeyRing(DataKey current, Optional<DataKey> previous) {

    public static final String PREVIOUS_ENV = "SAM_DATA_KEY_PREVIOUS";

    /** Primero la actual. */
    public List<DataKey> all() {
        var keys = new ArrayList<DataKey>();
        keys.add(current);
        previous.ifPresent(keys::add);
        return List.copyOf(keys);
    }
}
