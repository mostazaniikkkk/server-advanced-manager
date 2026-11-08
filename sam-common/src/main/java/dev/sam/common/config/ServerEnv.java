package dev.sam.common.config;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * La configuración efectiva: el {@code .env} más las variables de entorno reales del proceso, que
 * tienen prioridad (RF-CFG-02). Del entorno solo se toman las claves {@code SAM_}. Los secretos
 * maestros nunca se aceptan del archivo (RF-CFG-08).
 */
public final class ServerEnv {

    public static final String DATA_KEY = "SAM_DATA_KEY";
    public static final String IDENTITY_PASSPHRASE = "SAM_IDENTITY_PASSPHRASE";
    /** RF-CFG-12: la clave de datos anterior durante una rotación. */
    public static final String DATA_KEY_PREVIOUS = "SAM_DATA_KEY_PREVIOUS";
    public static final List<String> MASTER_SECRETS = List.of(DATA_KEY, DATA_KEY_PREVIOUS, IDENTITY_PASSPHRASE);

    private ServerEnv() {
    }

    /**
     * @throws IllegalArgumentException si el archivo trae un secreto maestro
     */
    public static Map<String, String> merge(Map<String, String> file, Map<String, String> process) {
        for (var secret : MASTER_SECRETS) {
            if (file.containsKey(secret)) {
                // Sin el valor: el mensaje va a la consola
                throw new IllegalArgumentException(secret + " está escrita en el .env: los secretos maestros solo se aceptan "
                    + "como variable de entorno del proceso (RF-CFG-08). Bórrala del archivo y defínela en el entorno.");
            }
        }
        var merged = new LinkedHashMap<>(file);
        process.forEach((key, value) -> {
            if (key.startsWith("SAM_")) {
                merged.put(key, value);
            }
        });
        return Collections.unmodifiableMap(merged);
    }
}
