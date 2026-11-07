package dev.sam.signer;

import java.util.Arrays;

/** Borra secretos de la memoria apenas dejan de hacer falta (claves, passphrases, PKCS#8 en claro). */
final class Secrets {

    private Secrets() {
    }

    static void wipe(byte[]... secrets) {
        for (var secret : secrets) {
            Arrays.fill(secret, (byte) 0);
        }
    }

    static void wipe(char[]... secrets) {
        for (var secret : secrets) {
            Arrays.fill(secret, '\0');
        }
    }
}
