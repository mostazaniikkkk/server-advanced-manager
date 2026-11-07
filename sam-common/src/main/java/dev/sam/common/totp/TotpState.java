package dev.sam.common.totp;

import java.util.List;

/**
 * El 2FA de una cuenta: el secreto, los hashes de los códigos de respaldo que quedan y el último paso
 * usado (un código ya usado no vuelve a valer). Se guarda cifrado (RS-AUTH-03).
 */
public record TotpState(byte[] secret, List<String> backupHashes, long lastStep) {

    public TotpState {
        if (secret.length == 0) {
            throw new IllegalArgumentException("secreto TOTP vacío");
        }
        secret = secret.clone();
        backupHashes = List.copyOf(backupHashes);
    }

    @Override
    public byte[] secret() {
        return secret.clone();
    }
}
