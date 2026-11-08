package dev.sam.common.totp;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HexFormat;
import java.util.Optional;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;

/**
 * El 2FA cifrado en reposo (RS-AUTH-03): AES-256-GCM con la clave de datos, un nonce nuevo en cada
 * sellado y la cuenta como datos asociados, así un estado no se puede copiar a otra cuenta. Lo que no
 * abre (otra clave, otra cuenta, alterado) es vacío.
 */
public final class TotpVault {

    private static final int NONCE = 12;
    private static final int TAG_BITS = 128;
    private static final int VERSION = 1;

    private final KeyRing ring;
    private final SecureRandom random;

    public TotpVault(DataKey key, SecureRandom random) {
        this(new KeyRing(key, Optional.empty()), random);
    }

    /** Con rotación (RF-CFG-12): sella con la actual y abre con cualquiera del anillo. */
    public TotpVault(KeyRing ring, SecureRandom random) {
        this.ring = ring;
        this.random = random;
    }

    public String seal(String account, TotpState state) {
        var nonce = new byte[NONCE];
        random.nextBytes(nonce);
        try {
            var cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, ring.current().key(), new GCMParameterSpec(TAG_BITS, nonce));
            cipher.updateAAD(aad(account));
            var sealed = cipher.doFinal(encode(state));
            return Base64.getEncoder().encodeToString(ByteBuffer.allocate(NONCE + sealed.length).put(nonce).put(sealed).array());
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("AES-GCM siempre existe en la JDK", e);
        }
    }

    public Optional<TotpState> open(String account, String sealed) {
        for (var key : ring.all()) {
            var opened = open(key, account, sealed);
            if (opened.isPresent()) {
                return opened;
            }
        }
        return Optional.empty();
    }

    private static Optional<TotpState> open(DataKey key, String account, String sealed) {
        try {
            var bytes = Base64.getDecoder().decode(sealed);
            var cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, key.key(), new GCMParameterSpec(TAG_BITS, bytes, 0, NONCE));
            cipher.updateAAD(aad(account));
            return Optional.of(decode(cipher.doFinal(bytes, NONCE, bytes.length - NONCE)));
        } catch (GeneralSecurityException | IllegalArgumentException | java.nio.BufferUnderflowException e) {
            return Optional.empty();
        }
    }

    private static byte[] aad(String account) {
        return ("sam-totp:" + account).getBytes(StandardCharsets.UTF_8);
    }

    private static byte[] encode(TotpState state) {
        var secret = state.secret();
        var hashes = state.backupHashes();
        var out = ByteBuffer.allocate(1 + 1 + secret.length + 8 + 1 + hashes.size() * 32);
        out.put((byte) VERSION).put((byte) secret.length).put(secret).putLong(state.lastStep()).put((byte) hashes.size());
        for (var hash : hashes) {
            out.put(HexFormat.of().parseHex(hash));
        }
        return out.array();
    }

    /** Paquete: la prueba de versión desconocida (lo sellado siempre lleva la actual). */
    static TotpState decode(byte[] plain) {
        var in = ByteBuffer.wrap(plain);
        if (in.get() != VERSION) {
            throw new IllegalArgumentException("versión desconocida");
        }
        var secret = new byte[in.get() & 0xFF];
        in.get(secret);
        var lastStep = in.getLong();
        var count = in.get() & 0xFF;
        var hashes = new ArrayList<String>();
        for (var i = 0; i < count; i++) {
            var hash = new byte[32];
            in.get(hash);
            hashes.add(HexFormat.of().formatHex(hash));
        }
        return new TotpState(secret, hashes, lastStep);
    }
}
