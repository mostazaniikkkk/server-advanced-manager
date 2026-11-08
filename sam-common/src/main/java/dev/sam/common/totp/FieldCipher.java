package dev.sam.common.totp;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Optional;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;

/**
 * RF-CFG-12 (H-13, H-14 de HARDENING.md): un campo de texto cifrado con la clave de datos. Formato
 * {@code enc1:<id de clave>:<base64(nonce de 12 bytes + AES-256-GCM)>}, con AAD {@code sam-field:<contexto>}
 * (el campo y la cuenta), así un valor no se puede mover a otra cuenta. Abre con cualquier clave del anillo y
 * sella siempre con la actual.
 */
public final class FieldCipher {

    private static final String PREFIX = "enc1:";
    private static final int NONCE = 12;
    private static final int TAG_BITS = 128;

    private final KeyRing ring;
    private final SecureRandom random;

    public FieldCipher(KeyRing ring, SecureRandom random) {
        this.ring = ring;
        this.random = random;
    }

    public static boolean isSealed(String value) {
        return value.startsWith(PREFIX);
    }

    public String seal(String context, String value) {
        var nonce = new byte[NONCE];
        random.nextBytes(nonce);
        var key = ring.current();
        try {
            var cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, key.key(), new GCMParameterSpec(TAG_BITS, nonce));
            cipher.updateAAD(aad(context));
            var sealed = cipher.doFinal(value.getBytes(StandardCharsets.UTF_8));
            return PREFIX + key.id() + ":"
                + Base64.getEncoder().encodeToString(ByteBuffer.allocate(NONCE + sealed.length).put(nonce).put(sealed).array());
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("AES-GCM siempre existe en la JDK", e);
        }
    }

    /** Vacío si no es un valor sellado, si su clave no está en el anillo o si no autentica. */
    public Optional<String> open(String context, String sealed) {
        var parts = sealed.split(":", 3);
        if (parts.length != 3) {
            return Optional.empty();
        }
        var key = ring.all().stream().filter(k -> k.id().equals(parts[1])).findFirst();
        if (key.isEmpty()) {
            return Optional.empty();
        }
        try {
            var bytes = Base64.getDecoder().decode(parts[2]);
            var cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, key.get().key(), new GCMParameterSpec(TAG_BITS, bytes, 0, NONCE));
            cipher.updateAAD(aad(context));
            return Optional.of(new String(cipher.doFinal(bytes, NONCE, bytes.length - NONCE), StandardCharsets.UTF_8));
        } catch (GeneralSecurityException | IllegalArgumentException e) {
            return Optional.empty();
        }
    }

    /** Si el valor está sellado con una clave que no es la actual (hay que volver a sellarlo). */
    public boolean needsRekey(String sealed) {
        return !sealed.startsWith(PREFIX + ring.current().id() + ":");
    }

    private static byte[] aad(String context) {
        return ("sam-field:" + context).getBytes(StandardCharsets.UTF_8);
    }
}
