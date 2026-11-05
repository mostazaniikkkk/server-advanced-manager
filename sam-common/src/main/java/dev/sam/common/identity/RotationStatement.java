package dev.sam.common.identity;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Objects;

/**
 * Declaración de rotación de la clave del servidor, firmada con la clave anterior
 * (PROTOCOLO.md 3.7).
 *
 * <pre>
 * firma = Ed25519(clave anterior, "SAM-rot-v1" ‖ server_id ‖ old_pin ‖ new_spki ‖ issued_at)
 * </pre>
 *
 * @param issuedAt segundos desde la época Unix; se firma en 8 bytes big-endian
 */
public record RotationStatement(ServerId serverId, Pin oldPin, ServerPublicKey newKey, long issuedAt, byte[] signature) {

    public static final int SIGNATURE_LENGTH = 64;

    private static final byte[] DOMAIN = "SAM-rot-v1".getBytes(StandardCharsets.US_ASCII);

    public RotationStatement {
        Objects.requireNonNull(serverId, "serverId");
        Objects.requireNonNull(oldPin, "oldPin");
        Objects.requireNonNull(newKey, "newKey");
        if (signature.length != SIGNATURE_LENGTH) {
            throw new IllegalArgumentException(
                "La firma debe medir " + SIGNATURE_LENGTH + " bytes, no " + signature.length);
        }
        signature = signature.clone();
    }

    /** Declaración sin firmar (firma en ceros): sirve para obtener {@link #signedMessage()} y firmarlo. */
    public static RotationStatement unsigned(ServerId serverId, Pin oldPin, ServerPublicKey newKey, long issuedAt) {
        return new RotationStatement(serverId, oldPin, newKey, issuedAt, new byte[SIGNATURE_LENGTH]);
    }

    /** Los bytes que cubre la firma. */
    public byte[] signedMessage() {
        var newSpki = newKey.spki();
        return ByteBuffer.allocate(DOMAIN.length + ServerId.LENGTH + Pin.LENGTH + newSpki.length + Long.BYTES)
            .put(DOMAIN)
            .put(serverId.toBytes())
            .put(oldPin.toBytes())
            .put(newSpki)
            .putLong(issuedAt)
            .array();
    }

    /**
     * {@code true} si {@code key} es la clave anterior que declara la propia rotación
     * ({@code old_pin}) y la firma es válida con ella.
     */
    public boolean isSignedBy(ServerPublicKey key) {
        return key.pin().equals(oldPin) && key.verify(signedMessage(), signature);
    }

    @Override
    public byte[] signature() {
        return signature.clone();
    }

    @Override
    public boolean equals(Object other) {
        return other instanceof RotationStatement that
            && serverId.equals(that.serverId)
            && oldPin.equals(that.oldPin)
            && newKey.equals(that.newKey)
            && issuedAt == that.issuedAt
            && Arrays.equals(signature, that.signature);
    }

    @Override
    public int hashCode() {
        return Objects.hash(serverId, oldPin, newKey, issuedAt, Arrays.hashCode(signature));
    }

    @Override
    public String toString() {
        return "RotationStatement[" + serverId.hex() + ", " + oldPin.hex() + " -> " + newKey.pin().hex()
            + ", issuedAt=" + issuedAt + "]";
    }
}
