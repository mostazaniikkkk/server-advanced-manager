package dev.sam.common.scripts;

import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.Signature;
import java.util.Objects;

import dev.sam.common.identity.ServerPublicKey;
import dev.sam.common.proto.ProtocolException;
import dev.sam.common.proto.SamReader;
import dev.sam.common.proto.SamWriter;

/**
 * Un contenido firmado por la identidad del servidor (PROTOCOLO.md 8.1): hoy, la lista de claves de firma
 * de scripts autorizadas. El cliente lo verifica con la clave que tiene fijada.
 */
public record SignedBlob(String type, int version, long issuedAt, byte[] body, byte[] signature) {

    public static final int MAX_BODY = 64 * 1024;
    private static final int MAX_TYPE = 32;
    private static final int SIGNATURE_LENGTH = 64;
    private static final byte[] DOMAIN = "SAM-blob-v1".getBytes(StandardCharsets.UTF_8);

    public SignedBlob {
        Objects.requireNonNull(type, "type");
        if (body.length > MAX_BODY) {
            throw new IllegalArgumentException("body supera 64 KiB");
        }
        if (signature.length != SIGNATURE_LENGTH) {
            throw new IllegalArgumentException("la firma debe medir 64 bytes");
        }
        body = body.clone();
        signature = signature.clone();
    }

    /** Firma con la clave privada de la identidad del servidor (Ed25519 de la JDK). */
    public static SignedBlob sign(String type, int version, long issuedAt, byte[] body, PrivateKey key) {
        try {
            var signer = Signature.getInstance("Ed25519");
            signer.initSign(key);
            signer.update(message(type, version, issuedAt, body));
            return new SignedBlob(type, version, issuedAt, body, signer.sign());
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("la identidad del servidor es Ed25519", e);
        }
    }

    public boolean verify(ServerPublicKey key) {
        return key.verify(message(type, version, issuedAt, body), signature);
    }

    public void write(SamWriter out) {
        out.string(type, MAX_TYPE).varInt(version).fixed(ByteBuffer.allocate(8).putLong(issuedAt).array(), 8)
            .bytes(body, MAX_BODY).fixed(signature, SIGNATURE_LENGTH);
    }

    public static SignedBlob read(SamReader in) {
        var type = in.string(MAX_TYPE);
        var version = in.varInt();
        var issuedAt = ByteBuffer.wrap(in.fixed(8)).getLong();
        var body = in.bytes(MAX_BODY);
        var signature = in.fixed(SIGNATURE_LENGTH);
        return ProtocolException.fromRead(() -> new SignedBlob(type, version, issuedAt, body, signature));
    }

    @Override
    public byte[] body() {
        return body.clone();
    }

    @Override
    public byte[] signature() {
        return signature.clone();
    }

    /** UTF-8("SAM-blob-v1") ‖ UTF-8(type) ‖ 0x00 ‖ Int32 BE(version) ‖ Int64 BE(issued_at) ‖ body. */
    private static byte[] message(String type, int version, long issuedAt, byte[] body) {
        var out = new ByteArrayOutputStream();
        out.writeBytes(DOMAIN);
        out.writeBytes(type.getBytes(StandardCharsets.UTF_8));
        out.write(0);
        out.writeBytes(ByteBuffer.allocate(12).putInt(version).putLong(issuedAt).array());
        out.writeBytes(body);
        return out.toByteArray();
    }
}
