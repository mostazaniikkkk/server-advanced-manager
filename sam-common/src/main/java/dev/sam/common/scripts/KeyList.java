package dev.sam.common.scripts;

import java.security.PrivateKey;
import java.util.HexFormat;
import java.util.List;
import java.util.Optional;

import dev.sam.common.identity.ServerPublicKey;
import dev.sam.common.proto.ProtocolException;
import dev.sam.common.proto.SamReader;
import dev.sam.common.proto.SamWriter;
import io.netty.buffer.ByteBufUtil;
import io.netty.buffer.Unpooled;

/**
 * La lista de claves de firma de scripts autorizadas por el servidor (PROTOCOLO.md 8.1, RS-SIG-05): la
 * firma su identidad, así el cliente acepta un script solo si (a) lo firmó una clave de esta lista y (b) la
 * lista la firmó el servidor que tiene fijado.
 */
public final class KeyList {

    public static final String TYPE = "keylist";
    public static final int VERSION = 1;
    private static final int MAX_KEYS = 64;
    private static final int MAX_LABEL = 64;

    /** Una clave autorizada y su etiqueta (el nombre del {@code .pub}), para el consentimiento. */
    public record Entry(SigningPublicKey key, String label) {
    }

    private KeyList() {
    }

    /** @throws IllegalArgumentException si hay más de 64 claves o una etiqueta demasiado larga */
    public static SignedBlob issue(List<Entry> keys, PrivateKey identity, long issuedAt) {
        var buf = Unpooled.buffer();
        new SamWriter(buf).list(keys, MAX_KEYS, (w, entry) -> w.fixed(HexFormat.of().parseHex(entry.key().keyId().hex()), 8)
            .fixed(entry.key().raw(), 32).string(entry.label(), MAX_LABEL));
        return SignedBlob.sign(TYPE, VERSION, issuedAt, ByteBufUtil.getBytes(buf), identity);
    }

    /** Las claves de la lista, solo si la firmó esa identidad y su contenido es válido. */
    public static Optional<List<Entry>> verify(SignedBlob blob, ServerPublicKey identity) {
        if (!blob.type().equals(TYPE) || !blob.verify(identity)) {
            return Optional.empty();
        }
        try {
            return Optional.of(SamReader.decode(Unpooled.wrappedBuffer(blob.body()), SignedBlob.MAX_BODY,
                in -> in.list(MAX_KEYS, KeyList::entry)));
        } catch (ProtocolException e) {
            return Optional.empty();
        }
    }

    private static Entry entry(SamReader in) {
        var keyId = HexFormat.of().formatHex(in.fixed(8));
        var raw = in.fixed(32);
        var label = in.string(MAX_LABEL);
        return ProtocolException.fromRead(() -> {
            var key = SigningPublicKey.of(raw);
            if (!key.keyId().hex().equals(keyId)) {
                throw new IllegalArgumentException("key_id no corresponde a la clave");
            }
            return new Entry(key, label);
        });
    }
}
