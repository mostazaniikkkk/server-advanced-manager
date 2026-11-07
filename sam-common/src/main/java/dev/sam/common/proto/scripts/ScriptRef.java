package dev.sam.common.proto.scripts;

import java.util.List;

import dev.sam.common.proto.ProtocolException;
import dev.sam.common.proto.SamReader;
import dev.sam.common.proto.SamWriter;
import dev.sam.common.scripts.ScriptPackage;

/**
 * Un script que el servidor ofrece al cliente en {@code sam:scripts_offer} (PROTOCOLO.md 5.5): lo identifica
 * el {@code sha256} de su paquete; {@code size} es el largo de ese paquete.
 */
public record ScriptRef(String id, String version, byte[] sha256, int size, boolean required, List<String> caps) {

    public static final int MAX_SIZE = ScriptPackage.MAX_PACKAGE;
    static final int MAX_ID = 64;
    private static final int MAX_VERSION = 32;
    private static final int MAX_CAPS = 32;
    private static final int MAX_CAP = 48;

    public ScriptRef {
        sha256 = Hashes.check(sha256);
        if (size < 0 || size > MAX_SIZE) {
            throw new IllegalArgumentException("tamaño " + size + " fuera de 0.." + MAX_SIZE);
        }
        caps = List.copyOf(caps);
    }

    @Override
    public byte[] sha256() {
        return sha256.clone();
    }

    public void write(SamWriter out) {
        out.string(id, MAX_ID).string(version, MAX_VERSION).fixed(sha256, Hashes.LENGTH).varInt(size).bool(required)
            .list(caps, MAX_CAPS, (w, cap) -> w.string(cap, MAX_CAP));
    }

    public static ScriptRef read(SamReader in) {
        var id = in.string(MAX_ID);
        var version = in.string(MAX_VERSION);
        var sha256 = in.fixed(Hashes.LENGTH);
        var size = in.varInt();
        var required = in.bool();
        var caps = in.list(MAX_CAPS, r -> r.string(MAX_CAP));
        return ProtocolException.fromRead(() -> new ScriptRef(id, version, sha256, size, required, caps));
    }
}
