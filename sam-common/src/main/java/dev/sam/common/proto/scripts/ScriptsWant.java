package dev.sam.common.proto.scripts;

import java.util.List;

import dev.sam.common.proto.ProtocolException;
import dev.sam.common.proto.SamReader;
import dev.sam.common.proto.SamWriter;

/**
 * {@code sam:scripts_want}, cliente → servidor (PROTOCOLO.md 5.5): los paquetes ofrecidos que el cliente no
 * tiene en caché. Como mucho {@value #MAX_BYTES} bytes.
 */
public record ScriptsWant(List<byte[]> hashes) {

    public static final String ID = "scripts_want";
    public static final int MAX_BYTES = 4608;

    public ScriptsWant {
        hashes = hashes.stream().map(Hashes::check).toList();
    }

    @Override
    public List<byte[]> hashes() {
        return hashes.stream().map(byte[]::clone).toList();
    }

    public void write(SamWriter out) {
        out.list(hashes, ScriptsOffer.MAX_SCRIPTS, (w, h) -> w.fixed(h, Hashes.LENGTH));
    }

    public static ScriptsWant read(SamReader in) {
        var hashes = in.list(ScriptsOffer.MAX_SCRIPTS, r -> r.fixed(Hashes.LENGTH));
        return ProtocolException.fromRead(() -> new ScriptsWant(hashes));
    }
}
