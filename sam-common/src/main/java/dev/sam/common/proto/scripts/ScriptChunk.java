package dev.sam.common.proto.scripts;

import dev.sam.common.proto.ProtocolException;
import dev.sam.common.proto.SamReader;
import dev.sam.common.proto.SamWriter;
import dev.sam.common.scripts.ScriptPackage;

/**
 * {@code sam:script_chunk}, servidor → cliente (PROTOCOLO.md 5.5): un fragmento del paquete de un script;
 * el orden y los totales los exige {@link ScriptPackage.Assembler}. Como mucho {@value #MAX_BYTES} bytes.
 */
public record ScriptChunk(byte[] sha256, int index, int total, byte[] data) {

    public static final String ID = "script_chunk";
    public static final int MAX_BYTES = ScriptPackage.CHUNK + 64;

    public ScriptChunk {
        sha256 = Hashes.check(sha256);
        data = data.clone();
    }

    @Override
    public byte[] sha256() {
        return sha256.clone();
    }

    @Override
    public byte[] data() {
        return data.clone();
    }

    public void write(SamWriter out) {
        out.fixed(sha256, Hashes.LENGTH).varInt(index).varInt(total).bytes(data, ScriptPackage.CHUNK);
    }

    public static ScriptChunk read(SamReader in) {
        var sha256 = in.fixed(Hashes.LENGTH);
        var index = in.varInt();
        var total = in.varInt();
        var data = in.bytes(ScriptPackage.CHUNK);
        return ProtocolException.fromRead(() -> new ScriptChunk(sha256, index, total, data));
    }
}
