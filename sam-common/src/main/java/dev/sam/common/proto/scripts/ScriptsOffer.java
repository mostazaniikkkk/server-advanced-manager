package dev.sam.common.proto.scripts;

import java.util.List;

import dev.sam.common.proto.SamReader;
import dev.sam.common.proto.SamWriter;
import dev.sam.common.scripts.SignedBlob;

/**
 * {@code sam:scripts_offer}, servidor → cliente (PROTOCOLO.md 5.5): la keylist firmada por la identidad
 * del servidor y los scripts que ofrece. Como mucho {@value #MAX_BYTES} bytes.
 */
public record ScriptsOffer(SignedBlob keylist, List<ScriptRef> scripts) {

    public static final String ID = "scripts_offer";
    public static final int MAX_BYTES = 320 * 1024;
    static final int MAX_SCRIPTS = 128;

    public ScriptsOffer {
        if (scripts.size() > MAX_SCRIPTS) {
            throw new IllegalArgumentException("largo " + scripts.size() + " fuera de 0.." + MAX_SCRIPTS);
        }
        scripts = List.copyOf(scripts);
    }

    public void write(SamWriter out) {
        keylist.write(out);
        out.list(scripts, MAX_SCRIPTS, (w, ref) -> ref.write(w));
    }

    public static ScriptsOffer read(SamReader in) {
        var keylist = SignedBlob.read(in);
        return new ScriptsOffer(keylist, in.list(MAX_SCRIPTS, ScriptRef::read));
    }
}
