package dev.sam.common.proto.scripts;

import java.util.List;

import dev.sam.common.proto.SamReader;
import dev.sam.common.proto.SamWriter;

/**
 * {@code sam:scripts_consent}, cliente → servidor (PROTOCOLO.md 5.5): los ids de los scripts que el
 * jugador aceptó en la pantalla de consentimiento. Como mucho {@value #MAX_BYTES} bytes.
 */
public record ScriptsConsent(List<String> accepted) {

    public static final String ID = "scripts_consent";
    public static final int MAX_BYTES = 8704;

    public ScriptsConsent {
        accepted = List.copyOf(accepted);
    }

    public void write(SamWriter out) {
        out.list(accepted, ScriptsOffer.MAX_SCRIPTS, (w, id) -> w.string(id, ScriptRef.MAX_ID));
    }

    public static ScriptsConsent read(SamReader in) {
        return new ScriptsConsent(in.list(ScriptsOffer.MAX_SCRIPTS, r -> r.string(ScriptRef.MAX_ID)));
    }
}
