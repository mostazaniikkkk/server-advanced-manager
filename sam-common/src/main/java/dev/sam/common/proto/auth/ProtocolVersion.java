package dev.sam.common.proto.auth;

import dev.sam.common.proto.ProtocolException;
import dev.sam.common.proto.SamReader;
import dev.sam.common.proto.SamWriter;

/** Versión del protocolo SAM (PROTOCOLO.md 4.3): mayor y menor, cada una en 0..255. */
public record ProtocolVersion(int major, int minor) {

    public static final ProtocolVersion CURRENT = new ProtocolVersion(1, 0);

    private static final int MAX = 255;

    public ProtocolVersion {
        if (major < 0 || major > MAX || minor < 0 || minor > MAX) {
            throw new IllegalArgumentException("versión " + major + "." + minor + " fuera de rango");
        }
    }

    void write(SamWriter out) {
        out.varInt(major).varInt(minor);
    }

    static ProtocolVersion read(SamReader in) {
        var major = in.varInt();
        var minor = in.varInt();
        return ProtocolException.fromRead(() -> new ProtocolVersion(major, minor));
    }
}
