package dev.sam.common.proto.auth;

import dev.sam.common.proto.SamReader;
import dev.sam.common.proto.SamWriter;

/** {@code sam:hello_ack}, cliente → servidor (PROTOCOLO.md 5.1); como mucho {@value #MAX_BYTES} bytes (5.6). */
public record HelloAck(ProtocolVersion protocol, String clientVersion, byte[] devicePub) {

    public static final String ID = "hello_ack";
    public static final int MAX_BYTES = 512;

    private static final int MAX_VERSION = 32;
    private static final int DEVICE_PUB_LENGTH = 32;

    public HelloAck {
        if (devicePub.length != DEVICE_PUB_LENGTH) {
            throw new IllegalArgumentException("device_pub debe tener 32 bytes");
        }
    }

    public void write(SamWriter out) {
        protocol.write(out);
        out.string(clientVersion, MAX_VERSION).fixed(devicePub, DEVICE_PUB_LENGTH);
    }

    public static HelloAck read(SamReader in) {
        var protocol = ProtocolVersion.read(in);
        var clientVersion = in.string(MAX_VERSION);
        return new HelloAck(protocol, clientVersion, in.fixed(DEVICE_PUB_LENGTH));
    }
}
