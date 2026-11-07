package dev.sam.common.proto.scripts;

import dev.sam.common.proto.SamReader;
import dev.sam.common.proto.SamWriter;

/**
 * {@code sam:lua_msg}, en ambas direcciones en la fase play (PROTOCOLO.md 5.7): un mensaje entre las dos
 * partes de un mismo script, por un canal; {@code data} es un {@code LuaData} (8.5).
 */
public record LuaMessage(String script, String channel, byte[] data) {

    public static final String ID = "lua_msg";
    public static final int MAX_BYTES = 4096;
    private static final int MAX_NAME = 32;
    private static final int MAX_DATA = 4000;

    public LuaMessage {
        data = data.clone();
    }

    @Override
    public byte[] data() {
        return data.clone();
    }

    public void write(SamWriter out) {
        out.string(script, MAX_NAME).string(channel, MAX_NAME).bytes(data, MAX_DATA);
    }

    public static LuaMessage read(SamReader in) {
        return new LuaMessage(in.string(MAX_NAME), in.string(MAX_NAME), in.bytes(MAX_DATA));
    }
}
