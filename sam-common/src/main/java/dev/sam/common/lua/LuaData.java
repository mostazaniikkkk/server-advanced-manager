package dev.sam.common.lua;

import static org.squiddev.cobalt.ValueFactory.valueOf;

import java.nio.ByteBuffer;

import org.squiddev.cobalt.Constants;
import org.squiddev.cobalt.LuaError;
import org.squiddev.cobalt.LuaTable;
import org.squiddev.cobalt.LuaValue;

import dev.sam.common.proto.ProtocolException;
import dev.sam.common.proto.SamReader;
import dev.sam.common.proto.SamWriter;
import io.netty.buffer.ByteBufUtil;
import io.netty.buffer.Unpooled;

/**
 * Los datos de {@code sam:lua_msg} (PROTOCOLO.md 8.5): copias de nil, booleanos, números finitos, textos
 * UTF-8 y tablas con claves de número o texto; como mucho 8 niveles, 256 pares y 4000 bytes. Nunca
 * funciones ni referencias: lo que llega es una tabla nueva (RS-LUA-02c).
 */
public final class LuaData {

    public static final int MAX_BYTES = 4000;
    private static final int MAX_DEPTH = 8;
    private static final int MAX_PAIRS = 256;
    private static final byte NIL = 0;
    private static final byte FALSE = 1;
    private static final byte TRUE = 2;
    private static final byte NUMBER = 3;
    private static final byte STRING = 4;
    private static final byte TABLE = 5;

    private LuaData() {
    }

    /** @throws LuaError con el motivo si el valor no se puede enviar */
    public static byte[] encode(LuaValue value) throws LuaError {
        var buf = Unpooled.buffer();
        try {
            write(new SamWriter(buf), value, 0, new int[1]);
        } catch (IllegalArgumentException e) {
            throw tooBig();
        }
        if (buf.readableBytes() > MAX_BYTES) {
            throw tooBig();
        }
        return ByteBufUtil.getBytes(buf);
    }

    /** @throws ProtocolException (SAM-P001) si no es un {@code LuaData} válido */
    public static LuaValue decode(byte[] bytes) {
        var pairs = new int[1];
        return SamReader.decode(Unpooled.wrappedBuffer(bytes), MAX_BYTES, in -> {
            try {
                return read(in, 0, pairs);
            } catch (LuaError e) {
                throw new ProtocolException(ProtocolException.MALFORMED, e.getMessage());
            }
        });
    }

    private static LuaError tooBig() {
        return new LuaError("los datos ocupan más de " + MAX_BYTES + " bytes");
    }

    private static void write(SamWriter out, LuaValue value, int depth, int[] pairs) throws LuaError {
        switch (value.type()) {
            case Constants.TNIL -> tag(out, NIL);
            case Constants.TBOOLEAN -> tag(out, value.toBoolean() ? TRUE : FALSE);
            case Constants.TNUMBER -> {
                var number = finite(value.toDouble());
                tag(out, NUMBER);
                out.fixed(ByteBuffer.allocate(8).putDouble(number).array(), 8);
            }
            case Constants.TSTRING -> {
                tag(out, STRING);
                out.string(LuaSandbox.text(value), MAX_BYTES);
            }
            case Constants.TTABLE -> {
                if (depth >= MAX_DEPTH) {
                    throw tooDeep();
                }
                var table = (LuaTable) value;
                var entries = new java.util.ArrayList<LuaValue[]>();
                LuaValue key = Constants.NIL;
                while (true) {
                    var next = table.next(key);
                    key = next.first();
                    if (key.isNil()) {
                        break;
                    }
                    checkKey(key.type(), key.typeName());
                    if (++pairs[0] > MAX_PAIRS) {
                        throw tooMany();
                    }
                    entries.add(new LuaValue[] {key, next.arg(2)});
                }
                tag(out, TABLE);
                out.varInt(entries.size());
                for (var entry : entries) {
                    write(out, entry[0], 0, pairs);
                    write(out, entry[1], depth + 1, pairs);
                }
            }
            default -> throw new LuaError("no se puede enviar un valor de tipo " + value.typeName());
        }
    }

    private static LuaValue read(SamReader in, int depth, int[] pairs) throws LuaError {
        var type = in.fixed(1)[0];
        return switch (type) {
            case NIL -> Constants.NIL;
            case FALSE -> Constants.FALSE;
            case TRUE -> Constants.TRUE;
            case NUMBER -> valueOf(finite(ByteBuffer.wrap(in.fixed(8)).getDouble()));
            case STRING -> LuaSandbox.lua(in.string(MAX_BYTES));
            case TABLE -> {
                if (depth >= MAX_DEPTH) {
                    throw tooDeep();
                }
                var size = in.varInt();
                var table = new LuaTable();
                for (var i = 0; i < size; i++) {
                    if (++pairs[0] > MAX_PAIRS) {
                        throw tooMany();
                    }
                    var key = readKey(in);
                    table.rawset(key, read(in, depth + 1, pairs));
                }
                yield table;
            }
            default -> throw new LuaError("tipo de dato " + type + " desconocido");
        };
    }

    /** Una clave: solo número o texto (no lleva anidamiento). */
    private static LuaValue readKey(SamReader in) throws LuaError {
        var type = in.fixed(1)[0];
        return switch (type) {
            case NUMBER -> valueOf(finite(ByteBuffer.wrap(in.fixed(8)).getDouble()));
            case STRING -> LuaSandbox.lua(in.string(MAX_BYTES));
            case NIL -> throw new LuaError("clave de tipo nil (solo número o texto)");
            case FALSE, TRUE -> throw new LuaError("clave de tipo boolean (solo número o texto)");
            case TABLE -> throw new LuaError("clave de tipo table (solo número o texto)");
            default -> throw new LuaError("tipo de dato " + type + " desconocido");
        };
    }

    private static void tag(SamWriter out, byte tag) {
        out.fixed(new byte[] {tag}, 1);
    }

    private static double finite(double number) throws LuaError {
        if (!Double.isFinite(number)) {
            throw new LuaError("número no finito");
        }
        return number;
    }

    private static void checkKey(int type, String name) throws LuaError {
        if (type != Constants.TNUMBER && type != Constants.TSTRING) {
            throw new LuaError("clave de tipo " + name + " (solo número o texto)");
        }
    }

    private static LuaError tooDeep() {
        return new LuaError("más de " + MAX_DEPTH + " niveles de tablas");
    }

    private static LuaError tooMany() {
        return new LuaError("más de " + MAX_PAIRS + " pares");
    }
}
