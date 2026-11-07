package dev.sam.common.lua;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.squiddev.cobalt.ValueFactory.valueOf;

import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.Map;

import org.junit.jupiter.api.Test;
import org.squiddev.cobalt.Constants;
import org.squiddev.cobalt.LuaError;
import org.squiddev.cobalt.LuaTable;
import org.squiddev.cobalt.LuaValue;

import dev.sam.common.proto.ProtocolException;

/**
 * {@code LuaData} (PROTOCOLO.md 8.5): los datos de {@code sam:lua_msg} son copias de valores de Lua, sin
 * funciones ni referencias, con tope de anidamiento, de pares y de tamaño.
 */
class LuaDataTest {

    /** Un valor de Lua como Java, para comparar (las tablas de Cobalt se comparan por identidad). */
    private static Object java(LuaValue value) throws LuaError {
        return switch (value.type()) {
            case Constants.TNIL -> null;
            case Constants.TBOOLEAN -> value.toBoolean();
            case Constants.TNUMBER -> value.toDouble();
            case Constants.TSTRING -> LuaSandbox.text(value);
            default -> {
                var map = new LinkedHashMap<Object, Object>();
                var table = (LuaTable) value;
                LuaValue key = Constants.NIL;
                while (true) {
                    var next = table.next(key);
                    key = next.first();
                    if (key.isNil()) {
                        break;
                    }
                    map.put(java(key), java(next.arg(2)));
                }
                yield map;
            }
        };
    }

    private static String hex(LuaValue value) throws LuaError {
        return HexFormat.of().formatHex(LuaData.encode(value));
    }

    @Test
    void cadaTipoTieneSuCodificacion() throws Exception {
        assertThat(hex(Constants.NIL)).isEqualTo("00");
        assertThat(hex(Constants.FALSE)).isEqualTo("01");
        assertThat(hex(Constants.TRUE)).isEqualTo("02");
        assertThat(hex(valueOf(1.5))).isEqualTo("033ff8000000000000");
        assertThat(hex(LuaSandbox.lua("ñ"))).isEqualTo("0402c3b1");
        var tabla = new LuaTable();
        tabla.rawset(1, Constants.TRUE);
        assertThat(hex(tabla)).isEqualTo("0501033ff000000000000002");
    }

    @Test
    void losValoresVanYVuelven() throws Exception {
        var interna = new LuaTable();
        interna.rawset("vida", valueOf(20));
        interna.rawset("nombre", LuaSandbox.lua("Steve ñandú"));
        var tabla = new LuaTable();
        tabla.rawset(1, interna);
        tabla.rawset("ok", Constants.TRUE);
        tabla.rawset("pi", valueOf(3.25));
        var vuelta = java(LuaData.decode(LuaData.encode(tabla)));
        assertThat(vuelta).isEqualTo(Map.of(1.0, Map.of("vida", 20.0, "nombre", "Steve ñandú"), "ok", true, "pi", 3.25));
        assertThat(java(LuaData.decode(new byte[] {0}))).isNull();
        assertThat(java(LuaData.decode(new byte[] {1}))).isEqualTo(false);
    }

    @Test
    void loQueNoEsUnDatoNoSeEnvia() throws Exception {
        var ciclo = new LuaTable();
        ciclo.rawset("yo", ciclo);
        assertThatThrownBy(() -> LuaData.encode(ciclo)).isInstanceOf(LuaError.class).hasMessageContaining("más de 8 niveles de tablas");
        assertThatThrownBy(() -> LuaData.encode(valueOf(Double.NaN))).isInstanceOf(LuaError.class).hasMessageContaining("número no finito");
        assertThatThrownBy(() -> LuaData.encode(valueOf(Double.POSITIVE_INFINITY))).isInstanceOf(LuaError.class);
        var claveRara = new LuaTable();
        claveRara.rawset(Constants.TRUE, valueOf(1));
        assertThatThrownBy(() -> LuaData.encode(claveRara)).isInstanceOf(LuaError.class).hasMessageContaining("clave de tipo boolean");
        var muchos = new LuaTable();
        for (var i = 1; i <= 257; i++) {
            muchos.rawset(i, Constants.TRUE);
        }
        assertThatThrownBy(() -> LuaData.encode(muchos)).isInstanceOf(LuaError.class).hasMessageContaining("más de 256 pares");
        var grande = new LuaTable();
        grande.rawset(1, LuaSandbox.lua("x".repeat(2000)));
        grande.rawset(2, LuaSandbox.lua("x".repeat(2000)));
        assertThatThrownBy(() -> LuaData.encode(grande)).isInstanceOf(LuaError.class).hasMessageContaining("más de 4000 bytes");
        // Los topes justos valen: 8 niveles, 256 pares, 4000 bytes
        var nivel = new LuaTable();
        var raiz = nivel;
        for (var i = 1; i < 8; i++) {
            var hijo = new LuaTable();
            nivel.rawset(1, hijo);
            nivel = hijo;
        }
        assertThat(LuaData.decode(LuaData.encode(raiz))).isNotNull();
        var noveno = new LuaTable();
        nivel.rawset(1, noveno);
        assertThatThrownBy(() -> LuaData.encode(raiz)).isInstanceOf(LuaError.class).hasMessageContaining("más de 8 niveles de tablas");
        var justos = new LuaTable();
        for (var i = 1; i <= 256; i++) {
            justos.rawset(i, Constants.TRUE);
        }
        assertThat(java(LuaData.decode(LuaData.encode(justos)))).asInstanceOf(org.assertj.core.api.InstanceOfAssertFactories.MAP).hasSize(256);
        assertThat(LuaData.encode(LuaSandbox.lua("x".repeat(3997)))).hasSize(4000);
        assertThatThrownBy(() -> LuaData.encode(LuaSandbox.lua("x".repeat(3998)))).isInstanceOf(LuaError.class);
    }

    @Test
    void loRecibidoSeValidaIgual() throws Exception {
        malFormado(new byte[] {7}, "tipo de dato 7 desconocido");
        malFormado(HexFormat.of().parseHex("037ff8000000000000"), "número no finito");
        malFormado(HexFormat.of().parseHex("05010102"), "clave de tipo boolean");
        malFormado(HexFormat.of().parseHex("0501050002"), "clave de tipo table");
        malFormado(HexFormat.of().parseHex("05010002"), "clave de tipo nil");
        malFormado(HexFormat.of().parseHex("05010202"), "clave de tipo boolean");
        malFormado(HexFormat.of().parseHex("05010902"), "tipo de dato 9 desconocido");
        malFormado(HexFormat.of().parseHex("0501037ff800000000000002"), "número no finito");
        assertThat(java(LuaData.decode(HexFormat.of().parseHex("050104016102")))).isEqualTo(Map.of("a", true));
        malFormado(HexFormat.of().parseHex("0502"), "mensaje incompleto");
        malFormado(HexFormat.of().parseHex("0000"), "sobran 1 bytes al final del mensaje");
        // Nueve niveles anidados
        var nueve = new StringBuilder();
        for (var i = 0; i < 9; i++) {
            nueve.append("0501033ff0000000000000");
        }
        nueve.append("00");
        malFormado(HexFormat.of().parseHex(nueve.toString()), "más de 8 niveles de tablas");
        // 257 pares en total: una tabla de 2 pares cuyo segundo valor es una tabla de 255
        malFormado(tablaCon(255, 2), "más de 256 pares");
        assertThat(java(LuaData.decode(tablaCon(254, 2)))).isNotNull();
        assertThatThrownBy(() -> LuaData.decode(new byte[4001])).isInstanceOf(ProtocolException.class);
    }

    /** Una tabla de {@code externos} pares; el último valor es una tabla de {@code internos} pares. */
    private static byte[] tablaCon(int internos, int externos) {
        var buf = io.netty.buffer.Unpooled.buffer();
        var w = new dev.sam.common.proto.SamWriter(buf);
        w.fixed(new byte[] {5}, 1).varInt(externos);
        for (var i = 1; i < externos; i++) {
            numero(w, i);
            w.fixed(new byte[] {2}, 1);
        }
        numero(w, externos);
        w.fixed(new byte[] {5}, 1).varInt(internos);
        for (var i = 1; i <= internos; i++) {
            numero(w, i);
            w.fixed(new byte[] {1}, 1);
        }
        return io.netty.buffer.ByteBufUtil.getBytes(buf);
    }

    private static void numero(dev.sam.common.proto.SamWriter w, double valor) {
        w.fixed(new byte[] {3}, 1).fixed(java.nio.ByteBuffer.allocate(8).putDouble(valor).array(), 8);
    }

    private static void malFormado(byte[] bytes, String detalle) {
        var error = assertThatThrownBy(() -> LuaData.decode(bytes)).isInstanceOfSatisfying(ProtocolException.class,
            e -> assertThat(e.code()).isEqualTo("SAM-P001"));
        if (detalle != null) {
            error.hasMessageContaining(detalle);
        }
    }
}
