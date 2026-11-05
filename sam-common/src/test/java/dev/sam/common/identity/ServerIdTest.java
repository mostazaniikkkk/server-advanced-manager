package dev.sam.common.identity;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import net.jqwik.api.ForAll;
import net.jqwik.api.Property;
import net.jqwik.api.constraints.Size;

/** PROTOCOLO.md 3.1: el server_id son exactamente 16 bytes y se representa en hex (32 caracteres). */
class ServerIdTest {

    @ParameterizedTest
    @ValueSource(ints = {0, 1, 15, 17, 32})
    void rechazaLongitudesDistintasDe16(int longitud) {
        assertThatThrownBy(() -> ServerId.of(new byte[longitud]))
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessageContaining("16");
    }

    @Test
    void conservaLosBytesYSuHex() {
        var id = ServerId.of(serverIdBytes(0x01));
        assertThat(id.toBytes()).containsExactly(serverIdBytes(0x01));
        assertThat(id.hex()).isEqualTo("00000000000000000000000000000001");
    }

    @Test
    void esInmuneAModificacionesDelArregloOriginal() {
        var original = serverIdBytes(0x01);
        var id = ServerId.of(original);
        original[15] = 0x7F;
        assertThat(id.toBytes()[15]).isEqualTo((byte) 0x01);
    }

    @Test
    void esInmuneAModificacionesDelArregloDevuelto() {
        var id = ServerId.of(serverIdBytes(0x01));
        id.toBytes()[15] = 0x7F;
        assertThat(id.toBytes()[15]).isEqualTo((byte) 0x01);
    }

    @Test
    void dosIdsConLosMismosBytesSonIguales() {
        var a = ServerId.of(serverIdBytes(0x05));
        var b = ServerId.of(serverIdBytes(0x05));
        var c = ServerId.of(serverIdBytes(0x06));
        assertThat(a).isEqualTo(b).hasSameHashCodeAs(b).isNotEqualTo(c);
        assertThat(a).isNotEqualTo(null).isNotEqualTo("00000000000000000000000000000005");
    }

    @Test
    void idsDistintosTienenHashesDistintos() {
        // No es una garantía general (puede haber colisiones), pero estos casos no colisionan:
        // un hashCode constante degradaría los HashMap de pins a listas.
        var hashes = java.util.stream.IntStream.range(0, 32)
            .mapToObj(i -> ServerId.of(serverIdBytes(i)).hashCode())
            .distinct()
            .count();
        assertThat(hashes).isEqualTo(32);
    }

    @Test
    void seParseaDesdeHexEnMayusculasOMinusculas() {
        assertThat(ServerId.fromHex("0000000000000000000000000000ABcd").toBytes())
            .endsWith((byte) 0xAB, (byte) 0xCD);
    }

    @ParameterizedTest
    @ValueSource(strings = {"", "00", "0000000000000000000000000000000", "000000000000000000000000000000001",
        "0000000000000000000000000000000g", "0x000000000000000000000000000001"})
    void rechazaHexInvalido(String hex) {
        assertThatThrownBy(() -> ServerId.fromHex(hex)).isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void toStringMuestraElHex() {
        assertThat(ServerId.of(serverIdBytes(0x01)).toString()).contains("00000000000000000000000000000001");
    }

    @Property
    void hexIdaYVuelta(@ForAll @Size(16) byte[] bytes) {
        var id = ServerId.of(bytes);
        assertThat(ServerId.fromHex(id.hex())).isEqualTo(id);
        assertThat(id.hex()).hasSize(32).matches("[0-9a-f]+");
    }

    static byte[] serverIdBytes(int ultimo) {
        var bytes = new byte[16];
        bytes[15] = (byte) ultimo;
        return bytes;
    }
}
