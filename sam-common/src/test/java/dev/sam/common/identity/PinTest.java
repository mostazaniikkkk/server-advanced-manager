package dev.sam.common.identity;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.nio.charset.StandardCharsets;
import java.util.HexFormat;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import net.jqwik.api.ForAll;
import net.jqwik.api.Property;
import net.jqwik.api.constraints.Size;

/** PROTOCOLO.md 3.3 (P-04): el pin es SHA-256 de la SubjectPublicKeyInfo del servidor. */
class PinTest {

    @Test
    void ofSpkiEsElSha256DeLaClavePublica() {
        // Vector FIPS 180: SHA-256("abc")
        var pin = Pin.ofSpki("abc".getBytes(StandardCharsets.US_ASCII));
        assertThat(pin.hex()).isEqualTo("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    }

    @ParameterizedTest
    @ValueSource(ints = {0, 16, 31, 33})
    void rechazaLongitudesDistintasDe32(int longitud) {
        assertThatThrownBy(() -> Pin.of(new byte[longitud]))
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessageContaining("32");
    }

    @Test
    void esInmutable() {
        var bytes = new byte[32];
        var pin = Pin.of(bytes);
        bytes[0] = 1;
        pin.toBytes()[1] = 1;
        assertThat(pin.toBytes()).containsOnly((byte) 0);
    }

    @Test
    void igualdadPorValor() {
        var a = Pin.of(new byte[32]);
        var b = Pin.of(new byte[32]);
        var otroBytes = new byte[32];
        otroBytes[31] = 1;
        var c = Pin.of(otroBytes);
        assertThat(a).isEqualTo(b).hasSameHashCodeAs(b).isNotEqualTo(c).isNotEqualTo(null).isNotEqualTo("x");
        assertThat(a.hashCode()).isNotEqualTo(c.hashCode());
    }

    @Test
    void toStringMuestraElHex() {
        assertThat(Pin.of(new byte[32]).toString()).contains("0000000000000000000000000000000000000000000000000000000000000000");
    }

    @Property
    void hexIdaYVuelta(@ForAll @Size(32) byte[] bytes) {
        var pin = Pin.of(bytes);
        assertThat(Pin.fromHex(pin.hex())).isEqualTo(pin);
        assertThat(pin.hex()).isEqualTo(HexFormat.of().formatHex(bytes));
    }

    @ParameterizedTest
    @ValueSource(strings = {"", "00", "zz00000000000000000000000000000000000000000000000000000000000000"})
    void rechazaHexInvalido(String hex) {
        assertThatThrownBy(() -> Pin.fromHex(hex)).isInstanceOf(IllegalArgumentException.class);
    }
}
