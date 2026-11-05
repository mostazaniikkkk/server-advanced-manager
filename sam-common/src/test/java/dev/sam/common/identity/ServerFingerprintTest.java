package dev.sam.common.identity;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.security.MessageDigest;
import java.util.HexFormat;
import java.util.List;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import net.jqwik.api.ForAll;
import net.jqwik.api.Property;
import net.jqwik.api.constraints.IntRange;
import net.jqwik.api.constraints.Size;

/**
 * RN-42 / PROTOCOLO.md 3.5 (P-07): huella visual del certificado del servidor.
 *
 * <p>Vectores calculados con una implementación de referencia en Python, independiente de esta.
 */
class ServerFingerprintTest {

    private static final byte[] PIN_A = HexFormat.of().parseHex(
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
    private static final byte[] PIN_B = HexFormat.of().parseHex(
        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
    private static final byte[] PIN_C = HexFormat.of().parseHex(
        "e96e02d8e47f2a7c03be5117b3ed175c52aa30fb22028cf9c96f261563577605");

    // ===== Vectores =====

    @Test
    void vectorPinA() {
        var huella = ServerFingerprint.of(PIN_A);
        assertThat(huella.words()).containsExactly("satán", "testigo", "chupar");
        assertThat(huella.hex()).isEqualTo("0001 0203 0405 0607 0809 0A0B 0C0D 0E0F");
        assertThat(huella.identicon().cellMask()).isEqualTo(0x456d40);
        assertThat(huella.identicon().rgb()).isEqualTo(0x4527A0);
        assertThat(dibujo(huella.identicon())).containsExactly(".....", ".#.#.", "##.##", ".#.#.", "..#..");
    }

    @Test
    void vectorPinB() {
        var huella = ServerFingerprint.of(PIN_B);
        assertThat(huella.words()).containsExactly("culpa", "oír", "leal");
        assertThat(huella.hex()).isEqualTo("FFFF FFFF FFFF FFFF FFFF FFFF FFFF FFFF");
        assertThat(huella.identicon().cellMask()).isEqualTo(0x80);
        assertThat(huella.identicon().rgb()).isEqualTo(0x1565C0);
    }

    @Test
    void vectorPinC() {
        var huella = ServerFingerprint.of(PIN_C);
        assertThat(huella.words()).containsExactly("náusea", "ducha", "límite");
        assertThat(huella.hex()).isEqualTo("E96E 02D8 E47F 2A7C 03BE 5117 B3ED 175C");
        assertThat(huella.identicon().cellMask()).isEqualTo(0xa8fc84);
        assertThat(huella.identicon().rgb()).isEqualTo(0x00695C);
        assertThat(dibujo(huella.identicon())).containsExactly("..#..", "..#..", "#####", "#...#", ".#.#.");
    }

    @Test
    void laFraseSeArmaConPuntosMedios() {
        assertThat(ServerFingerprint.of(PIN_C).phrase()).isEqualTo("náusea · ducha · límite");
    }

    // ===== Validación e inmutabilidad =====

    @ParameterizedTest
    @ValueSource(ints = {0, 16, 31, 33, 64})
    void rechazaPinsQueNoMiden32Bytes(int longitud) {
        assertThatThrownBy(() -> ServerFingerprint.of(new byte[longitud]))
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessageContaining("32");
    }

    @Test
    void lasPalabrasNoSePuedenModificar() {
        assertThatThrownBy(() -> ServerFingerprint.of(PIN_A).words().set(0, "x"))
            .isInstanceOf(UnsupportedOperationException.class);
    }

    @Test
    void dosHuellasDelMismoPinSonIguales() {
        assertThat(ServerFingerprint.of(PIN_C)).isEqualTo(ServerFingerprint.of(PIN_C.clone()));
    }

    @ParameterizedTest
    @ValueSource(ints = {-1, 5})
    void consultarUnaCeldaFueraDeLaCuadriculaFalla(int fueraDeRango) {
        var identicon = ServerFingerprint.of(PIN_A).identicon();
        assertThatThrownBy(() -> identicon.isFilled(fueraDeRango, 0)).isInstanceOf(IndexOutOfBoundsException.class);
        assertThatThrownBy(() -> identicon.isFilled(0, fueraDeRango)).isInstanceOf(IndexOutOfBoundsException.class);
    }

    @Test
    void laPaletaTiene16ColoresDistintos() {
        assertThat(Identicon.PALETTE).hasSize(16).doesNotHaveDuplicates();
    }

    // ===== Propiedades =====

    @Property
    void elIdenticonEsSimetricoDeIzquierdaADerecha(
            @ForAll @Size(32) byte[] pin, @ForAll @IntRange(max = 4) int fila, @ForAll @IntRange(max = 4) int columna) {
        var identicon = ServerFingerprint.of(pin).identicon();
        assertThat(identicon.isFilled(fila, columna)).isEqualTo(identicon.isFilled(fila, 4 - columna));
    }

    @Property
    void siempreHayTresPalabrasDeLaLista(@ForAll @Size(32) byte[] pin) {
        var huella = ServerFingerprint.of(pin);
        assertThat(huella.words()).hasSize(3);
        assertThat(Wordlist.spanish()).containsAll(huella.words());
    }

    @Property
    void elColorSiempreEsDeLaPaleta(@ForAll @Size(32) byte[] pin) {
        assertThat(Identicon.PALETTE).contains(ServerFingerprint.of(pin).identicon().rgb());
    }

    @Property
    void elHexSonLosPrimeros16BytesDelPinEnOchoGrupos(@ForAll @Size(32) byte[] pin) {
        var hex = ServerFingerprint.of(pin).hex();
        assertThat(hex).matches("([0-9A-F]{4} ){7}[0-9A-F]{4}");
        assertThat(hex.replace(" ", "")).isEqualToIgnoringCase(HexFormat.of().formatHex(pin, 0, 16));
    }

    @Property
    void cambiarCualquierByteDelPinCambiaLaHuella(@ForAll @Size(32) byte[] pin, @ForAll @IntRange(max = 31) int posicion) throws Exception {
        var otro = pin.clone();
        otro[posicion] ^= 0x01;
        // Con 33 bits de palabras + 15 de celdas + 4 de color, una colisión es astronómicamente improbable
        // salvo que el SHA-256 de ambos coincida en los primeros 8 bytes.
        var h1 = MessageDigest.getInstance("SHA-256").digest(concat("SAM-fp-v1".getBytes(), pin));
        var h2 = MessageDigest.getInstance("SHA-256").digest(concat("SAM-fp-v1".getBytes(), otro));
        if (java.util.Arrays.equals(h1, 0, 8, h2, 0, 8)) {
            return;
        }
        assertThat(ServerFingerprint.of(otro)).isNotEqualTo(ServerFingerprint.of(pin));
    }

    private static List<String> dibujo(Identicon identicon) {
        var filas = new java.util.ArrayList<String>();
        for (int r = 0; r < Identicon.SIZE; r++) {
            var fila = new StringBuilder();
            for (int c = 0; c < Identicon.SIZE; c++) {
                fila.append(identicon.isFilled(r, c) ? '#' : '.');
            }
            filas.add(fila.toString());
        }
        return filas;
    }

    private static byte[] concat(byte[] a, byte[] b) {
        var out = java.util.Arrays.copyOf(a, a.length + b.length);
        System.arraycopy(b, 0, out, a.length, b.length);
        return out;
    }
}
