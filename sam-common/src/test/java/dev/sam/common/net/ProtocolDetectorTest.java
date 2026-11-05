package dev.sam.common.net;

import static dev.sam.common.net.ProtocolDetector.Classification.HTTP;
import static dev.sam.common.net.ProtocolDetector.Classification.LEGACY_PING;
import static dev.sam.common.net.ProtocolDetector.Classification.NEED_MORE;
import static dev.sam.common.net.ProtocolDetector.Classification.TLS;
import static dev.sam.common.net.ProtocolDetector.Classification.VANILLA;
import static org.assertj.core.api.Assertions.assertThat;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import net.jqwik.api.ForAll;
import net.jqwik.api.Property;
import net.jqwik.api.constraints.Size;

/**
 * RS-NET-06 / PROTOCOLO.md 2.1: el servidor clasifica cada conexión nueva por sus primeros bytes.
 */
class ProtocolDetectorTest {

    @Test
    void clientHelloDeTlsSeClasificaComoTls() {
        assertThat(ProtocolDetector.classify(bytes(0x16, 0x03, 0x01, 0x02, 0x00))).isEqualTo(TLS);
    }

    @Test
    void dosBytesAlcanzanParaReconocerTls() {
        assertThat(ProtocolDetector.classify(bytes(0x16, 0x03))).isEqualTo(TLS);
    }

    @Test
    void peticionGetSeClasificaComoHttp() {
        assertThat(ProtocolDetector.classify(ascii("GET /ruta HTTP/1.1\r\n"))).isEqualTo(HTTP);
    }

    @Test
    void pingLegacySeReconoceConUnSoloByte() {
        assertThat(ProtocolDetector.classify(bytes(0xFE))).isEqualTo(LEGACY_PING);
        assertThat(ProtocolDetector.classify(bytes(0xFE, 0x01, 0xFA))).isEqualTo(LEGACY_PING);
    }

    @Test
    void handshakeVanillaSeClasificaComoVanilla() {
        // VarInt de longitud 16, ID de paquete 0x00 (handshake)
        assertThat(ProtocolDetector.classify(bytes(0x10, 0x00, 0xF5, 0x05))).isEqualTo(VANILLA);
    }

    @Test
    void handshakeVanillaDeLongitud22NoSeConfundeConTls() {
        // 0x16 = 22 es una longitud válida de handshake; el segundo byte (ID 0x00) lo desambigua
        assertThat(ProtocolDetector.classify(bytes(0x16, 0x00, 0xF5, 0x05))).isEqualTo(VANILLA);
    }

    @Test
    void exactamenteLosCuatroBytesDeGetAlcanzanParaDecidir() {
        // Borde exacto: un cliente que manda "GET " en el primer segmento no debe quedar esperando
        assertThat(ProtocolDetector.classify(ascii("GET "))).isEqualTo(HTTP);
    }

    @Test
    void unSoloByteVanillaSeDecideSinEsperar() {
        // Un cliente vanilla cuyo primer segmento trae un solo byte no debe quedar colgado
        assertThat(ProtocolDetector.classify(bytes(0x10))).isEqualTo(VANILLA);
    }

    @ParameterizedTest
    @ValueSource(strings = {"XET ", "PET ", "gET ", "HET /ruta"})
    void soloUnaGMayusculaInicialPuedeSerHttp(String entrada) {
        assertThat(ProtocolDetector.classify(ascii(entrada))).isEqualTo(VANILLA);
    }

    @Test
    void sinBytesHaceFaltaLeerMas() {
        assertThat(ProtocolDetector.classify(new byte[0])).isEqualTo(NEED_MORE);
    }

    @Test
    void un0x16SoloEsAmbiguo() {
        assertThat(ProtocolDetector.classify(bytes(0x16))).isEqualTo(NEED_MORE);
    }

    @ParameterizedTest
    @ValueSource(strings = {"G", "GE", "GET"})
    void prefijoParcialDeGetEsAmbiguo(String prefijo) {
        assertThat(ProtocolDetector.classify(ascii(prefijo))).isEqualTo(NEED_MORE);
    }

    @ParameterizedTest
    @ValueSource(strings = {"GX", "GEX", "GETX", "GET/"})
    void algoQueEmpiezaComoGetPeroNoLoEsSeTrataComoVanilla(String entrada) {
        assertThat(ProtocolDetector.classify(ascii(entrada))).isEqualTo(VANILLA);
    }

    @Property
    void nuncaLanzaExcepcionesConEntradasArbitrarias(@ForAll @Size(max = 64) byte[] entrada) {
        assertThat(ProtocolDetector.classify(entrada)).isNotNull();
    }

    @Property
    void unaClasificacionDefinitivaNoCambiaAlLlegarMasBytes(
            @ForAll @Size(max = 8) byte[] prefijo, @ForAll @Size(max = 16) byte[] resto) {
        var antes = ProtocolDetector.classify(prefijo);
        if (antes == NEED_MORE) {
            return;
        }
        assertThat(ProtocolDetector.classify(concat(prefijo, resto))).isEqualTo(antes);
    }

    @Property
    void conCuatroBytesSiempreHayUnaDecision(@ForAll @Size(min = 4, max = 64) byte[] entrada) {
        assertThat(ProtocolDetector.classify(entrada)).isNotEqualTo(NEED_MORE);
    }

    private static byte[] bytes(int... valores) {
        var resultado = new byte[valores.length];
        for (int i = 0; i < valores.length; i++) {
            resultado[i] = (byte) valores[i];
        }
        return resultado;
    }

    private static byte[] ascii(String texto) {
        return texto.getBytes(StandardCharsets.US_ASCII);
    }

    private static byte[] concat(byte[] a, byte[] b) {
        var resultado = Arrays.copyOf(a, a.length + b.length);
        System.arraycopy(b, 0, resultado, a.length, b.length);
        return resultado;
    }
}
