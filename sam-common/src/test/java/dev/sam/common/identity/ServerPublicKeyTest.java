package dev.sam.common.identity;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.HexFormat;

import org.junit.jupiter.api.Test;

import net.jqwik.api.ForAll;
import net.jqwik.api.Property;
import net.jqwik.api.constraints.Size;

/** Clave pública Ed25519 del servidor, en formato SPKI (PROTOCOLO.md 3.1 y 3.3). */
class ServerPublicKeyTest {

    private static final String K1_SPKI = "302a300506032b6570032100d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
    private static final String K1_PIN = "06e3fd8fda29bb60ab59557de61edb0aecdb231134be30e75b455f8e1b792fa9";
    /** RFC 8032 §7.1, test 1: firma del mensaje vacío con K1. */
    private static final String RFC8032_TEST1_SIG = "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b";

    @Test
    void verificaLaFirmaOficialDeLaRfc8032() {
        var key = ServerPublicKey.fromSpki(hex(K1_SPKI));
        assertThat(key.verify(new byte[0], hex(RFC8032_TEST1_SIG))).isTrue();
    }

    @Test
    void rechazaLaFirmaSiCambiaUnBitDeLaFirmaODelMensaje() {
        var key = ServerPublicKey.fromSpki(hex(K1_SPKI));
        var firma = hex(RFC8032_TEST1_SIG);
        firma[10] ^= 0x01;
        assertThat(key.verify(new byte[0], firma)).isFalse();
        assertThat(key.verify(new byte[] {0}, hex(RFC8032_TEST1_SIG))).isFalse();
    }

    @Test
    void rechazaUnaFirmaDeOtraClave() {
        var mensaje = "hola".getBytes();
        assertThat(TestKeys.K2.publicKey().verify(mensaje, TestKeys.K1.sign(mensaje))).isFalse();
        assertThat(TestKeys.K1.publicKey().verify(mensaje, TestKeys.K1.sign(mensaje))).isTrue();
    }

    @Test
    void unaFirmaDeLongitudIncorrectaEsInvalidaSinExcepcion() {
        var key = ServerPublicKey.fromSpki(hex(K1_SPKI));
        assertThat(key.verify(new byte[0], new byte[63])).isFalse();
        assertThat(key.verify(new byte[0], new byte[0])).isFalse();
    }

    @Test
    void elPinEsElSha256DeLaSpki() {
        assertThat(ServerPublicKey.fromSpki(hex(K1_SPKI)).pin()).isEqualTo(Pin.fromHex(K1_PIN));
    }

    @Test
    void conservaLaSpkiYEsInmutable() {
        var spki = hex(K1_SPKI);
        var key = ServerPublicKey.fromSpki(spki);
        spki[20] ^= 1;
        key.spki()[21] ^= 1;
        assertThat(key.spki()).isEqualTo(hex(K1_SPKI));
    }

    @Test
    void rechazaSpkiQueNoSonEd25519() {
        // Longitud incorrecta
        assertThatThrownBy(() -> ServerPublicKey.fromSpki(new byte[43])).isInstanceOf(IllegalArgumentException.class);
        // 44 bytes pero con el OID de X25519 (1.3.101.110) en lugar de Ed25519 (1.3.101.112)
        var x25519 = hex(K1_SPKI);
        x25519[8] = 0x6e;
        assertThatThrownBy(() -> ServerPublicKey.fromSpki(x25519)).isInstanceOf(IllegalArgumentException.class);
        // 44 bytes de basura
        assertThatThrownBy(() -> ServerPublicKey.fromSpki(new byte[44])).isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void rechazaUnaSpkiNoCanonicaDe44Bytes() {
        // Byte de "bits sin usar" del BIT STRING en 1 en lugar de 0
        var noCanonica = hex(K1_SPKI);
        noCanonica[11] = 0x01;
        assertThatThrownBy(() -> ServerPublicKey.fromSpki(noCanonica)).isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void igualdadPorValor() {
        assertThat(TestKeys.K1.publicKey()).isEqualTo(ServerPublicKey.fromSpki(hex(K1_SPKI)))
            .isNotEqualTo(TestKeys.K2.publicKey());
    }

    @Property(tries = 200)
    void unaClaveVerificaSusPropiasFirmas(@ForAll @Size(32) byte[] semilla, @ForAll @Size(max = 64) byte[] mensaje) {
        var clave = TestKeys.fromSeed(semilla);
        assertThat(clave.publicKey().verify(mensaje, clave.sign(mensaje))).isTrue();
    }

    private static byte[] hex(String value) {
        return HexFormat.of().parseHex(value);
    }
}
