package dev.sam.common.scripts;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.HexFormat;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

/** Clave pública de firma del operador (PROTOCOLO.md 8.1): 32 bytes, key_id = SHA-256(clave)[0..8]. */
class SigningPublicKeyTest {

    static final byte[] K1_RAW = HexFormat.of().parseHex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
    private static final byte[] RFC_SIG = HexFormat.of().parseHex("e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b");

    @Test
    void elKeyIdCoincideConLaReferencia() {
        assertThat(SigningPublicKey.of(K1_RAW).keyId()).isEqualTo(KeyId.of("21fe31dfa154a261"));
    }

    @Test
    void verificaLaFirmaDeLaRfc8032YRechazaUnaAlterada() {
        var clave = SigningPublicKey.of(K1_RAW);
        assertThat(clave.verify(new byte[0], RFC_SIG)).isTrue();
        var alterada = RFC_SIG.clone();
        alterada[0] ^= 1;
        assertThat(clave.verify(new byte[0], alterada)).isFalse();
        assertThat(clave.verify(new byte[] {1}, RFC_SIG)).isFalse();
        assertThat(clave.verify(new byte[0], new byte[10])).isFalse();
    }

    @ParameterizedTest
    @ValueSource(ints = {0, 31, 33, 44})
    void rechazaClavesQueNoMiden32Bytes(int longitud) {
        assertThatThrownBy(() -> SigningPublicKey.of(new byte[longitud]))
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessageContaining("32");
    }

    @Test
    void esInmutableYSeComparaPorValor() {
        var raw = K1_RAW.clone();
        var clave = SigningPublicKey.of(raw);
        raw[0] ^= 1;
        clave.raw()[1] ^= 1;
        assertThat(clave.raw()).isEqualTo(K1_RAW);
        assertThat(clave).isEqualTo(SigningPublicKey.of(K1_RAW)).hasSameHashCodeAs(SigningPublicKey.of(K1_RAW));
        var otra = K1_RAW.clone();
        otra[31] ^= 1;
        assertThat(clave).isNotEqualTo(SigningPublicKey.of(otra)).isNotEqualTo(null);
        assertThat(clave.hashCode()).isNotEqualTo(SigningPublicKey.of(otra).hashCode());
        assertThat(clave.toString()).contains("21fe31dfa154a261");
    }

    // ===== KeyId =====

    @Test
    void keyIdSonDieciseisDigitosHexEnMinusculas() {
        assertThat(KeyId.of("0123456789abcdef").hex()).isEqualTo("0123456789abcdef");
        assertThat(KeyId.of("0123456789abcdef")).hasToString("0123456789abcdef");
    }

    @ParameterizedTest
    @ValueSource(strings = {"", "0123456789abcde", "0123456789abcdef0", "0123456789ABCDEF", "0123456789abcdeg"})
    void rechazaKeyIdsInvalidos(String hex) {
        assertThatThrownBy(() -> KeyId.of(hex)).isInstanceOf(IllegalArgumentException.class);
    }
}
