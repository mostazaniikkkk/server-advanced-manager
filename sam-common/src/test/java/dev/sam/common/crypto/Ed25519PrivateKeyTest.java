package dev.sam.common.crypto;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.HexFormat;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

/** Firma Ed25519 (la usa sam-signer en la máquina del operador). Vectores de la RFC 8032 §7.1. */
class Ed25519PrivateKeyTest {

    private static final String SEED_1 = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
    private static final String PUB_1 = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
    private static final String SIG_1 = "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b";

    @Test
    void derivaLaClavePublicaDeLaRfc8032() {
        assertThat(hex(Ed25519PrivateKey.fromSeed(bytes(SEED_1)).publicKeyRaw())).isEqualTo(PUB_1);
    }

    @Test
    void produceLaFirmaDeLaRfc8032() {
        assertThat(hex(Ed25519PrivateKey.fromSeed(bytes(SEED_1)).sign(new byte[0]))).isEqualTo(SIG_1);
    }

    @ParameterizedTest
    @ValueSource(ints = {0, 31, 33, 64})
    void rechazaSemillasQueNoMiden32Bytes(int longitud) {
        assertThatThrownBy(() -> Ed25519PrivateKey.fromSeed(new byte[longitud]))
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessageContaining("32");
    }

    @Test
    void esInmuneAModificacionesDeLaSemillaYDeLaClavePublicaDevuelta() {
        var semilla = bytes(SEED_1);
        var clave = Ed25519PrivateKey.fromSeed(semilla);
        semilla[0] ^= 1;
        clave.publicKeyRaw()[0] ^= 1;
        assertThat(hex(clave.publicKeyRaw())).isEqualTo(PUB_1);
        assertThat(hex(clave.sign(new byte[0]))).isEqualTo(SIG_1);
    }

    @Test
    void toStringNoRevelaLaSemilla() {
        assertThat(Ed25519PrivateKey.fromSeed(bytes(SEED_1)).toString())
            .doesNotContain(SEED_1)
            .contains(PUB_1.substring(0, 16));
    }

    static byte[] bytes(String hex) {
        return HexFormat.of().parseHex(hex);
    }

    static String hex(byte[] bytes) {
        return HexFormat.of().formatHex(bytes);
    }
}
