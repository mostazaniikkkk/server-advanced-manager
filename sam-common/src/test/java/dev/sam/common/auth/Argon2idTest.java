package dev.sam.common.auth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.Arrays;
import java.util.HexFormat;

import org.junit.jupiter.api.Test;

/**
 * Argon2id de bajo nivel. El vector oficial de la RFC 9106 (sección 5.3) garantiza que usamos
 * la variante (id) y la versión (0x13) correctas de la librería.
 */
class Argon2idTest {

    @Test
    void coincideConElVectorOficialDeLaRfc9106() {
        var password = filled(32, 0x01);
        var salt = filled(16, 0x02);
        var secret = filled(8, 0x03);
        var associatedData = filled(12, 0x04);

        var tag = Argon2id.hash(password, salt, secret, associatedData, new Argon2Params(32, 3, 4), 32);

        assertThat(HexFormat.of().formatHex(tag))
            .isEqualTo("0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659");
    }

    @Test
    void sinSecretoNiDatosAsociadosTambienFunciona() {
        var tag = Argon2id.hash(filled(8, 0x01), filled(16, 0x02), new Argon2Params(64, 1, 1), 32);
        assertThat(tag).hasSize(32).isNotEqualTo(new byte[32]);
    }

    @Test
    void laLongitudDeSalidaSeRespeta() {
        assertThat(Argon2id.hash(filled(8, 0x01), filled(16, 0x02), new Argon2Params(64, 1, 1), 16)).hasSize(16);
    }

    @Test
    void aceptaUnSaltDeExactamente8Bytes() {
        assertThat(Argon2id.hash(filled(8, 1), filled(8, 2), new Argon2Params(64, 1, 1), 32)).hasSize(32);
    }

    @Test
    void elSecretoYLosDatosAsociadosCambianElResultado() {
        var params = new Argon2Params(64, 1, 1);
        var base = Argon2id.hash(filled(8, 1), filled(16, 2), params, 32);
        assertThat(Argon2id.hash(filled(8, 1), filled(16, 2), filled(8, 3), null, params, 32)).isNotEqualTo(base);
        assertThat(Argon2id.hash(filled(8, 1), filled(16, 2), null, filled(8, 4), params, 32)).isNotEqualTo(base);
    }

    @Test
    void rechazaSaltsDeMenosDe8Bytes() {
        assertThatThrownBy(() -> Argon2id.hash(filled(8, 1), filled(7, 2), new Argon2Params(64, 1, 1), 32))
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessageContaining("salt");
    }

    @Test
    void rechazaSalidasDeMenosDe16Bytes() {
        assertThatThrownBy(() -> Argon2id.hash(filled(8, 1), filled(16, 2), new Argon2Params(64, 1, 1), 15))
            .isInstanceOf(IllegalArgumentException.class);
    }

    private static byte[] filled(int length, int value) {
        var bytes = new byte[length];
        Arrays.fill(bytes, (byte) value);
        return bytes;
    }
}
