package dev.sam.common.auth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

class Argon2ParamsTest {

    @Test
    void losParametrosDelClienteSonParteDelProtocolo() {
        // PROTOCOLO.md 6.1 (P-06). Cambiarlos rompe todas las contraseñas: exige "SAM-pw-v2".
        assertThat(Argon2Params.CLIENT_V1).isEqualTo(new Argon2Params(65536, 3, 1));
    }

    @Test
    void losParametrosDelServidorSonElMinimoDeOwasp() {
        assertThat(Argon2Params.SERVER_DEFAULT).isEqualTo(new Argon2Params(19456, 2, 1));
    }

    @ParameterizedTest(name = "m={0} t={1} p={2}")
    @CsvSource({
        "0, 1, 1",
        "64, 0, 1",
        "64, 1, 0",
        "7, 1, 1",      // m debe ser al menos 8 * p
        "15, 1, 2",
    })
    void rechazaParametrosInvalidos(int memoria, int iteraciones, int paralelismo) {
        assertThatThrownBy(() -> new Argon2Params(memoria, iteraciones, paralelismo))
            .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void aceptaElMinimoValido() {
        assertThat(new Argon2Params(16, 1, 2).memoryKiB()).isEqualTo(16);
    }
}
