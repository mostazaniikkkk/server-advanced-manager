package dev.sam.common.auth;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

/** RN-45 (H-06): longitud mínima, contraseñas comunes y el nick dentro de la contraseña, en el cliente. */
class PasswordPolicyTest {

    private final PasswordPolicy politica = PasswordPolicy.load();

    @Test
    void unaContrasenaBuenaPasa() {
        assertThat(politica.check("caballo bateria grapa", "Steve", 8)).isEmpty();
    }

    @Test
    void demasiadoCorta() {
        assertThat(politica.check("k7#pQ2x", "Steve", 8)).contains(PasswordPolicy.TOO_SHORT);
        assertThat(politica.check("k7#pQ2xZ", "Steve", 8)).isEmpty();
    }

    @Test
    void lasMasUsadasSeRechazanSinImportarMayusculas() {
        for (var comun : new String[] {"password", "PassWord", "123456789", "qwertyuiop", "iloveyou", "football"}) {
            assertThat(politica.check(comun, "Steve", 6)).as(comun).contains(PasswordPolicy.COMMON);
        }
    }

    @Test
    void noPuedeContenerElNick() {
        assertThat(politica.check("soysteve2026!", "Steve", 8)).contains(PasswordPolicy.HAS_NICK);
        assertThat(politica.check("STEVE-y-alex-99", "steve", 8)).contains(PasswordPolicy.HAS_NICK);
        // Un nick muy corto no cuenta (si no, "al" bloquearía media lengua)
        assertThat(politica.check("algo largo y raro 77", "Al", 8)).isEmpty();
        assertThat(politica.check("con tim adentro 77x", "Tim", 8)).contains(PasswordPolicy.HAS_NICK);
    }

    @Test
    void elOrdenDeLosMotivos() {
        assertThat(politica.check("steve", "Steve", 8)).contains(PasswordPolicy.TOO_SHORT);
        assertThat(politica.check("steve123", "Steve", 8)).contains(PasswordPolicy.COMMON);
    }

    @Test
    void laListaTieneLasNoventaYSeisMil() {
        assertThat(politica.commonCount()).isBetween(90_000, 100_000);
    }
}
