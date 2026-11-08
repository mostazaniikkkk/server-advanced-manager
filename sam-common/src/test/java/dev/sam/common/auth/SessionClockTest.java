package dev.sam.common.auth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.time.Duration;
import java.time.Instant;
import java.util.Map;

import org.junit.jupiter.api.Test;

/** RF-ADM-05a (H-04): caducidad de la sesión verificada de un admin y de cualquier sesión de juego. */
class SessionClockTest {

    private static final Instant T0 = Instant.parse("2026-11-08T12:00:00Z");
    private final SessionClock reloj = new SessionClock(Duration.ofHours(12), Duration.ofDays(7));

    @Test
    void laSesionVerificadaVenceALasDoceHorasYAvisaUnaVez() {
        reloj.start("Steve", true, T0);
        assertThat(reloj.verified("steve", T0.plus(Duration.ofHours(12)).minusSeconds(1))).isTrue();
        assertThat(reloj.verified("STEVE", T0.plus(Duration.ofHours(12)))).isFalse();
        assertThat(reloj.adminExpired(T0.plus(Duration.ofHours(11)))).isEmpty();
        assertThat(reloj.adminExpired(T0.plus(Duration.ofHours(12)))).containsExactly("Steve");
        assertThat(reloj.adminExpired(T0.plus(Duration.ofHours(13)))).isEmpty();
    }

    @Test
    void sinDosFANuncaEstaVerificado() {
        reloj.start("Alex", false, T0);
        assertThat(reloj.verified("alex", T0)).isFalse();
        assertThat(reloj.adminExpired(T0.plus(Duration.ofDays(1)))).isEmpty();
        assertThat(reloj.verified("nadie", T0)).isFalse();
    }

    @Test
    void cualquierSesionVenceALosSieteDias() {
        reloj.start("Alex", false, T0);
        reloj.start("Steve", true, T0.plusSeconds(10));
        assertThat(reloj.expired(T0.plus(Duration.ofDays(7)).minusSeconds(1))).isEmpty();
        assertThat(reloj.expired(T0.plus(Duration.ofDays(7)))).containsExactly("Alex");
        assertThat(reloj.expired(T0.plus(Duration.ofDays(7)).plusSeconds(10))).containsExactly("Steve");
    }

    @Test
    void volverAEntrarReiniciaYSalirOlvida() {
        reloj.start("Steve", true, T0);
        reloj.start("Steve", true, T0.plus(Duration.ofHours(11)));
        assertThat(reloj.verified("steve", T0.plus(Duration.ofHours(20)))).isTrue();
        reloj.forget("STEVE");
        assertThat(reloj.verified("steve", T0.plus(Duration.ofHours(20)))).isFalse();
        assertThat(reloj.expired(T0.plus(Duration.ofDays(30)))).isEmpty();
    }

    @Test
    void lasDuracionesSalenDelEnv() {
        var desdeEnv = SessionClock.fromConfig(Map.of("SAM_POLICY_ADMIN_SESSION_TTL", "30m", "SAM_POLICY_DEFAULT_SESSION_TTL", "2d"));
        desdeEnv.start("Steve", true, T0);
        assertThat(desdeEnv.verified("steve", T0.plus(Duration.ofMinutes(30)).minusSeconds(1))).isTrue();
        assertThat(desdeEnv.verified("steve", T0.plus(Duration.ofMinutes(30)))).isFalse();
        assertThat(desdeEnv.expired(T0.plus(Duration.ofDays(2)))).containsExactly("Steve");
        var porDefecto = SessionClock.fromConfig(Map.of());
        porDefecto.start("Steve", true, T0);
        assertThat(porDefecto.verified("steve", T0.plus(Duration.ofHours(12)).minusSeconds(1))).isTrue();
        assertThat(porDefecto.verified("steve", T0.plus(Duration.ofHours(12)))).isFalse();
        assertThat(porDefecto.expired(T0.plus(Duration.ofDays(7)).minusSeconds(1))).isEmpty();
        assertThat(porDefecto.expired(T0.plus(Duration.ofDays(7)))).containsExactly("Steve");
        assertThat(SessionClock.parse("X", "45s")).isEqualTo(Duration.ofSeconds(45));
        assertThat(SessionClock.parse("X", " 3h ")).isEqualTo(Duration.ofHours(3));
        for (var malo : new String[] {"", "12", "h", "0h", "-1h", "1.5h", "2w"}) {
            assertThatThrownBy(() -> SessionClock.parse("SAM_X", malo)).as(malo).isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("SAM_X");
        }
    }
}
