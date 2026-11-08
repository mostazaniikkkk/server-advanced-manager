package dev.sam.common.auth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.time.Duration;
import java.time.Instant;
import java.util.Optional;

import org.junit.jupiter.api.Test;

/** RF-AUTH-06 / RF-AUTH-06a (H-03): bloqueo exponencial por (cuenta, IP), global de cuenta más suave, pendientes. */
class LoginThrottleTest {

    private static final Instant T0 = Instant.parse("2026-11-08T12:00:00Z");
    private static final Duration BASE = Duration.ofMinutes(15);

    private Instant ahora = T0;
    private final LoginThrottle throttle = new LoginThrottle(new LoginThrottle.Limits(3, BASE, 2, 3), () -> ahora);

    private Optional<Instant> fallar(String cuenta, String ip, int veces) {
        Optional<Instant> ultimo = Optional.empty();
        for (var i = 0; i < veces; i++) {
            ultimo = throttle.failure(cuenta, ip);
        }
        return ultimo;
    }

    @Test
    void sinFallosNoHayBloqueo() {
        assertThat(throttle.lockedUntil("steve", "1.1.1.1")).isEmpty();
    }

    @Test
    void elTercerFalloDelParBloqueaQuinceMinutosSoloEsePar() {
        assertThat(fallar("steve", "1.1.1.1", 2)).isEmpty();
        assertThat(throttle.lockedUntil("steve", "1.1.1.1")).isEmpty();
        assertThat(throttle.failure("steve", "1.1.1.1")).contains(T0.plus(BASE));
        assertThat(throttle.lockedUntil("steve", "1.1.1.1")).contains(T0.plus(BASE));
        assertThat(throttle.lockedUntil("steve", "2.2.2.2")).isEmpty();
        assertThat(throttle.lockedUntil("alex", "1.1.1.1")).isEmpty();
    }

    @Test
    void elBloqueoVenceYCadaRepeticionLoDobla() {
        fallar("steve", "1.1.1.1", 3);
        ahora = T0.plus(BASE).minusSeconds(1);
        assertThat(throttle.lockedUntil("steve", "1.1.1.1")).isPresent();
        ahora = T0.plus(BASE);
        assertThat(throttle.lockedUntil("steve", "1.1.1.1")).isEmpty();
        assertThat(fallar("steve", "1.1.1.1", 3)).contains(ahora.plus(BASE.multipliedBy(2)));
        ahora = ahora.plus(BASE.multipliedBy(2));
        assertThat(fallar("steve", "1.1.1.1", 3)).contains(ahora.plus(BASE.multipliedBy(4)));
    }

    @Test
    void elBloqueoTieneTopeDe24Horas() {
        for (var i = 0; i < 12; i++) {
            var hasta = fallar("steve", "1.1.1.1", 3).orElseThrow();
            assertThat(Duration.between(ahora, hasta)).isLessThanOrEqualTo(Duration.ofHours(24));
            ahora = hasta;
        }
        assertThat(Duration.between(ahora, fallar("steve", "1.1.1.1", 3).orElseThrow())).isEqualTo(Duration.ofHours(24));
    }

    @Test
    void elGlobalDeLaCuentaSaltaConCuatroVecesLosFallosDesdeVariasIps() {
        // 3 fallos por par bloquean ese par; 12 en total (4 x 3) bloquean la cuenta desde cualquier IP
        for (var ip = 1; ip <= 3; ip++) {
            fallar("steve", "10.0.0." + ip, 3);
        }
        assertThat(throttle.lockedUntil("steve", "10.0.0.9")).isEmpty();
        assertThat(fallar("steve", "10.0.0.4", 2)).isEmpty();
        assertThat(throttle.failure("steve", "10.0.0.4")).contains(T0.plus(BASE));
        assertThat(throttle.lockedUntil("steve", "10.0.0.9")).contains(T0.plus(BASE));
        assertThat(throttle.lockedUntil("alex", "10.0.0.9")).isEmpty();
    }

    @Test
    void seRespetaElBloqueoMasLargoEntreParYCuenta() {
        // La cuenta se bloquea después y hasta más tarde que el par
        fallar("steve", "1.1.1.1", 3);
        ahora = T0.plus(Duration.ofMinutes(10));
        for (var ip = 2; ip <= 4; ip++) {
            fallar("steve", "10.0.0." + ip, 3);
        }
        assertThat(throttle.lockedUntil("steve", "1.1.1.1")).contains(T0.plus(Duration.ofMinutes(25)));
    }

    @Test
    void seRespetaElBloqueoDelParSiEsMasLargoQueElDeLaCuenta() {
        fallar("steve", "1.1.1.1", 3);
        ahora = T0.plus(BASE);
        fallar("steve", "1.1.1.1", 3);
        fallar("steve", "2.2.2.2", 3);
        assertThat(fallar("steve", "3.3.3.3", 3)).contains(ahora.plus(BASE));
        assertThat(throttle.lockedUntil("steve", "1.1.1.1")).contains(ahora.plus(BASE.multipliedBy(2)));
        assertThat(throttle.lockedUntil("steve", "3.3.3.3")).contains(ahora.plus(BASE));
    }

    @Test
    void justoEnElTopeTodaviaNoSeDescarta() {
        // Cada fallo de una cuenta nueva suma dos contadores: el del par y el de la cuenta
        for (var i = 0; i < LoginThrottle.PRUNE_ABOVE / 2; i++) {
            throttle.failure("cuenta" + i, "1.1.1.1");
        }
        assertThat(throttle.size()).isEqualTo(LoginThrottle.PRUNE_ABOVE);
        ahora = T0.plus(Duration.ofHours(25));
        throttle.failure("otra", "1.1.1.1");
        assertThat(throttle.size()).isEqualTo(LoginThrottle.PRUNE_ABOVE + 2);
    }

    @Test
    void conPocosContadoresNoSeDescartaNada() {
        throttle.failure("vieja", "1.1.1.1");
        ahora = T0.plus(Duration.ofHours(25));
        throttle.failure("otra", "1.1.1.1");
        assertThat(throttle.size()).isEqualTo(4);
    }

    @Test
    void unLoginCorrectoLimpiaElParYLaCuenta() {
        fallar("steve", "1.1.1.1", 2);
        fallar("steve", "2.2.2.2", 2);
        throttle.success("steve", "1.1.1.1");
        assertThat(fallar("steve", "1.1.1.1", 2)).isEmpty();
        // La cuenta volvió a cero: hacen falta 12 fallos nuevos para el global
        for (var ip = 3; ip <= 5; ip++) {
            fallar("steve", "10.0.0." + ip, 2);
        }
        assertThat(throttle.lockedUntil("steve", "9.9.9.9")).isEmpty();
    }

    @Test
    void unLoginCorrectoTambienOlvidaElNivelDelPar() {
        fallar("steve", "1.1.1.1", 3);
        ahora = T0.plus(BASE);
        throttle.success("steve", "1.1.1.1");
        assertThat(fallar("steve", "1.1.1.1", 3)).contains(ahora.plus(BASE));
    }

    @Test
    void veinticuatroHorasSinFallosOlvidanLosNiveles() {
        fallar("steve", "1.1.1.1", 3);
        ahora = T0.plus(Duration.ofHours(24)).plusSeconds(1);
        assertThat(fallar("steve", "1.1.1.1", 3)).contains(ahora.plus(BASE));
        assertThat(fallar("steve", "1.1.1.1", 2)).isEmpty();
    }

    @Test
    void menosDeVeinticuatroHorasNoOlvidan() {
        fallar("steve", "1.1.1.1", 3);
        ahora = T0.plus(Duration.ofHours(24));
        assertThat(fallar("steve", "1.1.1.1", 3)).contains(ahora.plus(BASE.multipliedBy(2)));
    }

    @Test
    void laCuentaSeComparaSinMayusculas() {
        fallar("Steve", "1.1.1.1", 3);
        assertThat(throttle.lockedUntil("STEVE", "1.1.1.1")).isPresent();
    }

    @Test
    void pendientesPorIpYGlobales() {
        assertThat(throttle.enter("1.1.1.1")).isTrue();
        assertThat(throttle.enter("1.1.1.1")).isTrue();
        assertThat(throttle.enter("1.1.1.1")).isFalse();
        assertThat(throttle.enter("2.2.2.2")).isTrue();
        assertThat(throttle.enter("3.3.3.3")).isFalse();
        throttle.leave("1.1.1.1");
        assertThat(throttle.enter("3.3.3.3")).isTrue();
        throttle.leave("1.1.1.1");
        throttle.leave("1.1.1.1");
        throttle.leave("desconocida");
        // Salir de más no deja contadores negativos: quedan 2.2.2.2 y 3.3.3.3, cabe uno más en total
        assertThat(throttle.enter("1.1.1.1")).isTrue();
        assertThat(throttle.enter("4.4.4.4")).isFalse();
        throttle.leave("2.2.2.2");
        throttle.leave("3.3.3.3");
        assertThat(throttle.enter("1.1.1.1")).isTrue();
        assertThat(throttle.enter("1.1.1.1")).isFalse();
    }

    @Test
    void losContadoresViejosSeDescartanParaNoCrecerSinFin() {
        for (var i = 0; i < LoginThrottle.PRUNE_ABOVE + 10; i++) {
            throttle.failure("cuenta" + i, "1.1.1.1");
        }
        assertThat(throttle.size()).isGreaterThan(LoginThrottle.PRUNE_ABOVE);
        ahora = T0.plus(Duration.ofHours(25));
        throttle.failure("otra", "1.1.1.1");
        assertThat(throttle.size()).isLessThanOrEqualTo(3);
    }

    @Test
    void losLimitesSalenDelEnvConValoresPorDefecto() {
        assertThat(LoginThrottle.Limits.fromConfig(java.util.Map.of()))
            .isEqualTo(new LoginThrottle.Limits(5, Duration.ofMinutes(15), 3, 50));
        assertThat(LoginThrottle.Limits.fromConfig(java.util.Map.of("SAM_AUTH_MAX_ATTEMPTS", " 4 ", "SAM_AUTH_LOCKOUT_BASE", "1h",
            "SAM_AUTH_PENDING_PER_IP", "2", "SAM_AUTH_PENDING_GLOBAL", "20")))
            .isEqualTo(new LoginThrottle.Limits(4, Duration.ofHours(1), 2, 20));
        assertThat(LoginThrottle.Limits.fromConfig(java.util.Map.of("SAM_AUTH_LOCKOUT_BASE", "90s")).base()).isEqualTo(Duration.ofSeconds(90));
        assertThat(LoginThrottle.Limits.fromConfig(java.util.Map.of("SAM_AUTH_LOCKOUT_BASE", "30m")).base()).isEqualTo(Duration.ofMinutes(30));
        for (var malo : java.util.List.of("15", "m", "-5m", "15d", "1.5h", "")) {
            assertThatThrownBy(() -> LoginThrottle.Limits.fromConfig(java.util.Map.of("SAM_AUTH_LOCKOUT_BASE", malo))).as(malo)
                .isInstanceOf(IllegalArgumentException.class).hasMessageContaining("SAM_AUTH_LOCKOUT_BASE");
        }
        assertThatThrownBy(() -> LoginThrottle.Limits.fromConfig(java.util.Map.of("SAM_AUTH_MAX_ATTEMPTS", "cinco")))
            .isInstanceOf(IllegalArgumentException.class).hasMessageContaining("SAM_AUTH_MAX_ATTEMPTS");
    }

    @Test
    void losLimitesInvalidosSeRechazan() {
        assertThatThrownBy(() -> new LoginThrottle.Limits(0, BASE, 1, 1)).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new LoginThrottle.Limits(1, Duration.ZERO, 1, 1)).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new LoginThrottle.Limits(1, Duration.ofSeconds(-1), 1, 1)).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new LoginThrottle.Limits(1, BASE, 0, 1)).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new LoginThrottle.Limits(1, BASE, 1, 0)).isInstanceOf(IllegalArgumentException.class);
        new LoginThrottle.Limits(1, Duration.ofSeconds(1), 1, 1);
    }
}
