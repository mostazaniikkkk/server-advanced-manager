package dev.sam.common.auth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.HexFormat;
import java.util.List;
import java.util.Optional;

import org.junit.jupiter.api.Test;

import dev.sam.common.proto.auth.AccountState;
import dev.sam.common.proto.auth.AuthResult;
import dev.sam.common.proto.auth.AuthResult.Status;

/**
 * Cuentas en el servidor (RF-AUTH-01, RS-AUTH-01/05/06, PROTOCOLO.md 6.2): el servidor guarda solo
 * Argon2id de K en formato PHC, el nick no distingue mayúsculas y las respuestas fallidas son
 * genéricas.
 */
class AccountServiceTest {

    /** Parámetros mínimos: los tests no miden Argon2, miden el flujo. */
    private static final Argon2Params RAPIDO = new Argon2Params(8, 1, 1);

    static byte[] k(int valor) {
        var k = new byte[32];
        Arrays.fill(k, (byte) valor);
        return k;
    }

    static SecureRandom ceros() {
        return new SecureRandom() {
            private static final long serialVersionUID = 1L;

            @Override
            public void nextBytes(byte[] bytes) {
                Arrays.fill(bytes, (byte) 0);
            }
        };
    }

    private final List<List<Account>> cambios = new ArrayList<>();

    private AccountService servicio(Account... cuentas) {
        return new AccountService(List.of(cuentas), RAPIDO, new SecureRandom(), cambios::add);
    }

    private static AuthResult ok() {
        return new AuthResult(Status.OK, Optional.empty(), Optional.empty());
    }

    private static AuthResult fallo(String detalle) {
        return new AuthResult(Status.FAILED, Optional.empty(), Optional.of(detalle));
    }

    // ===== Hash PHC =====

    @Test
    void elHashEsArgon2idEnFormatoPhcConSaltPropio() {
        var phc = PasswordHash.create(k(1), RAPIDO, ceros());
        var salt = new byte[16];
        var esperado = Argon2id.hash(k(1), salt, RAPIDO, 32);
        var b64 = Base64.getEncoder().withoutPadding();
        assertThat(phc).isEqualTo("$argon2id$v=19$m=8,t=1,p=1$" + b64.encodeToString(salt) + "$" + b64.encodeToString(esperado));
        assertThat(PasswordHash.create(k(1), RAPIDO, new SecureRandom())).isNotEqualTo(PasswordHash.create(k(1), RAPIDO, new SecureRandom()))
            .matches("\\$argon2id\\$v=19\\$m=8,t=1,p=1\\$[A-Za-z0-9+/]{22}\\$[A-Za-z0-9+/]{43}");
        assertThat(PasswordHash.create(k(1), Argon2Params.SERVER_DEFAULT, ceros())).startsWith("$argon2id$v=19$m=19456,t=2,p=1$");
    }

    @Test
    void elHashVerificaLaMismaKYNingunaOtra() {
        var phc = PasswordHash.create(k(1), RAPIDO, new SecureRandom());
        assertThat(PasswordHash.verify(k(1), phc)).isTrue();
        assertThat(PasswordHash.verify(k(2), phc)).isFalse();
        // Con otros parámetros guardados también verifica: se usan los del hash
        var otro = PasswordHash.create(k(3), new Argon2Params(16, 2, 1), new SecureRandom());
        assertThat(PasswordHash.verify(k(3), otro)).isTrue();
    }

    @Test
    void unHashGuardadoInvalidoSeRechaza() {
        var bueno = PasswordHash.create(k(1), RAPIDO, ceros());
        var partes = bueno.split("\\$");
        assertThat(partes).hasSize(6);
        var invalidos = List.of("", "argon2id", bueno.replace("argon2id", "argon2i"), bueno.replace("v=19", "v=16"),
            bueno.replace("m=8,t=1,p=1", "m=8,t=1"), bueno.replace("m=8", "m=x"), bueno.replace("m=8", "m=1048577"),
            bueno.replace("t=1", "t=0"), bueno.replace("t=1", "t=11"), bueno.replace("p=1", "p=0"), bueno.replace("p=1", "p=9"),
            bueno.replace("m=8", "m=-8"), bueno.replace("m=8", "m=+8"),
            bueno + "=", bueno + "$x", "$argon2id$v=19$m=8,t=1,p=1$" + partes[4] + "AA$" + partes[5],
            "$argon2id$v=19$m=8,t=1,p=1$" + partes[4] + "$" + partes[5].substring(4), bueno.replace(partes[5], "%%%"),
            "x" + bueno);
        for (var malo : invalidos) {
            assertThatThrownBy(() -> PasswordHash.verify(k(1), malo)).as(malo).isInstanceOf(IllegalArgumentException.class)
                .hasMessage("hash de contraseña inválido");
        }
    }

    @Test
    void losLimitesDeLosParametrosGuardadosIncluyenSusExtremos() {
        var bueno = PasswordHash.create(k(1), RAPIDO, ceros());
        assertThat(PasswordHash.parse(bueno.replace("m=8,t=1,p=1", "m=1048576,t=10,p=8")).params())
            .isEqualTo(new Argon2Params(1048576, 10, 8));
        assertThat(PasswordHash.parse(bueno).salt()).hasSize(16);
        assertThat(PasswordHash.parse(bueno).hash()).hasSize(32);
    }

    // ===== Nicks =====

    @Test
    void elNickNoDistingueMayusculasYSeValidaEstricto() {
        assertThat(Nick.normalize("SteVe_99")).isEqualTo("steve_99");
        assertThat(Nick.normalize("ISAAC")).isEqualTo("isaac");
        for (var bueno : List.of("abc", "A_1", "a".repeat(16), "Notch")) {
            assertThat(Nick.isValid(bueno)).as(bueno).isTrue();
        }
        for (var malo : List.of("", "ab", "a".repeat(17), "a-b", "ñandú", "a b", "abc\u0000", "abc\n")) {
            assertThat(Nick.isValid(malo)).as(malo).isFalse();
        }
    }

    // ===== Registro y login =====

    @Test
    void unNickNuevoSeRegistraYLuegoEntraConLaMismaK() {
        var servicio = servicio();
        assertThat(servicio.state("Steve")).isEqualTo(AccountState.NEW);
        assertThat(servicio.register("Steve", k(1), "steve@example.com")).isEqualTo(ok());
        assertThat(servicio.state("Steve")).isEqualTo(AccountState.REGISTERED);
        assertThat(servicio.state("STEVE")).isEqualTo(AccountState.REGISTERED);
        assertThat(servicio.login("steve", k(1))).isEqualTo(ok());
        assertThat(servicio.login("Steve", k(1))).isEqualTo(ok());
    }

    @Test
    void lasRespuestasFallidasDelLoginSonIdenticas() {
        var servicio = servicio();
        servicio.register("Steve", k(1), "steve@example.com");
        assertThat(servicio.login("Steve", k(2))).isEqualTo(fallo(AccountService.LOGIN_FAILED));
        assertThat(servicio.login("Alex", k(1))).isEqualTo(fallo(AccountService.LOGIN_FAILED));
    }

    @Test
    void unNickYaRegistradoNoSePisa() {
        var servicio = servicio();
        servicio.register("Steve", k(1), "steve@example.com");
        assertThat(servicio.register("STEVE", k(2), "otro@example.com")).isEqualTo(fallo(AccountService.REGISTER_FAILED));
        assertThat(servicio.login("Steve", k(1))).isEqualTo(ok());
        assertThat(servicio.login("Steve", k(2))).isEqualTo(fallo(AccountService.LOGIN_FAILED));
        assertThat(cambios).hasSize(1);
    }

    @Test
    void unCorreoONickInvalidoNoRegistra() {
        var servicio = servicio();
        for (var malo : List.of("", "a", "a@", "@b.c", "a@b", "a@b.", "a@.b", "a b@c.d", "a@b c.d", "a@@b.c", "a\u0000@b.c",
                "a@b.c\n", "a".repeat(250) + "@b.cd")) {
            assertThat(servicio.register("Steve", k(1), malo)).as(malo).isEqualTo(fallo(AccountService.INVALID_EMAIL));
        }
        assertThat(servicio.register("a-b", k(1), "a@b.c")).isEqualTo(fallo(AccountService.INVALID_NICK));
        assertThat(servicio.state("Steve")).isEqualTo(AccountState.NEW);
        assertThat(cambios).isEmpty();
        for (var bueno : List.of("a@b.c", "steve.x+1@mail.example.com", "a".repeat(248) + "@b.cd", "a".repeat(249) + "@b.cd")) {
            assertThat(AccountService.isValidEmail(bueno)).as(bueno).isTrue();
        }
    }

    @Test
    void cadaRegistroEntregaTodasLasCuentasParaGuardarlasSinLaKEnClaro() {
        var servicio = servicio();
        servicio.register("Steve", k(1), "steve@example.com");
        servicio.register("Alex", k(2), "alex@example.com");
        servicio.login("Steve", k(1));
        assertThat(cambios).hasSize(2);
        var ultimas = cambios.get(1);
        assertThat(ultimas).extracting(Account::key).containsExactlyInAnyOrder("steve", "alex");
        var steve = ultimas.stream().filter(c -> c.key().equals("steve")).findFirst().orElseThrow();
        assertThat(steve.nick()).isEqualTo("Steve");
        assertThat(steve.email()).isEqualTo("steve@example.com");
        assertThat(PasswordHash.verify(k(1), steve.passwordHash())).isTrue();
        assertThat(steve.passwordHash()).doesNotContain(HexFormat.of().formatHex(k(1)))
            .doesNotContain(Base64.getEncoder().withoutPadding().encodeToString(k(1)));
        assertThatThrownBy(() -> ultimas.add(steve)).isInstanceOf(UnsupportedOperationException.class);
    }

    @Test
    void lasCuentasGuardadasSeCarganAlArrancar() {
        var guardada = new Account("steve", "Steve", PasswordHash.create(k(1), RAPIDO, new SecureRandom()), "s@e.com");
        var servicio = servicio(guardada);
        assertThat(servicio.state("steve")).isEqualTo(AccountState.REGISTERED);
        assertThat(servicio.login("Steve", k(1))).isEqualTo(ok());
        assertThatThrownBy(() -> servicio(guardada, guardada)).isInstanceOf(IllegalArgumentException.class)
            .hasMessage("cuenta repetida: steve");
    }
}
