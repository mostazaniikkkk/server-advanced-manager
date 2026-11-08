package dev.sam.common.auth;

import static org.assertj.core.api.Assertions.assertThat;

import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;

import org.junit.jupiter.api.Test;

import dev.sam.common.proto.account.AccountInfo;
import dev.sam.common.proto.account.AccountResult;
import dev.sam.common.proto.account.OAuthProvider;

/**
 * Gestión de la cuenta desde "Opciones de cuenta" (RF-AUTH-07, 07b, 07d; RF-OAUTH-02/03; RS-AUTH-07;
 * RS-OAUTH-02): cambio de correo con la contraseña, vinculación de Google por su {@code sub} y correo
 * siempre enmascarado.
 */
class AccountManagementTest {

    private static final Argon2Params RAPIDO = new Argon2Params(8, 1, 1);
    private static final AccountResult OK = new AccountResult(AccountResult.Status.OK, Optional.empty());

    static byte[] k(int valor) {
        var k = new byte[32];
        Arrays.fill(k, (byte) valor);
        return k;
    }

    private final List<List<Account>> cambios = new ArrayList<>();

    private AccountService servicio() {
        var steve = new Account("steve", "Steve", PasswordHash.create(k(1), RAPIDO, new SecureRandom()), "steve@example.com");
        var alex = new Account("alex", "Alex", PasswordHash.create(k(2), RAPIDO, new SecureRandom()), "alex@example.com",
            Optional.of("sub-de-alex"));
        return new AccountService(List.of(steve, alex), RAPIDO, new SecureRandom(), cambios::add);
    }

    private static AccountResult fallo(String detalle) {
        return new AccountResult(AccountResult.Status.FAILED, Optional.of(detalle));
    }

    private Account guardada(String key) {
        return cambios.getLast().stream().filter(a -> a.key().equals(key)).findFirst().orElseThrow();
    }

    @Test
    void elCorreoSeEnmascara() {
        assertThat(AccountService.mask("steve@example.com")).isEqualTo("s***@e***.com");
        assertThat(AccountService.mask("a@b.co.uk")).isEqualTo("a***@b***.uk");
        assertThat(AccountService.mask("x@dominio.cl")).isEqualTo("x***@d***.cl");
    }

    @Test
    void laInfoMuestraElCorreoEnmascaradoYElEstadoDeGoogle() {
        var cuentas = servicio();
        assertThat(cuentas.info("STEVE", true)).isEqualTo(new AccountInfo("s***@e***.com", false, AccountInfo.Google.AVAILABLE, AccountInfo.Totp.UNAVAILABLE));
        assertThat(cuentas.info("Steve", false)).isEqualTo(new AccountInfo("s***@e***.com", false, AccountInfo.Google.UNAVAILABLE, AccountInfo.Totp.UNAVAILABLE));
        assertThat(cuentas.info("alex", true)).isEqualTo(new AccountInfo("a***@e***.com", false, AccountInfo.Google.LINKED, AccountInfo.Totp.UNAVAILABLE));
        // Si el admin deshabilita Google, una cuenta vinculada se ve como no disponible
        assertThat(cuentas.info("alex", false).google()).isEqualTo(AccountInfo.Google.UNAVAILABLE);
    }

    @Test
    void elCorreoSeCambiaConLaContrasenaYSeGuarda() {
        var cuentas = servicio();
        assertThat(cuentas.changeEmail("Steve", k(1), Optional.empty(), "nuevo@correo.cl")).isEqualTo(OK);
        assertThat(guardada("steve").email()).isEqualTo("nuevo@correo.cl");
        assertThat(cuentas.info("steve", true).email()).isEqualTo("n***@c***.cl");
        // La contraseña sigue siendo la misma
        assertThat(cuentas.login("steve", k(1)).status()).isEqualTo(dev.sam.common.proto.auth.AuthResult.Status.OK);
    }

    @Test
    void sinLaContrasenaCorrectaOConCorreoInvalidoNoCambia() {
        var cuentas = servicio();
        assertThat(cuentas.changeEmail("steve", k(9), Optional.empty(), "nuevo@correo.cl")).isEqualTo(fallo(AccountService.WRONG_PASSWORD));
        assertThat(cuentas.changeEmail("nadie", k(1), Optional.empty(), "nuevo@correo.cl")).isEqualTo(fallo(AccountService.WRONG_PASSWORD));
        assertThat(cuentas.changeEmail("steve", k(1), Optional.empty(), "sin-arroba")).isEqualTo(fallo(AccountService.INVALID_EMAIL));
        assertThat(cambios).isEmpty();
        assertThat(cuentas.info("steve", true).email()).isEqualTo("s***@e***.com");
    }

    @Test
    void googleSeVinculaPorSuSubYDespuesEncuentraLaCuenta() {
        var cuentas = servicio();
        assertThat(cuentas.nickForGoogle("sub-de-steve")).isEmpty();
        assertThat(cuentas.linkGoogle("steve", "sub-de-steve")).isEqualTo(OK);
        assertThat(guardada("steve").googleSub()).contains("sub-de-steve");
        assertThat(cuentas.nickForGoogle("sub-de-steve")).contains("Steve");
        assertThat(cuentas.nickForGoogle("sub-de-alex")).contains("Alex");
        assertThat(cuentas.info("steve", true).google()).isEqualTo(AccountInfo.Google.LINKED);
    }

    @Test
    void unaCuentaDeGoogleVaAUnaSolaCuentaYCadaCuentaTieneUnaSola() {
        var cuentas = servicio();
        assertThat(cuentas.linkGoogle("steve", "sub-de-alex")).isEqualTo(fallo(AccountService.GOOGLE_TAKEN));
        assertThat(cuentas.linkGoogle("alex", "otro-sub")).isEqualTo(fallo(AccountService.GOOGLE_ALREADY));
        assertThat(cuentas.linkGoogle("nadie", "otro-sub")).isEqualTo(fallo(AccountService.GOOGLE_ALREADY));
        assertThat(cambios).isEmpty();
    }

    @Test
    void desvincularPideLaContrasena() {
        var cuentas = servicio();
        assertThat(cuentas.unlink("alex", k(9), Optional.empty(), OAuthProvider.GOOGLE)).isEqualTo(fallo(AccountService.WRONG_PASSWORD));
        assertThat(cuentas.unlink("steve", k(1), Optional.empty(), OAuthProvider.GOOGLE)).isEqualTo(fallo(AccountService.NOT_LINKED));
        assertThat(cuentas.unlink("alex", k(2), Optional.empty(), OAuthProvider.DISCORD)).isEqualTo(fallo(AccountService.NOT_LINKED));
        assertThat(cambios).isEmpty();
        assertThat(cuentas.unlink("alex", k(2), Optional.empty(), OAuthProvider.GOOGLE)).isEqualTo(OK);
        assertThat(guardada("alex").googleSub()).isEmpty();
        assertThat(cuentas.nickForGoogle("sub-de-alex")).isEmpty();
        // Libre otra vez: se puede vincular a otra cuenta
        assertThat(cuentas.linkGoogle("steve", "sub-de-alex")).isEqualTo(OK);
    }

    @Test
    void googleSeGuardaYSeCargaDelArchivo() {
        var cuentas = servicio();
        cuentas.linkGoogle("steve", "sub-123");
        var json = AccountsFile.encode(cambios.getLast());
        assertThat(json).contains("\"google\": \"sub-123\"");
        var leidas = AccountsFile.decode(json);
        assertThat(leidas).containsExactlyInAnyOrderElementsOf(cambios.getLast());
        // Sin Google, el campo no se escribe (y los archivos de antes siguen cargando)
        var sinGoogle = AccountsFile.encode(List.of(guardada("steve").withGoogleSub(Optional.empty())));
        assertThat(sinGoogle).doesNotContain("google");
        assertThat(AccountsFile.decode(sinGoogle).getFirst().googleSub()).isEmpty();
    }

    @Test
    void unArchivoConElMismoGoogleEnDosCuentasOVacioSeRechaza() {
        var steve = guardadaCon("steve", "Steve", "mismo");
        var alex = guardadaCon("alex", "Alex", "mismo");
        org.assertj.core.api.Assertions.assertThatThrownBy(() -> AccountsFile.decode(AccountsFile.encode(List.of(steve, alex))))
            .isInstanceOf(IllegalArgumentException.class).hasMessage("accounts.json inválido: Google repetido en steve");
        var vacio = AccountsFile.encode(List.of(steve)).replace("\"google\": \"mismo\"", "\"google\": \"\"");
        org.assertj.core.api.Assertions.assertThatThrownBy(() -> AccountsFile.decode(vacio))
            .isInstanceOf(IllegalArgumentException.class).hasMessage("accounts.json inválido: google vacío en la cuenta Steve");
    }

    private static Account guardadaCon(String key, String nick, String sub) {
        return new Account(key, nick, PasswordHash.create(k(1), RAPIDO, new SecureRandom()), key + "@example.com", Optional.of(sub));
    }

    @Test
    void elResetBorraLaCuentaYElJugadorVuelveARegistrarse() {
        var servicio = servicio();
        assertThat(servicio.reset("STEVE")).isTrue();
        assertThat(servicio.state("steve")).isEqualTo(dev.sam.common.proto.auth.AccountState.NEW);
        assertThat(cambios.getLast()).extracting(Account::key).containsExactly("alex");
        var antes = cambios.size();
        assertThat(servicio.reset("nadie")).isFalse();
        assertThat(cambios).hasSize(antes);
    }
}
