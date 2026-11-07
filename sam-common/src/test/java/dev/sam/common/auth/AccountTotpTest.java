package dev.sam.common.auth;

import static org.assertj.core.api.Assertions.assertThat;

import java.security.SecureRandom;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;

import org.junit.jupiter.api.Test;

import dev.sam.common.proto.account.AccountInfo;
import dev.sam.common.proto.account.AccountResult;
import dev.sam.common.proto.account.OAuthProvider;
import dev.sam.common.totp.DataKey;
import dev.sam.common.totp.Totp;
import dev.sam.common.totp.TotpVault;

/**
 * El 2FA de una cuenta (RF-AUTH-04, 5.0): se activa con la contraseña y se confirma con un primer código;
 * se guarda cifrado (RS-AUTH-03); con el 2FA activo, cambiar el correo, desvincular Google y desactivarlo
 * piden también el código.
 */
class AccountTotpTest {

    private static final Argon2Params RAPIDO = new Argon2Params(8, 1, 1);
    private static final AccountResult OK = new AccountResult(AccountResult.Status.OK, Optional.empty());
    private static final Optional<String> SIN = Optional.empty();

    static byte[] k(int valor) {
        var k = new byte[32];
        Arrays.fill(k, (byte) valor);
        return k;
    }

    private static final class Reloj extends Clock {
        Instant ahora = Instant.parse("2026-11-07T12:00:00Z");

        @Override
        public Instant instant() {
            return ahora;
        }

        @Override
        public ZoneId getZone() {
            return ZoneOffset.UTC;
        }

        @Override
        public Clock withZone(ZoneId zone) {
            return this;
        }
    }

    private final Reloj reloj = new Reloj();
    private final List<List<Account>> cambios = new ArrayList<>();
    private final TotpVault boveda = new TotpVault(DataKey.parse(DataKey.suggest(new SecureRandom())), new SecureRandom());

    private AccountService servicio(boolean conClave) {
        var steve = new Account("steve", "Steve", PasswordHash.create(k(1), RAPIDO, new SecureRandom()), "steve@example.com",
            Optional.of("sub-steve"));
        return new AccountService(List.of(steve), RAPIDO, new SecureRandom(), cambios::add,
            conClave ? Optional.of(boveda) : Optional.empty(), reloj);
    }

    private static AccountResult fallo(String detalle) {
        return new AccountResult(AccountResult.Status.FAILED, Optional.of(detalle));
    }

    /** El secreto, sacado de la URI otpauth del QR (como lo haría la app). */
    private static byte[] secreto(String uri) {
        var base32 = uri.replaceAll(".*[?&]secret=([A-Z2-7]+).*", "$1");
        var alfabeto = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
        var salida = new java.io.ByteArrayOutputStream();
        int buffer = 0;
        int bits = 0;
        for (var c : base32.toCharArray()) {
            buffer = (buffer << 5) | alfabeto.indexOf(c);
            bits += 5;
            if (bits >= 8) {
                salida.write((buffer >> (bits - 8)) & 0xFF);
                bits -= 8;
            }
        }
        return salida.toByteArray();
    }

    private String codigo(byte[] secreto) {
        return Totp.code(secreto, reloj.ahora.getEpochSecond() / Totp.PERIOD_SECONDS);
    }

    private byte[] activar(AccountService cuentas) {
        var inicio = cuentas.beginTotp("steve", k(1), "BlockSouls");
        assertThat(inicio.result()).isEqualTo(OK);
        var secreto = secreto(inicio.enrollment().orElseThrow().uri());
        assertThat(cuentas.confirmTotp("steve", codigo(secreto))).isEqualTo(OK);
        reloj.ahora = reloj.ahora.plusSeconds(Totp.PERIOD_SECONDS);
        return secreto;
    }

    @Test
    void sinClaveDeDatosElDosFANoEstaDisponible() {
        var cuentas = servicio(false);
        assertThat(cuentas.info("steve", true).totp()).isEqualTo(AccountInfo.Totp.UNAVAILABLE);
        var inicio = cuentas.beginTotp("steve", k(1), "S");
        assertThat(inicio.result()).isEqualTo(fallo(AccountService.TOTP_UNAVAILABLE));
        assertThat(inicio.enrollment()).isEmpty();
        assertThat(cuentas.hasTotp("steve")).isFalse();
        assertThat(cuentas.hasTotp("nadie")).isFalse();
    }

    @Test
    void activarPideLaContrasenaMuestraElQrYSeConfirmaConUnCodigo() {
        var cuentas = servicio(true);
        assertThat(cuentas.info("steve", true).totp()).isEqualTo(AccountInfo.Totp.OFF);
        assertThat(cuentas.beginTotp("steve", k(9), "S").result()).isEqualTo(fallo(AccountService.WRONG_PASSWORD));
        var inicio = cuentas.beginTotp("Steve", k(1), "BlockSouls");
        var enrolamiento = inicio.enrollment().orElseThrow();
        assertThat(enrolamiento.uri()).startsWith("otpauth://totp/BlockSouls:Steve?secret=");
        assertThat(enrolamiento.backupCodes()).hasSize(10);
        assertThat(cambios).as("nada se guarda hasta confirmar").isEmpty();
        assertThat(cuentas.hasTotp("steve")).isFalse();

        var secreto = secreto(enrolamiento.uri());
        assertThat(cuentas.confirmTotp("steve", "000000".equals(codigo(secreto)) ? "111111" : "000000"))
            .isEqualTo(fallo(AccountService.WRONG_CODE));
        assertThat(cuentas.confirmTotp("steve", enrolamiento.backupCodes().get(0))).as("hay que probar la app, no un respaldo")
            .isEqualTo(fallo(AccountService.WRONG_CODE));
        assertThat(cuentas.confirmTotp("steve", codigo(secreto))).isEqualTo(OK);
        assertThat(cuentas.hasTotp("STEVE")).isTrue();
        assertThat(cuentas.info("steve", true).totp()).isEqualTo(AccountInfo.Totp.ON);
        // Se guarda cifrado: ni el secreto ni los códigos aparecen en el archivo
        var json = AccountsFile.encode(cambios.getLast());
        assertThat(json).contains("\"totp\": \"").doesNotContain(Totp.base32(secreto)).doesNotContain(enrolamiento.backupCodes().get(0));
        assertThat(AccountsFile.decode(json)).containsExactlyElementsOf(cambios.getLast());
        var vacio = json.replaceAll("\"totp\": \"[^\"]+\"", "\"totp\": \"\"");
        org.assertj.core.api.Assertions.assertThatThrownBy(() -> AccountsFile.decode(vacio))
            .isInstanceOf(IllegalArgumentException.class).hasMessage("accounts.json inválido: totp vacío en la cuenta Steve");
        // Confirmar sin haber empezado, o activar dos veces, no vale
        assertThat(cuentas.confirmTotp("steve", codigo(secreto))).isEqualTo(fallo(AccountService.WRONG_CODE));
        assertThat(cuentas.beginTotp("steve", k(1), "S").result()).isEqualTo(fallo(AccountService.TOTP_ALREADY));
    }

    @Test
    void elCodigoValeUnaVezYLosDeRespaldoTambien() {
        var cuentas = servicio(true);
        var inicio = cuentas.beginTotp("steve", k(1), "S");
        var respaldos = inicio.enrollment().orElseThrow().backupCodes();
        var secreto = secreto(inicio.enrollment().get().uri());
        cuentas.confirmTotp("steve", codigo(secreto));
        assertThat(cuentas.verifyTotp("steve", codigo(secreto))).as("el de la confirmación ya se usó")
            .isEqualTo(fallo(AccountService.WRONG_CODE));
        reloj.ahora = reloj.ahora.plusSeconds(Totp.PERIOD_SECONDS);
        var actual = codigo(secreto);
        assertThat(cuentas.verifyTotp("steve", actual)).isEqualTo(OK);
        assertThat(cuentas.verifyTotp("steve", actual)).as("repetido").isEqualTo(fallo(AccountService.WRONG_CODE));
        assertThat(cuentas.verifyTotp("steve", respaldos.get(0))).isEqualTo(OK);
        assertThat(cuentas.verifyTotp("steve", respaldos.get(0))).isEqualTo(fallo(AccountService.WRONG_CODE));
        assertThat(cuentas.verifyTotp("nadie", actual)).isEqualTo(fallo(AccountService.WRONG_CODE));
    }

    @Test
    void conDosFACambiarElCorreoODesvincularPidenElCodigo() {
        var cuentas = servicio(true);
        var secreto = activar(cuentas);
        assertThat(cuentas.changeEmail("steve", k(1), SIN, "n@correo.cl")).isEqualTo(fallo(AccountService.CODE_REQUIRED));
        assertThat(cuentas.changeEmail("steve", k(1), Optional.of("123"), "n@correo.cl")).isEqualTo(fallo(AccountService.WRONG_CODE));
        // Con la contraseña mala no se gasta el código
        assertThat(cuentas.changeEmail("steve", k(9), Optional.of(codigo(secreto)), "n@correo.cl"))
            .isEqualTo(fallo(AccountService.WRONG_PASSWORD));
        assertThat(cuentas.info("steve", true).email()).as("todavía no cambió").isEqualTo("s***@e***.com");
        assertThat(cuentas.changeEmail("steve", k(1), Optional.of(codigo(secreto)), "n@correo.cl")).isEqualTo(OK);
        assertThat(cuentas.info("steve", true).email()).isEqualTo("n***@c***.cl");
        reloj.ahora = reloj.ahora.plusSeconds(Totp.PERIOD_SECONDS);
        assertThat(cuentas.unlink("steve", k(1), SIN, OAuthProvider.GOOGLE)).isEqualTo(fallo(AccountService.CODE_REQUIRED));
        assertThat(cuentas.unlink("steve", k(1), Optional.of(codigo(secreto)), OAuthProvider.GOOGLE)).isEqualTo(OK);
        assertThat(cuentas.info("steve", true).google()).isEqualTo(AccountInfo.Google.AVAILABLE);
    }

    @Test
    void desactivarPideContrasenaYCodigo() {
        var cuentas = servicio(true);
        var secreto = activar(cuentas);
        assertThat(cuentas.disableTotp("steve", k(9), codigo(secreto))).isEqualTo(fallo(AccountService.WRONG_PASSWORD));
        assertThat(cuentas.disableTotp("steve", k(1), "000")).isEqualTo(fallo(AccountService.WRONG_CODE));
        assertThat(cuentas.hasTotp("steve")).isTrue();
        assertThat(cuentas.disableTotp("steve", k(1), codigo(secreto))).isEqualTo(OK);
        assertThat(cuentas.hasTotp("steve")).isFalse();
        assertThat(cambios.getLast().getFirst().totp()).isEmpty();
        assertThat(cuentas.disableTotp("steve", k(1), codigo(secreto))).isEqualTo(fallo(AccountService.WRONG_CODE));
        // Sin 2FA, el correo vuelve a cambiarse solo con la contraseña
        assertThat(cuentas.changeEmail("steve", k(1), SIN, "n@correo.cl")).isEqualTo(OK);
    }

    @Test
    void siLaClaveDeDatosCambioElDosFANoSeAbreYNoSeDejaPasar() {
        var cuentas = servicio(true);
        var secreto = activar(cuentas);
        var otraClave = new TotpVault(DataKey.parse(DataKey.suggest(new SecureRandom())), new SecureRandom());
        var reiniciado = new AccountService(cambios.getLast(), RAPIDO, new SecureRandom(), cambios::add, Optional.of(otraClave), reloj);
        assertThat(reiniciado.hasTotp("steve")).isTrue();
        assertThat(reiniciado.verifyTotp("steve", codigo(secreto))).isEqualTo(fallo(AccountService.WRONG_CODE));
        var sinClave = new AccountService(cambios.getLast(), RAPIDO, new SecureRandom(), cambios::add, Optional.empty(), reloj);
        assertThat(sinClave.hasTotp("steve")).as("sigue exigiéndose aunque falte la clave").isTrue();
        assertThat(sinClave.verifyTotp("steve", codigo(secreto))).isEqualTo(fallo(AccountService.WRONG_CODE));
        assertThat(sinClave.info("steve", true).totp()).isEqualTo(AccountInfo.Totp.ON);
    }
}
