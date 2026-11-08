package dev.sam.common.auth;

import static org.assertj.core.api.Assertions.assertThat;

import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import org.junit.jupiter.api.Test;

import dev.sam.common.proto.account.AccountResult;

/** RF-AUTH-07e (H-15): exportar y borrar la cuenta con reautenticación. */
class AccountDataServiceTest {

    private final List<List<Account>> guardado = new ArrayList<>();
    private final AccountService cuentas = new AccountService(List.of(), new Argon2Params(8, 1, 1), new SecureRandom(), guardado::add);

    @Test
    void exportarDevuelveTodoSinEnmascarar() {
        cuentas.register("Steve", AccountServiceTest.k(1), "steve@example.com");
        cuentas.linkGoogle("steve", "sub-1");
        var r = cuentas.export("Steve", AccountServiceTest.k(1), Optional.empty());
        assertThat(r.result().status()).isEqualTo(AccountResult.Status.OK);
        assertThat(r.data()).contains(new AccountService.Export("Steve", "steve@example.com", true, false));
    }

    @Test
    void conLaContrasenaMalaNadaSeExportaNiSeBorra() {
        cuentas.register("Steve", AccountServiceTest.k(1), "steve@example.com");
        var r = cuentas.export("steve", AccountServiceTest.k(9), Optional.empty());
        assertThat(r.result()).isEqualTo(new AccountResult(AccountResult.Status.FAILED, Optional.of(AccountService.WRONG_PASSWORD)));
        assertThat(r.data()).isEmpty();
        var antes = guardado.size();
        assertThat(cuentas.delete("steve", AccountServiceTest.k(9), Optional.empty()).status()).isEqualTo(AccountResult.Status.FAILED);
        assertThat(guardado).hasSize(antes);
        assertThat(cuentas.state("steve")).isEqualTo(dev.sam.common.proto.auth.AccountState.REGISTERED);
    }

    @Test
    void borrarQuitaLaCuentaYGuarda() {
        cuentas.register("Steve", AccountServiceTest.k(1), "steve@example.com");
        cuentas.register("Alex", AccountServiceTest.k(2), "alex@example.com");
        assertThat(cuentas.delete("STEVE", AccountServiceTest.k(1), Optional.empty()).status()).isEqualTo(AccountResult.Status.OK);
        assertThat(cuentas.state("steve")).isEqualTo(dev.sam.common.proto.auth.AccountState.NEW);
        assertThat(guardado.getLast()).extracting(Account::nick).containsExactly("Alex");
    }

    @Test
    void conDosFAHaceFaltaElCodigo() {
        var servicio = new AccountService(List.of(), new Argon2Params(8, 1, 1), new SecureRandom(), guardado::add,
            Optional.of(new dev.sam.common.totp.TotpVault(dev.sam.common.totp.DataKey.parse(
                dev.sam.common.totp.DataKey.suggest(new SecureRandom())), new SecureRandom())), java.time.Clock.systemUTC());
        servicio.register("Steve", AccountServiceTest.k(1), "steve@example.com");
        var inicio = servicio.beginTotp("steve", AccountServiceTest.k(1), "S");
        var secreto = AccountTotpTest.secreto(inicio.enrollment().orElseThrow().uri());
        var paso = java.time.Instant.now().getEpochSecond() / dev.sam.common.totp.Totp.PERIOD_SECONDS;
        servicio.confirmTotp("steve", dev.sam.common.totp.Totp.code(secreto, paso));
        assertThat(servicio.export("steve", AccountServiceTest.k(1), Optional.empty()).result().status())
            .isEqualTo(AccountResult.Status.FAILED);
        var r = servicio.export("steve", AccountServiceTest.k(1), Optional.of(dev.sam.common.totp.Totp.code(secreto, paso + 1)));
        assertThat(r.data()).contains(new AccountService.Export("Steve", "steve@example.com", false, true));
        assertThat(servicio.delete("steve", AccountServiceTest.k(1), Optional.empty()).status()).isEqualTo(AccountResult.Status.FAILED);
        assertThat(servicio.state("steve")).isEqualTo(dev.sam.common.proto.auth.AccountState.REGISTERED);
    }
}
