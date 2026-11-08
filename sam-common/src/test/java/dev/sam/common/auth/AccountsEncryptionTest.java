package dev.sam.common.auth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import dev.sam.common.totp.DataKey;
import dev.sam.common.totp.FieldCipher;
import dev.sam.common.totp.KeyRing;
import dev.sam.common.totp.TotpVault;

/** RF-CFG-12 (H-13, H-14): correo y Google cifrados en accounts.json, migración y rotación de la clave. */
class AccountsEncryptionTest {

    private static final DataKey A = DataKey.parse(DataKey.suggest(new SecureRandom()));
    private static final DataKey B = DataKey.parse(DataKey.suggest(new SecureRandom()));
    private static final String HASH = PasswordHash.create(AccountServiceTest.k(1), new Argon2Params(8, 1, 1), AccountServiceTest.ceros());
    private static final Account STEVE = new Account("steve", "Steve", HASH, "steve@example.com", Optional.of("sub-steve"));

    @TempDir
    Path dir;

    private static Optional<FieldCipher> con(DataKey actual, DataKey anterior) {
        return Optional.of(new FieldCipher(new KeyRing(actual, Optional.ofNullable(anterior)), new SecureRandom()));
    }

    @Test
    void conLaClaveElCorreoYGoogleNoQuedanEnClaro() throws Exception {
        var archivo = dir.resolve("accounts.json");
        AccountsFile.save(archivo, List.of(STEVE), con(A, null));
        var texto = Files.readString(archivo);
        assertThat(texto).doesNotContain("steve@example.com").doesNotContain("sub-steve").contains("\"email\": \"enc1:" + A.id());
        assertThat(AccountsFile.load(archivo, con(A, null))).containsExactly(STEVE);
    }

    @Test
    void losValoresViejosEnClaroSeLeenYSeCifranAlGuardar() throws Exception {
        var archivo = dir.resolve("accounts.json");
        AccountsFile.save(archivo, List.of(STEVE));
        assertThat(Files.readString(archivo)).contains("steve@example.com");
        var cuentas = AccountsFile.load(archivo, con(A, null));
        assertThat(cuentas).containsExactly(STEVE);
        AccountsFile.save(archivo, cuentas, con(A, null));
        assertThat(Files.readString(archivo)).doesNotContain("steve@example.com");
    }

    @Test
    void sinLaClaveUnArchivoCifradoNoAbre() throws Exception {
        var archivo = dir.resolve("accounts.json");
        AccountsFile.save(archivo, List.of(STEVE), con(A, null));
        assertThatThrownBy(() -> AccountsFile.load(archivo)).isInstanceOf(IllegalArgumentException.class)
            .hasMessageContaining("SAM_DATA_KEY");
        assertThatThrownBy(() -> AccountsFile.load(archivo, con(B, null))).isInstanceOf(IllegalArgumentException.class)
            .hasMessageContaining("SAM_DATA_KEY");
    }

    @Test
    void conLaAnteriorAbreYAlGuardarQuedaConLaNueva() throws Exception {
        var archivo = dir.resolve("accounts.json");
        AccountsFile.save(archivo, List.of(STEVE), con(A, null));
        var cuentas = AccountsFile.load(archivo, con(B, A));
        assertThat(cuentas).containsExactly(STEVE);
        AccountsFile.save(archivo, cuentas, con(B, A));
        assertThat(AccountsFile.load(archivo, con(B, null))).containsExactly(STEVE);
    }

    @Test
    void sinArchivoNoHayCuentasTampocoConClave() throws Exception {
        assertThat(AccountsFile.load(dir.resolve("no-existe.json"), con(A, null))).isEmpty();
    }

    @Test
    void unaCuentaSinNickSeRechazaAunConClave() {
        var json = "{\"version\":1,\"accounts\":[{\"hash\":\"" + HASH + "\",\"email\":\"s@e.com\"}]}";
        assertThatThrownBy(() -> AccountsFile.decode(json, con(A, null))).isInstanceOf(IllegalArgumentException.class)
            .hasMessageStartingWith("accounts.json inválido");
    }

    @Test
    void googleRepetidoSeDetectaAunCifrado() throws Exception {
        var archivo = dir.resolve("accounts.json");
        var alex = new Account("alex", "Alex", HASH, "alex@example.com", Optional.of("sub-steve"));
        AccountsFile.save(archivo, List.of(STEVE, alex), con(A, null));
        assertThatThrownBy(() -> AccountsFile.load(archivo, con(A, null))).isInstanceOf(IllegalArgumentException.class)
            .hasMessageContaining("Google repetido");
    }

    @Test
    void unCorreoDescifradoInvalidoSeRechaza() throws Exception {
        var archivo = dir.resolve("accounts.json");
        var raro = new Account("steve", "Steve", HASH, "no es un correo");
        Files.writeString(archivo, AccountsFile.encode(List.of(raro), con(A, null)));
        assertThatThrownBy(() -> AccountsFile.load(archivo, con(A, null))).isInstanceOf(IllegalArgumentException.class)
            .hasMessageContaining("correo");
    }

    @Test
    void rekeyVuelveASellarElDosFAConLaClaveNueva() {
        var guardado = new ArrayList<List<Account>>();
        var viejo = new AccountService(List.of(), new Argon2Params(8, 1, 1), new SecureRandom(), guardado::add,
            Optional.of(new TotpVault(A, new SecureRandom())), java.time.Clock.systemUTC());
        viejo.register("Steve", AccountServiceTest.k(1), "s@e.com");
        var inicio = viejo.beginTotp("steve", AccountServiceTest.k(1), "S");
        var secreto = AccountTotpTest.secreto(inicio.enrollment().orElseThrow().uri());
        var paso = java.time.Instant.now().getEpochSecond() / dev.sam.common.totp.Totp.PERIOD_SECONDS;
        viejo.confirmTotp("steve", dev.sam.common.totp.Totp.code(secreto, paso));
        List<Account> cuentas = guardado.getLast();
        var antes = guardado.size();
        // Una cuenta sin 2FA y otra con un 2FA que ninguna clave abre: no cuentan y no rompen nada
        var conAlex = new ArrayList<>(cuentas);
        conAlex.add(new Account("alex", "Alex", HASH, "a@e.com"));
        conAlex.add(new Account("zoe", "Zoe", HASH, "z@e.com", Optional.empty(), Optional.of("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")));
        cuentas = conAlex;
        var rotado = new AccountService(cuentas, new Argon2Params(8, 1, 1), new SecureRandom(), guardado::add,
            Optional.of(new TotpVault(new KeyRing(B, Optional.of(A)), new SecureRandom())), java.time.Clock.systemUTC());
        assertThat(rotado.rekey()).isEqualTo(1);
        assertThat(guardado).hasSize(antes + 1);
        var soloNueva = new AccountService(guardado.getLast(), new Argon2Params(8, 1, 1), new SecureRandom(), c -> { },
            Optional.of(new TotpVault(B, new SecureRandom())), java.time.Clock.systemUTC());
        assertThat(soloNueva.verifyTotp("steve", dev.sam.common.totp.Totp.code(secreto, paso + 1)).status())
            .isEqualTo(dev.sam.common.proto.account.AccountResult.Status.OK);
        var sinGuardar = new ArrayList<List<Account>>();
        var sinBoveda = new AccountService(List.of(new Account("alex", "Alex", HASH, "a@e.com")), new Argon2Params(8, 1, 1),
            new SecureRandom(), sinGuardar::add);
        assertThat(sinBoveda.rekey()).isZero();
        assertThat(sinGuardar).isEmpty();
    }
}
