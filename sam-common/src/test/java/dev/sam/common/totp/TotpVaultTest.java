package dev.sam.common.totp;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.security.SecureRandom;
import java.util.Base64;
import java.util.List;

import org.junit.jupiter.api.Test;

/**
 * El 2FA cifrado en reposo (RS-AUTH-03): AES-256-GCM con la clave de datos ({@code SAM_DATA_KEY}, del
 * entorno del proceso), atado a la cuenta. Cualquier alteración, otra clave u otra cuenta: no abre.
 */
class TotpVaultTest {

    private static String claveBase64(int valor) {
        var bytes = new byte[32];
        java.util.Arrays.fill(bytes, (byte) valor);
        return Base64.getEncoder().encodeToString(bytes);
    }

    private static final TotpState ESTADO = new TotpState("12345678901234567890".getBytes(), BackupCodes.hashes(List.of("aaaa-bbbb",
        "cccc-dddd")), 12345L);

    private static TotpVault boveda(int clave) {
        return new TotpVault(DataKey.parse(claveBase64(clave)), new SecureRandom());
    }

    @Test
    void loSelladoSeAbreConLaMismaClaveYCuenta() {
        var sellado = boveda(1).seal("steve", ESTADO);
        var abierto = boveda(1).open("steve", sellado).orElseThrow();
        assertThat(abierto.secret()).isEqualTo(ESTADO.secret());
        assertThat(abierto.backupHashes()).isEqualTo(ESTADO.backupHashes());
        assertThat(abierto.lastStep()).isEqualTo(12345L);
        assertThat(sellado).doesNotContain("12345678901234567890").doesNotContain(Totp.base32(ESTADO.secret()));
        assertThat(boveda(1).seal("steve", ESTADO)).as("nonce nuevo cada vez").isNotEqualTo(sellado);
        var sinRespaldos = new TotpState(new byte[] {7}, List.of(), 0);
        assertThat(boveda(1).open("x", boveda(1).seal("x", sinRespaldos)).orElseThrow().backupHashes()).isEmpty();
    }

    @Test
    void otraCuentaOtraClaveOAlteradoNoAbre() {
        var sellado = boveda(1).seal("steve", ESTADO);
        assertThat(boveda(1).open("alex", sellado)).as("otra cuenta").isEmpty();
        assertThat(boveda(2).open("steve", sellado)).as("otra clave").isEmpty();
        var bytes = Base64.getDecoder().decode(sellado);
        for (var i : List.of(0, 12, bytes.length - 1)) {
            var alterado = bytes.clone();
            alterado[i] ^= 1;
            assertThat(boveda(1).open("steve", Base64.getEncoder().encodeToString(alterado))).as("byte %d", i).isEmpty();
        }
        assertThat(boveda(1).open("steve", "no es base64!")).isEmpty();
        assertThat(boveda(1).open("steve", Base64.getEncoder().encodeToString(new byte[11]))).as("corto").isEmpty();
        assertThat(boveda(1).open("steve", "")).isEmpty();
    }

    @Test
    void laClaveDeDatosSonExactamente32BytesEnBase64() {
        assertThat(DataKey.parse("  " + claveBase64(3) + "\n")).isNotNull();
        for (var mala : List.of("", "corta", Base64.getEncoder().encodeToString(new byte[31]),
                Base64.getEncoder().encodeToString(new byte[33]), "%%%%")) {
            assertThatThrownBy(() -> DataKey.parse(mala)).as(mala).isInstanceOf(IllegalArgumentException.class)
                .hasMessage(DataKey.ENV + " debe ser 32 bytes aleatorios en base64");
        }
        assertThat(DataKey.parse(claveBase64(3)).toString()).isEqualTo("DataKey[***]").doesNotContain(claveBase64(3));
        assertThat(DataKey.suggest(new SecureRandom())).satisfies(s -> assertThat(DataKey.parse(s)).isNotNull())
            .isNotEqualTo(DataKey.suggest(new SecureRandom()));
    }

    @Test
    void unFormatoDeOtraVersionNoSeLee() {
        var plano = new byte[] {2, 1, 7, 0, 0, 0, 0, 0, 0, 0, 0, 0};
        assertThatThrownBy(() -> TotpVault.decode(plano)).isInstanceOf(IllegalArgumentException.class).hasMessage("versión desconocida");
        plano[0] = 1;
        assertThat(TotpVault.decode(plano).secret()).containsExactly(7);
    }
}
