package dev.sam.common.totp;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.HashSet;
import java.util.List;

import org.junit.jupiter.api.Test;

/**
 * 2FA con TOTP (RF-AUTH-04, RFC 6238): códigos de 6 dígitos, pasos de 30 s, ventana de ±1 paso y un
 * código ya usado no vuelve a valer. Códigos de respaldo de un solo uso, guardados solo como hash.
 */
class TotpTest {

    private static final byte[] RFC_SECRET = "12345678901234567890".getBytes(StandardCharsets.US_ASCII);

    @Test
    void base32SigueElRfc4648SinRelleno() {
        var casos = List.of("", "", "f", "MY", "fo", "MZXQ", "foo", "MZXW6", "foob", "MZXW6YQ", "fooba", "MZXW6YTB", "foobar",
            "MZXW6YTBOI");
        for (int i = 0; i < casos.size(); i += 2) {
            assertThat(Totp.base32(casos.get(i).getBytes(StandardCharsets.US_ASCII))).isEqualTo(casos.get(i + 1));
        }
    }

    @Test
    void losCodigosSiguenLosVectoresDelRfc6238() {
        // RFC 6238, apéndice B (SHA1): los últimos 6 de los 8 dígitos
        long[] tiempos = {59L, 1111111109L, 1111111111L, 1234567890L, 2000000000L, 20000000000L};
        String[] codigos = {"287082", "081804", "050471", "005924", "279037", "353130"};
        for (int i = 0; i < tiempos.length; i++) {
            assertThat(Totp.code(RFC_SECRET, tiempos[i] / Totp.PERIOD_SECONDS)).isEqualTo(codigos[i]);
        }
    }

    private static TotpState estado(long ultimoPaso) {
        return new TotpState(RFC_SECRET, List.of(), ultimoPaso);
    }

    @Test
    void valeElPasoActualYUnoAntesODespues() {
        var ahora = Instant.ofEpochSecond(1111111111L);
        var paso = 1111111111L / 30;
        for (var desfase : List.of(-1L, 0L, 1L)) {
            var usado = Totp.check(estado(0), Totp.code(RFC_SECRET, paso + desfase), ahora);
            assertThat(usado).as("desfase %d", desfase).isPresent();
            assertThat(usado.get().lastStep()).isEqualTo(paso + desfase);
        }
        for (var desfase : List.of(-2L, 2L)) {
            assertThat(Totp.check(estado(0), Totp.code(RFC_SECRET, paso + desfase), ahora)).as("desfase %d", desfase).isEmpty();
        }
    }

    @Test
    void unCodigoYaUsadoOAnteriorNoVuelveAValer() {
        var ahora = Instant.ofEpochSecond(1111111111L);
        var paso = 1111111111L / 30;
        var codigo = Totp.code(RFC_SECRET, paso);
        var usado = Totp.check(estado(0), codigo, ahora).orElseThrow();
        assertThat(Totp.check(usado, codigo, ahora)).as("repetido").isEmpty();
        assertThat(Totp.check(usado, Totp.code(RFC_SECRET, paso - 1), ahora)).as("anterior al usado").isEmpty();
        assertThat(Totp.check(usado, Totp.code(RFC_SECRET, paso + 1), ahora)).as("el siguiente sí").isPresent();
    }

    @Test
    void loQueNoSonSeisDigitosNoEsUnCodigo() {
        var ahora = Instant.ofEpochSecond(59L);
        for (var malo : List.of("28708", "2870822", "28708a", "", " 287082", "２８７０８２")) {
            assertThat(Totp.check(estado(0), malo, ahora)).as(malo).isEmpty();
        }
        assertThat(Totp.check(estado(0), "287082", ahora)).isPresent();
    }

    @Test
    void losCodigosDeRespaldoSonDeUnSoloUsoYSoloSeGuardaSuHash() {
        var codigos = BackupCodes.generate(new SecureRandom());
        assertThat(codigos).hasSize(10);
        assertThat(new HashSet<>(codigos)).hasSize(10);
        assertThat(codigos).allMatch(c -> c.matches("[a-hjkmnp-z2-9]{4}-[a-hjkmnp-z2-9]{4}"));
        var hashes = BackupCodes.hashes(codigos);
        assertThat(hashes).hasSize(10).allMatch(h -> h.matches("[0-9a-f]{64}")).doesNotContainAnyElementsOf(codigos);

        var estado = new TotpState(RFC_SECRET, hashes, 7);
        var ahora = Instant.ofEpochSecond(1111111111L);
        // Se acepta sin el guion, en mayúsculas y con espacios alrededor
        var tolerante = codigos.get(3).toUpperCase().replace("-", "");
        var usado = Totp.check(estado, "  " + tolerante + " ", ahora).orElseThrow();
        assertThat(usado.backupHashes()).hasSize(9).doesNotContain(hashes.get(3));
        assertThat(usado.lastStep()).as("el respaldo no mueve el paso").isEqualTo(7);
        assertThat(Totp.check(usado, codigos.get(3), ahora)).as("un solo uso").isEmpty();
        assertThat(Totp.check(usado, codigos.get(4), ahora)).isPresent();
        assertThat(Totp.check(usado, "zzzz-zzzz", ahora)).isEmpty();
    }

    @Test
    void laUriDeEnrolamientoEsLaDeLasAppsDeAutenticacion() {
        var uri = Totp.otpauthUri("BlockSouls QA", "Steve", "foobar".getBytes(StandardCharsets.US_ASCII));
        assertThat(uri).isEqualTo("otpauth://totp/BlockSouls%20QA:Steve?secret=MZXW6YTBOI&issuer=BlockSouls%20QA"
            + "&algorithm=SHA1&digits=6&period=30");
    }

    @Test
    void unSecretoNuevoTiene20BytesAleatorios() {
        var a = Totp.newSecret(new SecureRandom());
        assertThat(a).hasSize(20);
        assertThat(Totp.newSecret(new SecureRandom())).isNotEqualTo(a);
    }

    @Test
    void elEstadoCopiaElSecretoYValida() {
        var secreto = RFC_SECRET.clone();
        var estado = new TotpState(secreto, List.of(), 0);
        secreto[0] = 0;
        assertThat(estado.secret()[0]).isEqualTo((byte) '1');
        estado.secret()[1] = 0;
        assertThat(estado.secret()[1]).isEqualTo((byte) '2');
        assertThatThrownBy(() -> new TotpState(new byte[0], List.of(), 0)).isInstanceOf(IllegalArgumentException.class)
            .hasMessage("secreto TOTP vacío");
    }
}
