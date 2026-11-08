package dev.sam.signer;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.HashMap;
import java.util.HexFormat;
import java.util.Map;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import dev.sam.common.config.FilePermissions;

/** RF-CFG-11 (H-16): sam-signer backup-key, backup-seal y backup-open. */
class SamSignerBackupTest {

    @TempDir
    Path dir;

    private final ByteArrayOutputStream salida = new ByteArrayOutputStream();
    private final Map<String, String> entorno = new HashMap<>();

    private int run(String... args) {
        return SamSigner.run(args, new SamSigner.Env(dir, new PrintStream(salida, true, StandardCharsets.UTF_8),
            prompt -> null, new SecureRandom(), 1000, entorno::get));
    }

    private String texto() {
        return salida.toString(StandardCharsets.UTF_8);
    }

    private static String sha256(byte[] datos) throws Exception {
        return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(datos));
    }

    @Test
    void backupKeyMuestraUnaClaveNuevaYComoUsarla() {
        assertThat(run("backup-key")).isZero();
        var clave = texto().lines().filter(l -> l.startsWith("SAM_BACKUP_KEY=")).findFirst().orElseThrow().substring(15);
        assertThat(Base64.getDecoder().decode(clave)).hasSize(32);
        assertThat(texto()).contains("variable de entorno");
    }

    @Test
    void sellarYAbrirConHashAlLado() throws Exception {
        entorno.put("SAM_BACKUP_KEY", Base64.getEncoder().encodeToString(new byte[32]));
        var zip = dir.resolve("respaldo.zip");
        Files.write(zip, "contenido del respaldo".getBytes(StandardCharsets.UTF_8));
        assertThat(run("backup-seal", "respaldo.zip", "respaldo.sambk")).isZero();
        var sellado = dir.resolve("respaldo.sambk");
        assertThat(Files.readAllBytes(sellado)).startsWith("SAMBK1".getBytes(StandardCharsets.US_ASCII));
        assertThat(FilePermissions.readableByOthers(sellado)).isFalse();
        assertThat(Files.readString(dir.resolve("respaldo.sambk.sha256")))
            .isEqualTo(sha256(Files.readAllBytes(sellado)) + "  respaldo.sambk\n");
        assertThat(run("backup-open", "respaldo.sambk", "vuelta.zip")).isZero();
        assertThat(Files.readString(dir.resolve("vuelta.zip"))).isEqualTo("contenido del respaldo");
        assertThat(FilePermissions.readableByOthers(dir.resolve("vuelta.zip"))).isFalse();
        assertThat(texto()).contains("respaldo.sambk").contains("vuelta.zip");
    }

    @Test
    void noPisaArchivosNiAbreConElHashCambiado() throws Exception {
        entorno.put("SAM_BACKUP_KEY", Base64.getEncoder().encodeToString(new byte[32]));
        Files.writeString(dir.resolve("a.zip"), "x");
        assertThat(run("backup-seal", "a.zip", "a.sambk")).isZero();
        assertThat(run("backup-seal", "a.zip", "a.sambk")).isEqualTo(1);
        assertThat(texto()).contains("ya existe");
        Files.writeString(dir.resolve("a.sambk.sha256"), "0".repeat(64) + "  a.sambk\n");
        assertThat(run("backup-open", "a.sambk", "b.zip")).isEqualTo(1);
        assertThat(texto()).contains("hash");
        assertThat(Files.exists(dir.resolve("b.zip"))).isFalse();
        Files.delete(dir.resolve("a.sambk.sha256"));
        assertThat(run("backup-open", "a.sambk", "b.zip")).isEqualTo(1);
        assertThat(texto()).contains("falta a.sambk.sha256");
        assertThat(run("backup-seal", "a.zip", "c.sambk")).isZero();
        assertThat(run("backup-open", "c.sambk", "a.zip")).isEqualTo(1);
        assertThat(texto()).contains("a.zip ya existe");
    }

    @Test
    void sinClaveOConOtraClaveFalla() throws Exception {
        Files.writeString(dir.resolve("a.zip"), "x");
        assertThat(run("backup-seal", "a.zip", "a.sambk")).isEqualTo(1);
        assertThat(texto()).contains("SAM_BACKUP_KEY");
        assertThat(Files.exists(dir.resolve("a.sambk"))).isFalse();
        entorno.put("SAM_BACKUP_KEY", Base64.getEncoder().encodeToString(new byte[32]));
        assertThat(run("backup-seal", "a.zip", "a.sambk")).isZero();
        var otra = new byte[32];
        otra[0] = 1;
        entorno.put("SAM_BACKUP_KEY", Base64.getEncoder().encodeToString(otra));
        assertThat(run("backup-open", "a.sambk", "b.zip")).isEqualTo(1);
        assertThat(texto()).contains("clave");
        assertThat(Files.exists(dir.resolve("b.zip"))).isFalse();
    }

    @Test
    void argumentosIncompletosMuestranElUso() {
        assertThat(run("backup-seal", "solo-uno")).isEqualTo(2);
        assertThat(texto()).contains("backup-seal").contains("backup-open").contains("backup-key");
    }
}
