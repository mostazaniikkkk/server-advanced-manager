package dev.sam.common.config;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.nio.file.Files;
import java.nio.file.Path;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** RF-CFG-08 / H-10: los secretos sugeridos van a un archivo solo del dueño, nunca al log. */
class SuggestedSecretsTest {

    @TempDir
    Path dir;

    private Path archivo() {
        return dir.resolve("config").resolve("sam").resolve("secretos-sugeridos.txt");
    }

    @Test
    void guardaElValorConInstruccionesYSoloParaElDueno() throws Exception {
        SuggestedSecrets.save(archivo(), "SAM_DATA_KEY", "abc123");
        var texto = Files.readString(archivo());
        assertThat(texto).startsWith("# ").contains("variable de entorno").contains("borra este archivo");
        assertThat(texto.lines()).contains("SAM_DATA_KEY=abc123");
        assertThat(FilePermissions.readableByOthers(archivo())).isFalse();
    }

    @Test
    void conservaLosOtrosYReemplazaElMismo() throws Exception {
        SuggestedSecrets.save(archivo(), "SAM_DATA_KEY", "uno");
        SuggestedSecrets.save(archivo(), "SAM_IDENTITY_PASSPHRASE", "dos");
        SuggestedSecrets.save(archivo(), "SAM_DATA_KEY", "tres");
        var lineas = Files.readString(archivo()).lines().filter(l -> !l.startsWith("#") && !l.isBlank()).toList();
        assertThat(lineas).containsExactly("SAM_DATA_KEY=tres", "SAM_IDENTITY_PASSPHRASE=dos");
    }

    @Test
    void ignoraLineasAjenasAlReescribir() throws Exception {
        Files.createDirectories(archivo().getParent());
        Files.writeString(archivo(), "basura sin igual\n=sin nombre\n# comentario=viejo\nOTRA=x=y\n");
        SuggestedSecrets.save(archivo(), "SAM_DATA_KEY", "v");
        var lineas = Files.readString(archivo()).lines().filter(l -> !l.startsWith("#") && !l.isBlank()).toList();
        assertThat(lineas).containsExactly("OTRA=x=y", "SAM_DATA_KEY=v");
        assertThat(Files.readString(archivo())).doesNotContain("comentario=viejo");
    }

    @Test
    void rechazaNombresOValoresQueRompanElFormato() {
        assertThatThrownBy(() -> SuggestedSecrets.save(archivo(), "sam data", "v")).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> SuggestedSecrets.save(archivo(), "SAM_X", "a\nb")).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> SuggestedSecrets.save(archivo(), "SAM_X", "")).isInstanceOf(IllegalArgumentException.class);
        assertThat(Files.exists(archivo())).isFalse();
    }
}
