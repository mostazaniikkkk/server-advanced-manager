package dev.sam.common.scripts;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Set;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** RS-LUA-05: el consentimiento de scripts recordado por servidor. */
class ScriptConsentsTest {

    private static final String PIN_A = "a".repeat(64);
    private static final String PIN_B = "b".repeat(64);
    private static final String SHA_1 = "1".repeat(64);
    private static final String SHA_2 = "2".repeat(64);

    @TempDir
    Path dir;

    private Path file() {
        return dir.resolve("sub").resolve("script-consents.properties");
    }

    @Test
    void sinNadaGuardadoNoCubreNada() {
        var consents = new ScriptConsents(file());
        assertThat(consents.covers(PIN_A, Set.of("homes:" + SHA_1))).isFalse();
    }

    @Test
    void recuerdaLoAceptadoYSobreviveAReabrir() {
        new ScriptConsents(file()).remember(PIN_A, List.of("homes:" + SHA_1, "mensajes:" + SHA_2));
        var consents = new ScriptConsents(file());
        assertThat(consents.covers(PIN_A, Set.of("mensajes:" + SHA_2, "homes:" + SHA_1))).isTrue();
        assertThat(consents.covers(PIN_A, Set.of("homes:" + SHA_1))).isTrue();
    }

    @Test
    void otroHashOtroScriptOOtroServidorVuelveAPreguntar() {
        var consents = new ScriptConsents(file());
        consents.remember(PIN_A, List.of("homes:" + SHA_1));
        assertThat(consents.covers(PIN_A, Set.of("homes:" + SHA_2))).isFalse();
        assertThat(consents.covers(PIN_A, Set.of("homes:" + SHA_1, "mensajes:" + SHA_2))).isFalse();
        assertThat(consents.covers(PIN_B, Set.of("homes:" + SHA_1))).isFalse();
    }

    @Test
    void unaOfertaVaciaNoSeDaPorCubierta() {
        var consents = new ScriptConsents(file());
        consents.remember(PIN_A, List.of("homes:" + SHA_1));
        assertThat(consents.covers(PIN_A, Set.of())).isFalse();
    }

    @Test
    void recordarReemplazaYOlvidarBorraSoloEseServidor() {
        var consents = new ScriptConsents(file());
        consents.remember(PIN_A, List.of("homes:" + SHA_1));
        consents.remember(PIN_B, List.of("homes:" + SHA_1));
        consents.remember(PIN_A, List.of("mensajes:" + SHA_2));
        assertThat(consents.covers(PIN_A, Set.of("homes:" + SHA_1))).isFalse();
        assertThat(consents.covers(PIN_A, Set.of("mensajes:" + SHA_2))).isTrue();
        consents.forget(PIN_A);
        var reabierto = new ScriptConsents(file());
        assertThat(reabierto.covers(PIN_A, Set.of("mensajes:" + SHA_2))).isFalse();
        assertThat(reabierto.covers(PIN_B, Set.of("homes:" + SHA_1))).isTrue();
    }

    @Test
    void elArchivoEsSoloDelDueno() throws Exception {
        try (var posix = com.google.common.jimfs.Jimfs.newFileSystem(com.google.common.jimfs.Configuration.unix().toBuilder()
                .setAttributeViews("basic", "owner", "posix").build())) {
            var archivo = posix.getPath("/cliente/config/sam-client/script-consents.properties");
            new ScriptConsents(archivo).remember(PIN_A, List.of("homes:" + SHA_1));
            assertThat(java.nio.file.attribute.PosixFilePermissions.toString(Files.getPosixFilePermissions(archivo)))
                .isEqualTo("rw-------");
        }
    }

    @Test
    void elArchivoEsLegibleYOrdenado() throws Exception {
        new ScriptConsents(file()).remember(PIN_A, List.of("mensajes:" + SHA_2, "homes:" + SHA_1));
        var text = Files.readString(file(), StandardCharsets.UTF_8);
        assertThat(text).contains(PIN_A + "=homes:" + SHA_1 + ",mensajes:" + SHA_2);
    }

    @Test
    void unaLineaRotaSeIgnoraYSeVuelveAPreguntar() throws Exception {
        Files.createDirectories(file().getParent());
        Files.writeString(file(), "esto no es un pin=homes:" + SHA_1 + "\n" + PIN_A + "\n" + PIN_B + "=homes:" + SHA_1 + "\n");
        var consents = new ScriptConsents(file());
        assertThat(consents.covers("esto no es un pin", Set.of("homes:" + SHA_1))).isFalse();
        assertThat(consents.covers(PIN_B, Set.of("homes:" + SHA_1))).isTrue();
    }

    @Test
    void noGuardaNiConsultaPinsNiEntradasInvalidos() {
        var consents = new ScriptConsents(file());
        assertThatThrownBy(() -> consents.remember("zz", List.of("homes:" + SHA_1))).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> consents.remember(PIN_A, List.of("homes=x"))).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> consents.remember(PIN_A, List.of("homes:" + SHA_1 + ",x:" + SHA_2)))
            .isInstanceOf(IllegalArgumentException.class);
        assertThat(Files.exists(file())).isFalse();
    }

    @Test
    void unaEntradaRotaDentroDeUnaLineaSeDescarta() throws Exception {
        Files.createDirectories(file().getParent());
        Files.writeString(file(), PIN_A + "=homes:" + SHA_1 + ",NO VALE\n");
        var consents = new ScriptConsents(file());
        assertThat(consents.covers(PIN_A, Set.of("homes:" + SHA_1))).isTrue();
        assertThat(consents.covers(PIN_A, Set.of("NO VALE"))).isFalse();
    }

    @Test
    void olvidarUnServidorDesconocidoNoEscribeNada() {
        var consents = new ScriptConsents(file());
        consents.forget(PIN_A);
        assertThat(Files.exists(file())).isFalse();
        assertThatThrownBy(() -> consents.forget("zz")).isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void siNoSePuedeEscribirLanzaUncheckedIo() throws Exception {
        Files.writeString(dir.resolve("sub"), "un archivo donde debería ir la carpeta");
        var consents = new ScriptConsents(file());
        assertThatThrownBy(() -> consents.remember(PIN_A, List.of("homes:" + SHA_1))).isInstanceOf(UncheckedIOException.class);
    }

    @Test
    void entradaDeUnScript() {
        assertThat(ScriptConsents.entry("homes", new byte[] {0x0a, (byte) 0xff})).isEqualTo("homes:0aff");
    }
}
