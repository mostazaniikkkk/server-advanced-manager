package dev.sam.common.identity;

import static org.assertj.core.api.Assertions.assertThat;

import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.Map;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import dev.sam.common.identity.ServerIdentityBootstrap.Disabled;
import dev.sam.common.identity.ServerIdentityBootstrap.Ready;

/**
 * Arranque de la identidad del servidor (RF-CFG-08, RF-CFG-04, RS-NET-02): la passphrase solo
 * viene de la variable de entorno real. Si falta, el primer arranque sugiere una aleatoria (que se
 * muestra una vez y no se guarda) y el login queda cerrado. Cualquier problema falla cerrado sin
 * tumbar el servidor y sin regenerar la identidad.
 */
class ServerIdentityBootstrapTest {

    private static final Instant AHORA = Instant.parse("2026-11-05T12:00:00Z");
    private static final String CLAVE = "una passphrase de prueba larga";
    private static final Map<String, String> CON_CLAVE = Map.of(ServerIdentityBootstrap.PASSPHRASE_ENV, CLAVE);

    @TempDir
    Path dir;

    private Path archivo() {
        return dir.resolve("keys/identity.p12");
    }

    @Test
    void sinVariableYSinArchivoSugiereUnaPassphraseYNoCreaNada() {
        var resultado = ServerIdentityBootstrap.start(Map.of(), archivo(), new SecureRandom(), AHORA);
        assertThat(resultado).isInstanceOf(Disabled.class);
        var cerrado = (Disabled) resultado;
        assertThat(cerrado.reason()).contains(ServerIdentityBootstrap.PASSPHRASE_ENV);
        assertThat(cerrado.suggestedPassphrase()).hasValueSatisfying(
            sugerida -> assertThat(sugerida).matches("[A-Za-z0-9_-]{43}"));
        assertThat(archivo()).doesNotExist();
    }

    @Test
    void cadaSugerenciaEsAleatoria() {
        var a = (Disabled) ServerIdentityBootstrap.start(Map.of(), archivo(), new SecureRandom(), AHORA);
        var b = (Disabled) ServerIdentityBootstrap.start(Map.of(), archivo(), new SecureRandom(), AHORA);
        assertThat(a.suggestedPassphrase()).isNotEqualTo(b.suggestedPassphrase());
    }

    @Test
    void unaVariableEnBlancoCuentaComoAusente() {
        var resultado = ServerIdentityBootstrap.start(
            Map.of(ServerIdentityBootstrap.PASSPHRASE_ENV, " \t"), archivo(), new SecureRandom(), AHORA);
        assertThat(resultado).isInstanceOf(Disabled.class);
        assertThat(((Disabled) resultado).suggestedPassphrase()).isPresent();
        assertThat(archivo()).doesNotExist();
    }

    @Test
    void sinVariableConArchivoExistenteNoSugiereNadaYNoLoToca() throws Exception {
        ServerIdentityStore.loadOrCreate(archivo(), CLAVE.toCharArray(), new SecureRandom(), AHORA);
        var antes = Files.readAllBytes(archivo());
        var resultado = ServerIdentityBootstrap.start(Map.of(), archivo(), new SecureRandom(), AHORA);
        assertThat(resultado).isInstanceOf(Disabled.class);
        var cerrado = (Disabled) resultado;
        // Una passphrase nueva no abriría el archivo existente: sugerirla confundiría al admin
        assertThat(cerrado.suggestedPassphrase()).isEmpty();
        assertThat(cerrado.reason()).contains(ServerIdentityBootstrap.PASSPHRASE_ENV);
        assertThat(Files.readAllBytes(archivo())).isEqualTo(antes);
    }

    @Test
    void conVariableElPrimerArranqueCreaLaIdentidad() {
        var resultado = ServerIdentityBootstrap.start(CON_CLAVE, archivo(), new SecureRandom(), AHORA);
        assertThat(resultado).isInstanceOf(Ready.class);
        assertThat(((Ready) resultado).created()).isTrue();
        assertThat(archivo()).exists();
    }

    @Test
    void conVariableLosSiguientesArranquesCarganLaMisma() {
        var primera = ServerIdentityStore.loadOrCreate(archivo(), CLAVE.toCharArray(), new SecureRandom(), AHORA).identity();
        var segunda = ServerIdentityBootstrap.start(CON_CLAVE, archivo(), new SecureRandom(), AHORA);
        assertThat(segunda).isInstanceOfSatisfying(Ready.class, listo -> {
            assertThat(listo.created()).isFalse();
            assertThat(listo.identity().serverId()).isEqualTo(primera.serverId());
        });
    }

    @Test
    void unaPassphraseIncorrectaCierraElLoginSinRevelarlaNiTocarElArchivo() throws Exception {
        ServerIdentityStore.loadOrCreate(archivo(), CLAVE.toCharArray(), new SecureRandom(), AHORA);
        var antes = Files.readAllBytes(archivo());
        var resultado = ServerIdentityBootstrap.start(
            Map.of(ServerIdentityBootstrap.PASSPHRASE_ENV, "otra-passphrase-secreta"), archivo(), new SecureRandom(), AHORA);
        assertThat(resultado).isInstanceOf(Disabled.class);
        var cerrado = (Disabled) resultado;
        assertThat(cerrado.reason()).contains("passphrase").doesNotContain("otra-passphrase-secreta");
        assertThat(cerrado.suggestedPassphrase()).isEmpty();
        assertThat(Files.readAllBytes(archivo())).isEqualTo(antes);
    }

    @Test
    void siNoSePuedeGuardarCierraElLoginEnLugarDeTumbarElServidor() throws Exception {
        var bloqueo = dir.resolve("keys");
        Files.writeString(bloqueo, "no soy una carpeta");
        var resultado = ServerIdentityBootstrap.start(CON_CLAVE, archivo(), new SecureRandom(), AHORA);
        assertThat(resultado).isInstanceOf(Disabled.class);
        var cerrado = (Disabled) resultado;
        assertThat(cerrado.reason()).isNotBlank().doesNotContain(CLAVE);
        assertThat(cerrado.suggestedPassphrase()).isEmpty();
    }
}
