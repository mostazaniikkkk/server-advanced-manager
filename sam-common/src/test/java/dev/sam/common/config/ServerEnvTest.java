package dev.sam.common.config;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.Assertions.entry;

import java.util.LinkedHashMap;
import java.util.Map;

import org.junit.jupiter.api.Test;

/**
 * La configuración efectiva (RF-CFG-02, RF-CFG-08) y el enmascarado de secretos (RF-CFG-06).
 */
class ServerEnvTest {

    @Test
    void lasVariablesDelProcesoTienenPrioridadSobreElArchivo() {
        var archivo = new LinkedHashMap<String, String>();
        archivo.put("SAM_TCP_ENABLED", "true");
        archivo.put("SAM_LANG", "es_es");
        var efectiva = ServerEnv.merge(archivo, Map.of("SAM_TCP_ENABLED", "false", "SAM_WS_ENABLED", "true"));
        assertThat(efectiva).containsOnly(entry("SAM_TCP_ENABLED", "false"), entry("SAM_LANG", "es_es"),
            entry("SAM_WS_ENABLED", "true"));
    }

    @Test
    void delEntornoSoloSeTomanLasClavesDeSam() {
        var efectiva = ServerEnv.merge(Map.of(), Map.of("PATH", "/bin", "JAVA_HOME", "/jdk", "SAMBA", "x",
            ServerEnv.IDENTITY_PASSPHRASE, "secreto"));
        assertThat(efectiva).containsOnly(entry(ServerEnv.IDENTITY_PASSPHRASE, "secreto"));
    }

    @Test
    void unSecretoMaestroEnElArchivoImpideArrancar() {
        for (var clave : ServerEnv.MASTER_SECRETS) {
            assertThatThrownBy(() -> ServerEnv.merge(Map.of(clave, "abc"), Map.of(clave, "abc")))
                .as(clave)
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage(clave + " está escrita en el .env: los secretos maestros solo se aceptan como variable de entorno "
                    + "del proceso (RF-CFG-08). Bórrala del archivo y defínela en el entorno.")
                .hasMessageNotContaining("abc");
            // Aunque esté vacía: el lugar del secreto no es el archivo
            assertThatThrownBy(() -> ServerEnv.merge(Map.of(clave, ""), Map.of())).as(clave)
                .isInstanceOf(IllegalArgumentException.class);
        }
    }

    @Test
    void elResultadoNoSeModificaNiDependeDeLasEntradas() {
        var archivo = new LinkedHashMap<String, String>(Map.of("SAM_A", "1"));
        var efectiva = ServerEnv.merge(archivo, Map.of());
        archivo.put("SAM_A", "2");
        assertThat(efectiva).containsOnly(entry("SAM_A", "1"));
        assertThatThrownBy(() -> efectiva.put("SAM_B", "x")).isInstanceOf(UnsupportedOperationException.class);
    }

    @Test
    void lasClavesSecretasSeReconocenPorSuSufijo() {
        assertThat(Secrets.isSecret("SAM_OAUTH_GOOGLE_CLIENT_SECRET")).isTrue();
        assertThat(Secrets.isSecret("SAM_DATA_KEY")).isTrue();
        assertThat(Secrets.isSecret("SAM_MAIL_SMTP_PASSWORD")).isTrue();
        assertThat(Secrets.isSecret("SAM_IDENTITY_PASSPHRASE")).isTrue();
        assertThat(Secrets.isSecret("SAM_OAUTH_GOOGLE_CLIENT_ID")).isFalse();
        assertThat(Secrets.isSecret("SAM_SCRIPTS_TRUSTED_KEYS")).isFalse();
        assertThat(Secrets.isSecret("SAM_KEY_FILE")).isFalse();
        assertThat(Secrets.isSecret("SAM_SECRET")).isTrue();
    }

    @Test
    void losSecretosSeEnmascaranSalvoQueEstenVacios() {
        assertThat(Secrets.mask("SAM_MAIL_SMTP_PASSWORD", "hunter2")).isEqualTo(Secrets.MASK);
        assertThat(Secrets.mask("SAM_MAIL_SMTP_PASSWORD", "")).isEmpty();
        assertThat(Secrets.mask("SAM_MAIL_SMTP_USER", "yo")).isEqualTo("yo");
    }

    @Test
    void laVistaEnmascaradaVaOrdenadaYNoExponeSecretos() {
        var vista = Secrets.masked(Map.of("SAM_Z", "1", "SAM_DATA_KEY", "k", "SAM_A", "2"));
        assertThat(vista).containsExactly(entry("SAM_A", "2"), entry("SAM_DATA_KEY", Secrets.MASK), entry("SAM_Z", "1"));
        assertThat(vista.toString()).doesNotContain("=k");
    }
}
