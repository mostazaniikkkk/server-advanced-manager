package dev.sam.server.qa;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.AclEntryType;
import java.nio.file.attribute.AclFileAttributeView;
import java.nio.file.attribute.PosixFileAttributeView;
import java.nio.file.attribute.PosixFilePermissions;

import org.junit.jupiter.api.Test;

/**
 * De punta a punta en QA Server SAM (RF-CFG-01/03/09): el servidor arrancó con su .env en
 * config/sam/, con el ejemplo, el .gitignore y permisos solo para el dueño. La carpeta la indica
 * qa-run.ps1 en QA_SAM_SERVER_DIR.
 */
class EnvFileQaTest {

    private static Path config() {
        var dir = System.getenv("QA_SAM_SERVER_DIR");
        assertThat(dir).as("QA_SAM_SERVER_DIR (lo define qa-run.ps1)").isNotBlank();
        return Path.of(dir, "config", "sam");
    }

    @Test
    void elServidorTieneSuEnvConRutaWebSocketGeneradaEjemploYGitignore() throws IOException {
        var config = config();
        var env = config.resolve(".env");
        assertThat(env).exists();
        assertThat(Files.readAllLines(env)).anyMatch(line -> line.matches("SAM_WS_PATH=/sam-[A-Za-z0-9_-]{22}"))
            .noneMatch(line -> line.startsWith("SAM_DATA_KEY") || line.startsWith("SAM_IDENTITY_PASSPHRASE"));
        assertThat(Files.readAllLines(config.resolve(".gitignore"))).contains(".env");
        assertThat(Files.readString(config.resolve(".env.example"))).contains("SAM_WS_PATH=\n");
    }

    @Test
    void elEnvGeneradoSoloLoLeeElDueno() throws IOException {
        var env = config().resolve(".env");
        var posix = Files.getFileAttributeView(env, PosixFileAttributeView.class);
        if (posix != null) {
            assertThat(PosixFilePermissions.toString(posix.readAttributes().permissions())).isEqualTo("rw-------");
            return;
        }
        var acl = Files.getFileAttributeView(env, AclFileAttributeView.class);
        assertThat(acl.getAcl()).singleElement().satisfies(entry -> {
            assertThat(entry.type()).isEqualTo(AclEntryType.ALLOW);
            assertThat(entry.principal()).isEqualTo(acl.getOwner());
        });
    }
}
