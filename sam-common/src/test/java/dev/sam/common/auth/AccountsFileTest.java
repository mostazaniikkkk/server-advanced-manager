package dev.sam.common.auth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.util.List;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import dev.sam.common.config.FilePermissions;

/** Las cuentas en disco: van y vuelven, un archivo dañado no se interpreta y se escribe atómico. */
class AccountsFileTest {

    private static final String HASH = PasswordHash.create(AccountServiceTest.k(1), new Argon2Params(8, 1, 1), AccountServiceTest.ceros());
    private static final Account STEVE = new Account("steve", "Steve", HASH, "steve@example.com");
    private static final Account ALEX = new Account("alex", "Alex", HASH, "alex@example.com");

    @Test
    void lasCuentasVanYVuelvenOrdenadasPorNick() {
        var json = AccountsFile.encode(List.of(STEVE, ALEX));
        assertThat(json).isEqualTo("""
            {
              "version": 1,
              "accounts": [
                {
                  "nick": "Alex",
                  "hash": "%s",
                  "email": "alex@example.com"
                },
                {
                  "nick": "Steve",
                  "hash": "%s",
                  "email": "steve@example.com"
                }
              ]
            }
            """.formatted(HASH, HASH));
        assertThat(AccountsFile.decode(json)).containsExactly(ALEX, STEVE);
        assertThat(AccountsFile.decode(AccountsFile.encode(List.of()))).isEmpty();
    }

    @Test
    void unArchivoDanadoNoSeInterpreta() {
        var cuenta = "{\"nick\":\"Steve\",\"hash\":\"" + HASH + "\",\"email\":\"s@e.com\"}";
        var malos = List.of("", "[]", "{", "{\"version\":2,\"accounts\":[]}", "{\"accounts\":[]}", "{\"version\":1}",
            "{\"version\":\"1\",\"accounts\":[]}", "{\"version\":1,\"accounts\":{}}", "{\"version\":1,\"accounts\":[],\"x\":1}",
            "{\"version\":1,\"version\":1,\"accounts\":[]}",
            "{\"version\":1,\"accounts\":[" + cuenta + "," + cuenta.replace("Steve", "STEVE") + "]}",
            "{\"version\":1,\"accounts\":[" + cuenta.replace("Steve", "a-b") + "]}",
            "{\"version\":1,\"accounts\":[" + cuenta.replace(HASH, "x") + "]}",
            "{\"version\":1,\"accounts\":[" + cuenta.replace("s@e.com", "nada") + "]}",
            "{\"version\":1,\"accounts\":[" + cuenta.replace(",\"email\":\"s@e.com\"", "") + "]}",
            "{\"version\":1,\"accounts\":[" + cuenta.replace("}", ",\"otro\":1}") + "]}",
            "{\"version\":1,\"accounts\":[" + cuenta.replace("\"Steve\"", "7") + "]}",
            "{\"version\":1,\"accounts\":[" + cuenta.replace("\"nick\":\"Steve\",", "\"nick\":\"Steve\",\"nick\":\"Alex\",") + "]}",
            // Un número donde va texto, aunque se lea como un nick válido
            "{\"version\":1,\"accounts\":[" + cuenta.replace("\"Steve\"", "1234") + "]}",
            "{\"version\":1,\"accounts\":[" + cuenta.replace("\"email\"", "\"otro\"") + "]}",
            "{\"version\":1,\"accounts\":[7]}",
            "{\"version\":1,\"accounts\":[]} {}",
            "{version:1,accounts:[]}");
        for (var malo : malos) {
            assertThatThrownBy(() -> AccountsFile.decode(malo)).as(malo).isInstanceOf(IllegalArgumentException.class)
                .hasMessageStartingWith("accounts.json inválido");
        }
        assertThat(AccountsFile.decode("{\"accounts\":[" + cuenta + "],\"version\":1}"))
            .containsExactly(new Account("steve", "Steve", HASH, "s@e.com"));
    }

    @Test
    void sinArchivoNoHayCuentasYLoGuardadoSeLeeIgual(@TempDir Path carpeta) throws IOException {
        var archivo = carpeta.resolve("sam/accounts.json");
        assertThat(AccountsFile.load(archivo)).isEmpty();
        AccountsFile.save(archivo, List.of(STEVE));
        assertThat(AccountsFile.load(archivo)).containsExactly(STEVE);
        AccountsFile.save(archivo, List.of(STEVE, ALEX));
        assertThat(AccountsFile.load(archivo)).containsExactly(ALEX, STEVE);
        assertThat(FilePermissions.readableByOthers(archivo)).isFalse();
        // En Windows el temporal hereda la ACL de la carpeta: se restringe antes de escribir
        try (var fs = com.google.common.jimfs.Jimfs.newFileSystem(com.google.common.jimfs.Configuration.windows().toBuilder()
                .setAttributeViews("basic", "owner", "acl").build())) {
            var enWindows = fs.getPath("C:\\srv\\accounts.json");
            AccountsFile.save(enWindows, List.of(STEVE));
            var acl = Files.getFileAttributeView(enWindows, java.nio.file.attribute.AclFileAttributeView.class);
            assertThat(acl.getAcl()).singleElement().satisfies(e -> assertThat(e.principal()).isEqualTo(acl.getOwner()));
        }
        // No quedan temporales al lado
        try (var archivos = Files.list(archivo.getParent())) {
            assertThat(archivos).containsExactly(archivo);
        }
    }

    @Test
    void unArchivoDanadoEnDiscoSeRechazaNombrandoloYNoSeBorra(@TempDir Path carpeta) throws IOException {
        var archivo = carpeta.resolve("accounts.json");
        Files.writeString(archivo, "{roto");
        assertThatThrownBy(() -> AccountsFile.load(archivo)).isInstanceOf(IllegalArgumentException.class)
            .hasMessageContaining(archivo.toString());
        assertThat(Files.readString(archivo)).isEqualTo("{roto");
    }

    @Test
    void elServicioYElArchivoTrabajanJuntos(@TempDir Path carpeta) throws IOException {
        var archivo = carpeta.resolve("accounts.json");
        var servicio = new AccountService(AccountsFile.load(archivo), new Argon2Params(8, 1, 1), new SecureRandom(), cuentas -> {
            try {
                AccountsFile.save(archivo, cuentas);
            } catch (IOException e) {
                throw new java.io.UncheckedIOException(e);
            }
        });
        servicio.register("Steve", AccountServiceTest.k(5), "steve@example.com");
        var reiniciado = new AccountService(AccountsFile.load(archivo), new Argon2Params(8, 1, 1), new SecureRandom(), c -> { });
        assertThat(reiniciado.login("steve", AccountServiceTest.k(5)).status()).isEqualTo(dev.sam.common.proto.auth.AuthResult.Status.OK);
    }
}
