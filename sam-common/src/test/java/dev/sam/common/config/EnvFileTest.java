package dev.sam.common.config;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileSystem;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.AclEntry;
import java.nio.file.attribute.AclEntryPermission;
import java.nio.file.attribute.AclEntryType;
import java.nio.file.attribute.AclFileAttributeView;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.EnumSet;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import com.google.common.jimfs.Configuration;
import com.google.common.jimfs.Jimfs;

import dev.sam.common.net.IngressPolicy.Action;
import dev.sam.common.net.IngressPolicy.Transport;
import dev.sam.common.net.ProtocolDetector.Classification;
import dev.sam.common.net.ws.WebSocketUpgrade;

/**
 * El .env en disco (RF-CFG-01/03/09, RN-34): ubicación, generación en el primer arranque con valores
 * seguros, el ejemplo, el .gitignore, los lugares prohibidos y los permisos.
 */
class EnvFileTest {

    private final List<FileSystem> abiertos = new ArrayList<>();

    @AfterEach
    void cerrar() throws IOException {
        for (var fs : abiertos) {
            fs.close();
        }
    }

    /** Bytes fijos: la ruta del WebSocket generada es predecible en el test. */
    static SecureRandom fijo(int valor) {
        return new SecureRandom() {
            private static final long serialVersionUID = 1L;

            @Override
            public void nextBytes(byte[] bytes) {
                java.util.Arrays.fill(bytes, (byte) valor);
            }
        };
    }

    private Path unix() {
        var fs = Jimfs.newFileSystem(Configuration.unix().toBuilder().setAttributeViews("basic", "owner", "posix").build());
        abiertos.add(fs);
        return fs.getPath("/srv/mc");
    }

    private Path windows(String... vistas) {
        var fs = Jimfs.newFileSystem(Configuration.windows().toBuilder().setAttributeViews("basic", vistas).build());
        abiertos.add(fs);
        return fs.getPath("C:\\srv\\mc");
    }

    @Test
    void porDefectoVaEnConfigSamYSeCambiaConSamEnvFile() {
        var servidor = unix();
        assertThat(EnvFile.locate(servidor, Map.of())).isEqualTo(servidor.resolve("config/sam/.env"));
        assertThat(EnvFile.locate(servidor, Map.of(EnvFile.ENV_FILE, "  "))).isEqualTo(servidor.resolve("config/sam/.env"));
        assertThat(EnvFile.locate(servidor, Map.of(EnvFile.ENV_FILE, " otra/sam.env "))).isEqualTo(servidor.resolve("otra/sam.env"));
        assertThat(EnvFile.locate(servidor, Map.of(EnvFile.ENV_FILE, "/etc/sam/.env")))
            .isEqualTo(servidor.getFileSystem().getPath("/etc/sam/.env"));
    }

    @Test
    void enElPrimerArranqueSeGeneraConValoresPorDefectoSeguros() throws IOException {
        var archivo = unix().resolve("config/sam/.env");
        var cargado = EnvFile.load(archivo, List.of(), fijo(0));
        assertThat(cargado.created()).isTrue();
        assertThat(cargado.file()).isEqualTo(archivo);
        assertThat(Files.readString(archivo)).isEqualTo(EnvFile.template("/sam-AAAAAAAAAAAAAAAAAAAAAA"));
        // La ruta del WebSocket se genera aleatoria y es válida (RF-WS-02)
        assertThat(cargado.values()).containsEntry(TransportConfig.WS_PATH, "/sam-AAAAAAAAAAAAAAAAAAAAAA");
        WebSocketUpgrade.validatePath(cargado.values().get(TransportConfig.WS_PATH));
        // Los valores por defecto son los mismos que sin archivo: solo TCP, sin WebSocket
        var transporte = TransportConfig.from(cargado.values());
        assertThat(transporte.webSocketPath()).isEmpty();
        assertThat(transporte.policy().decide(Transport.DIRECT_TCP, Classification.TLS)).isEqualTo(Action.SAM_TLS);
        assertThat(transporte.unclassifiedPerIp()).isEqualTo(8);
        assertThat(transporte.unclassifiedGlobal()).isEqualTo(256);
        // Con el WebSocket encendido, la ruta generada sirve tal cual
        var conWs = new java.util.HashMap<>(cargado.values());
        conWs.put(TransportConfig.WS_ENABLED, "true");
        assertThat(TransportConfig.from(conWs).webSocketPath()).contains("/sam-AAAAAAAAAAAAAAAAAAAAAA");
        assertThat(cargado.warnings()).isEmpty();
    }

    @Test
    void laPlantillaDocumentaLasClavesYNoTraeSecretosMaestros() {
        var plantilla = EnvFile.template("/x");
        var valores = DotEnv.parse(plantilla);
        assertThat(valores).containsOnlyKeys(TransportConfig.TCP_ENABLED, TransportConfig.WS_ENABLED, TransportConfig.WS_PATH,
            TransportConfig.TRUSTED_PROXIES, TransportConfig.REAL_IP_HEADER, TransportConfig.UNCLASSIFIED_PER_IP,
            TransportConfig.UNCLASSIFIED_GLOBAL);
        assertThat(valores).containsEntry(TransportConfig.WS_PATH, "/x");
        // Los secretos maestros se mencionan solo en comentarios (RF-CFG-08)
        assertThat(ServerEnv.merge(valores, Map.of())).doesNotContainKeys(ServerEnv.MASTER_SECRETS.toArray(String[]::new));
        assertThat(plantilla).contains("SAM_DATA_KEY", "SAM_IDENTITY_PASSPHRASE", EnvFile.ENV_FILE, "[reinicio]");
        assertThat(DotEnv.parse(EnvFile.template(""))).containsEntry(TransportConfig.WS_PATH, "");
    }

    @Test
    void cadaServidorGeneraSuPropiaRutaYNoSeRegeneraAlReiniciar() throws IOException {
        var a = EnvFile.load(unix().resolve("config/sam/.env"), List.of(), new SecureRandom());
        var b = EnvFile.load(unix().resolve("config/sam/.env"), List.of(), new SecureRandom());
        assertThat(a.values().get(TransportConfig.WS_PATH)).matches("/sam-[A-Za-z0-9_-]{22}")
            .isNotEqualTo(b.values().get(TransportConfig.WS_PATH));
        var otraVez = EnvFile.load(a.file(), List.of(), fijo(0));
        assertThat(otraVez.created()).isFalse();
        assertThat(otraVez.values()).isEqualTo(a.values());
    }

    @Test
    void unEnvExistenteSeLeeTalCual() throws IOException {
        var archivo = unix().resolve("config/sam/.env");
        Files.createDirectories(archivo.getParent());
        Files.writeString(archivo, "SAM_TCP_ENABLED=false\nSAM_WS_ENABLED=true\n");
        var cargado = EnvFile.load(archivo, List.of(), fijo(0));
        assertThat(cargado.created()).isFalse();
        assertThat(cargado.values()).containsExactly(org.assertj.core.api.Assertions.entry("SAM_TCP_ENABLED", "false"),
            org.assertj.core.api.Assertions.entry("SAM_WS_ENABLED", "true"));
        assertThat(Files.readString(archivo)).isEqualTo("SAM_TCP_ENABLED=false\nSAM_WS_ENABLED=true\n");
    }

    @Test
    void unEnvInvalidoSeRechazaNombrandoElArchivo() throws IOException {
        var archivo = unix().resolve("config/sam/.env");
        Files.createDirectories(archivo.getParent());
        Files.writeString(archivo, "SAM_A=1\nbasura\n");
        assertThatThrownBy(() -> EnvFile.load(archivo, List.of(), fijo(0)))
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessage(".env, línea 2: se esperaba CLAVE=valor (/srv/mc/config/sam/.env)");
    }

    @Test
    void alLadoQuedanElEjemploYUnGitignoreQueLoExcluye() throws IOException {
        var archivo = unix().resolve("config/sam/.env");
        EnvFile.load(archivo, List.of(), fijo(0));
        var carpeta = archivo.getParent();
        assertThat(carpeta.resolve(EnvFile.EXAMPLE_NAME)).exists();
        assertThat(carpeta.resolve(EnvFile.GITIGNORE_NAME)).exists();
        assertThat(Files.readString(carpeta.resolve(EnvFile.EXAMPLE_NAME))).isEqualTo(EnvFile.template(""));
        assertThat(Files.readString(carpeta.resolve(EnvFile.GITIGNORE_NAME))).isEqualTo(".env\n");
    }

    @Test
    void elEjemploSeActualizaYElGitignoreExistenteSeCompletaSinPerderNada() throws IOException {
        var archivo = unix().resolve("conf/mi.env");
        var carpeta = archivo.getParent();
        Files.createDirectories(carpeta);
        Files.writeString(archivo, "SAM_A=1\n");
        Files.writeString(carpeta.resolve(EnvFile.EXAMPLE_NAME), "viejo");
        Files.writeString(carpeta.resolve(EnvFile.GITIGNORE_NAME), "*.log");
        EnvFile.load(archivo, List.of(), fijo(0));
        assertThat(Files.readString(carpeta.resolve(EnvFile.EXAMPLE_NAME))).isEqualTo(EnvFile.template(""));
        assertThat(Files.readString(carpeta.resolve(EnvFile.GITIGNORE_NAME), StandardCharsets.UTF_8)).isEqualTo("*.log\nmi.env\n");
        // Ya completo: no se toca otra vez
        EnvFile.load(archivo, List.of(), fijo(0));
        assertThat(Files.readString(carpeta.resolve(EnvFile.GITIGNORE_NAME))).isEqualTo("*.log\nmi.env\n");
        Files.writeString(carpeta.resolve(EnvFile.GITIGNORE_NAME), "*.tmp\n");
        EnvFile.load(archivo, List.of(), fijo(0));
        assertThat(Files.readString(carpeta.resolve(EnvFile.GITIGNORE_NAME))).isEqualTo("*.tmp\nmi.env\n");
        Files.writeString(carpeta.resolve(EnvFile.GITIGNORE_NAME), "mi.env\n*.log\n");
        EnvFile.load(archivo, List.of(), fijo(0));
        assertThat(Files.readString(carpeta.resolve(EnvFile.GITIGNORE_NAME))).isEqualTo("mi.env\n*.log\n");
    }

    @Test
    void dentroDeLaCarpetaDelMundoNoArrancaYNoCreaNada() {
        var servidor = unix();
        var mundo = servidor.resolve("world");
        for (var archivo : List.of(mundo.resolve(".env"), mundo.resolve("data/../sam/.env"), servidor.resolve("world/./x/.env"))) {
            assertThatThrownBy(() -> EnvFile.load(archivo, List.of(servidor.resolve("otro"), mundo), fijo(0)))
                .as(archivo.toString())
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("El .env (" + archivo.normalize() + ") está dentro de la carpeta del mundo (" + mundo
                    + "): podría copiarse en un backup o compartirse con el mundo. Muévelo a config/sam/ (RF-CFG-09).");
            assertThat(Files.exists(archivo)).isFalse();
            assertThat(Files.exists(mundo)).isFalse();
        }
    }

    @Test
    void dentroDeUnDatapackNoArranca() {
        var servidor = unix();
        for (var archivo : List.of(servidor.resolve("datapacks/mio/.env"), servidor.resolve("x/DataPacks/.env"))) {
            assertThatThrownBy(() -> EnvFile.load(archivo, List.of(), fijo(0)))
                .as(archivo.toString())
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("El .env (" + archivo + ") está dentro de una carpeta de datapacks: se distribuiría con el "
                    + "datapack. Muévelo a config/sam/ (RF-CFG-09).");
        }
    }

    @Test
    void unaCarpetaHermanaDelMundoNoEstaProhibida() throws IOException {
        var servidor = unix();
        var cargado = EnvFile.load(servidor.resolve("world2/.env"), List.of(servidor.resolve("world")), fijo(0));
        assertThat(cargado.created()).isTrue();
    }

    @Test
    void unEnlaceHaciaElMundoTambienSeRechaza() throws IOException {
        var servidor = unix();
        var mundo = Files.createDirectories(servidor.resolve("world"));
        var enlace = Files.createSymbolicLink(servidor.resolve("config"), mundo);
        var archivo = enlace.resolve(".env");
        assertThatThrownBy(() -> EnvFile.load(archivo, List.of(mundo), fijo(0)))
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessageContaining("está dentro de la carpeta del mundo");
        assertThat(Files.exists(mundo.resolve(".env"))).isFalse();
    }

    @Test
    void enPosixElEnvGeneradoQuedaSoloParaElDuenoYUnoAbiertoSeAdvierte() throws IOException {
        var archivo = unix().resolve("config/sam/.env");
        EnvFile.load(archivo, List.of(), fijo(0));
        assertThat(archivo).exists();
        assertThat(PosixFilePermissions.toString(Files.getPosixFilePermissions(archivo))).isEqualTo("rw-------");

        for (var abiertos : List.of("rw-r-----", "rw----r--")) {
            Files.setPosixFilePermissions(archivo, PosixFilePermissions.fromString(abiertos));
            var cargado = EnvFile.load(archivo, List.of(), fijo(0));
            assertThat(cargado.warnings()).as(abiertos).containsExactly("El .env (" + archivo + ") lo pueden leer otros "
                + "usuarios del sistema: restringe sus permisos para que solo lo lea el usuario del servidor (RF-CFG-09).");
            // Advertir no es cambiar: los permisos del operador no se tocan
            assertThat(PosixFilePermissions.toString(Files.getPosixFilePermissions(archivo))).isEqualTo(abiertos);
        }
        Files.setPosixFilePermissions(archivo, PosixFilePermissions.fromString("rw--w--w-"));
        assertThat(EnvFile.load(archivo, List.of(), fijo(0)).warnings()).isEmpty();
    }

    @Test
    void enWindowsElEnvGeneradoQuedaSoloParaElDueno() throws IOException {
        var archivo = windows("owner", "acl").resolve("config\\sam\\.env");
        EnvFile.load(archivo, List.of(), fijo(0));
        assertThat(archivo).exists();
        var acl =Files.getFileAttributeView(archivo, AclFileAttributeView.class).getAcl();
        assertThat(acl).hasSize(1);
        assertThat(acl.get(0).principal()).isEqualTo(Files.getOwner(archivo));
        assertThat(acl.get(0).type()).isEqualTo(AclEntryType.ALLOW);
        assertThat(acl.get(0).permissions()).containsAll(EnumSet.allOf(AclEntryPermission.class));
    }

    @Test
    void enWindowsSeAdviertenLosGruposAmplios() throws IOException {
        var archivo = windows("owner", "acl").resolve("config\\sam\\.env");
        EnvFile.load(archivo, List.of(), fijo(0));
        assertThat(archivo).exists();
        var vista =Files.getFileAttributeView(archivo, AclFileAttributeView.class);
        var nombres = archivo.getFileSystem().getUserPrincipalLookupService();
        var dueno = vista.getAcl();
        // Cualquiera que no sea el dueño ni una cuenta privilegiada, con nombres en cualquier idioma
        for (var grupo : List.of("Everyone", "Todos", "BUILTIN\\Usuarios", "NT AUTHORITY\\Usuarios autentificados",
                "SERVIDOR\\backup")) {
            var acl = new ArrayList<>(dueno);
            acl.add(entrada(nombres.lookupPrincipalByName(grupo), AclEntryType.ALLOW, AclEntryPermission.READ_DATA));
            vista.setAcl(acl);
            assertThat(EnvFile.load(archivo, List.of(), fijo(0)).warnings()).as(grupo).hasSize(1);
        }
        // Denegar, solo escribir, SYSTEM o administradores (leen todo de todos modos): no se advierte
        for (var otra : List.of(
                entrada(nombres.lookupPrincipalByName("Everyone"), AclEntryType.DENY, AclEntryPermission.READ_DATA),
                entrada(nombres.lookupPrincipalByName("Everyone"), AclEntryType.ALLOW, AclEntryPermission.WRITE_DATA),
                entrada(nombres.lookupPrincipalByName("NT AUTHORITY\\SYSTEM"), AclEntryType.ALLOW, AclEntryPermission.READ_DATA),
                entrada(nombres.lookupPrincipalByName("BUILTIN\\Administradores"), AclEntryType.ALLOW, AclEntryPermission.READ_DATA),
                entrada(nombres.lookupPrincipalByName("Administrators"), AclEntryType.ALLOW, AclEntryPermission.READ_DATA))) {
            var acl = new ArrayList<>(dueno);
            acl.add(otra);
            vista.setAcl(acl);
            assertThat(EnvFile.load(archivo, List.of(), fijo(0)).warnings()).as(otra.toString()).isEmpty();
        }
    }

    @Test
    void sinVistasDePermisosNoSeAdvierteNiFalla() throws IOException {
        var archivo = windows().resolve("config\\sam\\.env");
        var cargado = EnvFile.load(archivo, List.of(), fijo(0));
        assertThat(cargado.created()).isTrue();
        assertThat(cargado.warnings()).isEmpty();
        // Ya existente: tampoco se puede saber quién lo lee
        assertThat(EnvFile.load(archivo, List.of(), fijo(0)).warnings()).isEmpty();
    }

    @Test
    void enElDiscoRealElEnvGeneradoNoLoLeenOtros(@TempDir Path carpeta) throws IOException {
        var archivo = carpeta.resolve("config/sam/.env");
        var cargado = EnvFile.load(archivo, List.of(), new SecureRandom());
        assertThat(cargado.created()).isTrue();
        assertThat(FilePermissions.readableByOthers(archivo)).isFalse();
        assertThat(EnvFile.load(archivo, List.of(), new SecureRandom()).warnings()).isEmpty();
    }

    private static AclEntry entrada(java.nio.file.attribute.UserPrincipal quien, AclEntryType tipo, AclEntryPermission permiso) {
        return AclEntry.newBuilder().setPrincipal(quien).setType(tipo).setPermissions(permiso).build();
    }
}
