package dev.sam.common.config;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

import java.nio.file.attribute.AclEntryPermission;
import java.nio.file.attribute.AclEntryType;
import java.nio.file.attribute.AclFileAttributeView;
import java.util.EnumSet;

import com.google.common.jimfs.Configuration;
import com.google.common.jimfs.Jimfs;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** RF-CFG-10 / H-12: escritura atómica y solo para el dueño desde que el archivo nace. */
class SecureFilesTest {

    @TempDir
    Path dir;

    @Test
    void escribeCreandoLaCarpetaYSoloParaElDueno() throws Exception {
        var archivo = dir.resolve("a").resolve("b").resolve("secreto.json");
        SecureFiles.write(archivo, "hola".getBytes(StandardCharsets.UTF_8));
        assertThat(Files.readString(archivo)).isEqualTo("hola");
        assertThat(FilePermissions.readableByOthers(archivo)).isFalse();
    }

    @Test
    void enWindowsLaAclQuedaSoloConElDueno() throws Exception {
        try (var fs = Jimfs.newFileSystem(Configuration.windows().toBuilder().setAttributeViews("basic", "owner", "acl").build())) {
            var archivo = fs.getPath("C:\\srv\\config\\secreto.json");
            SecureFiles.write(archivo, new byte[] {1, 2});
            var acl = Files.getFileAttributeView(archivo, AclFileAttributeView.class).getAcl();
            assertThat(acl).hasSize(1);
            assertThat(acl.get(0).principal()).isEqualTo(Files.getOwner(archivo));
            assertThat(acl.get(0).type()).isEqualTo(AclEntryType.ALLOW);
            assertThat(acl.get(0).permissions()).containsAll(EnumSet.allOf(AclEntryPermission.class));
            assertThat(Files.readAllBytes(archivo)).containsExactly(1, 2);
        }
    }

    @Test
    void enStreamingSinReemplazarYSoloParaElDueno() throws Exception {
        try (var fs = Jimfs.newFileSystem(Configuration.unix().toBuilder().setAttributeViews("basic", "owner", "posix").build())) {
            var archivo = fs.getPath("/respaldos/r.sambk");
            SecureFiles.write(archivo, out -> out.write(new byte[] {4, 5, 6}), false);
            assertThat(Files.readAllBytes(archivo)).containsExactly(4, 5, 6);
            assertThat(java.nio.file.attribute.PosixFilePermissions.toString(Files.getPosixFilePermissions(archivo)))
                .isEqualTo("rw-------");
            assertThatThrownBy(() -> SecureFiles.write(archivo, out -> out.write(9), false))
                .isInstanceOf(java.nio.file.FileAlreadyExistsException.class);
            assertThat(Files.readAllBytes(archivo)).containsExactly(4, 5, 6);
            SecureFiles.write(archivo, out -> out.write(9), true);
            assertThat(Files.readAllBytes(archivo)).containsExactly(9);
            try (var archivos = Files.list(archivo.getParent())) {
                assertThat(archivos.map(p -> p.getFileName().toString())).containsExactly("r.sambk");
            }
        }
    }

    @Test
    void sinReemplazarNoPisaEnElDiscoReal() throws Exception {
        var archivo = dir.resolve("r.sambk");
        Files.writeString(archivo, "original");
        assertThatThrownBy(() -> SecureFiles.write(archivo, out -> out.write(1), false))
            .isInstanceOf(java.nio.file.FileAlreadyExistsException.class);
        assertThat(Files.readString(archivo)).isEqualTo("original");
        try (var archivos = Files.list(dir)) {
            assertThat(archivos.map(p -> p.getFileName().toString())).containsExactly("r.sambk");
        }
    }

    @Test
    void reemplazaElContenidoSinDejarTemporales() throws Exception {
        var archivo = dir.resolve("secreto.json");
        Files.writeString(archivo, "viejo y más largo");
        SecureFiles.write(archivo, "nuevo".getBytes(StandardCharsets.UTF_8));
        assertThat(Files.readString(archivo)).isEqualTo("nuevo");
        assertThat(FilePermissions.readableByOthers(archivo)).isFalse();
        try (var archivos = Files.list(dir)) {
            assertThat(archivos.map(p -> p.getFileName().toString())).containsExactly("secreto.json");
        }
    }

    @Test
    void elTextoSeGuardaEnUtf8() throws Exception {
        var archivo = dir.resolve("t.txt");
        SecureFiles.writeString(archivo, "año ñ");
        assertThat(Files.readAllBytes(archivo)).isEqualTo("año ñ".getBytes(StandardCharsets.UTF_8));
        assertThat(FilePermissions.readableByOthers(archivo)).isFalse();
    }

    @Test
    void unaFallaDeEscrituraLanzaIoYNoDejaTemporales() throws Exception {
        Files.writeString(dir.resolve("ocupado"), "un archivo donde iría la carpeta");
        assertThatThrownBy(() -> SecureFiles.write(dir.resolve("ocupado").resolve("x"), new byte[] {1}))
            .isInstanceOf(IOException.class);
        var destino = dir.resolve("carpeta");
        Files.createDirectory(destino);
        Files.writeString(destino.resolve("dentro"), "no se puede reemplazar una carpeta con contenido");
        assertThatThrownBy(() -> SecureFiles.write(destino, new byte[] {1})).isInstanceOf(IOException.class);
        try (var archivos = Files.list(dir)) {
            assertThat(archivos.map(p -> p.getFileName().toString())).containsExactlyInAnyOrder("ocupado", "carpeta");
        }
    }
}
