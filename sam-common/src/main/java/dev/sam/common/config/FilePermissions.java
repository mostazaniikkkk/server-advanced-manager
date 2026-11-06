package dev.sam.common.config;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.AclEntry;
import java.nio.file.attribute.AclEntryPermission;
import java.nio.file.attribute.AclEntryType;
import java.nio.file.attribute.AclFileAttributeView;
import java.nio.file.attribute.PosixFileAttributeView;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.UserPrincipal;
import java.util.EnumSet;
import java.util.List;
import java.util.Set;

/**
 * Permisos de archivos con secretos o configuración sensible (RF-CFG-09): POSIX donde exista, ACL en
 * Windows. Sin ninguna de las dos vistas, no se puede saber ni restringir.
 *
 * <p>En Windows los nombres de los grupos dependen del idioma («Usuarios autentificados»): en lugar de
 * buscar grupos amplios, cualquier lectura permitida a alguien que no sea el dueño, SYSTEM o los
 * administradores (que pueden leer todo de todos modos) cuenta como abierta.
 */
public final class FilePermissions {

    /** Nombres (sin dominio) de las cuentas privilegiadas, en los idiomas más comunes. */
    private static final Set<String> PRIVILEGED = Set.of("SYSTEM", "Administrators", "Administradores", "Administrateurs",
        "Administratoren", "Amministratori");

    private FilePermissions() {
    }

    /** {@code true} si otros usuarios del sistema pueden leerlo. */
    public static boolean readableByOthers(Path file) throws IOException {
        var posix = Files.getFileAttributeView(file, PosixFileAttributeView.class);
        if (posix != null) {
            var permissions = posix.readAttributes().permissions();
            return permissions.contains(PosixFilePermission.GROUP_READ) || permissions.contains(PosixFilePermission.OTHERS_READ);
        }
        var acl = Files.getFileAttributeView(file, AclFileAttributeView.class);
        if (acl != null) {
            var owner = acl.getOwner();
            return acl.getAcl().stream().anyMatch(entry -> readsOthers(entry, owner));
        }
        return false;
    }

    /** Solo el dueño puede leerlo y escribirlo. */
    public static void restrictToOwner(Path file) throws IOException {
        var posix = Files.getFileAttributeView(file, PosixFileAttributeView.class);
        if (posix != null) {
            posix.setPermissions(EnumSet.of(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE));
            return;
        }
        var acl = Files.getFileAttributeView(file, AclFileAttributeView.class);
        if (acl != null) {
            acl.setAcl(List.of(AclEntry.newBuilder().setType(AclEntryType.ALLOW).setPrincipal(acl.getOwner())
                .setPermissions(EnumSet.allOf(AclEntryPermission.class)).build()));
        }
    }

    private static boolean readsOthers(AclEntry entry, UserPrincipal owner) {
        var name = entry.principal().getName();
        return entry.type() == AclEntryType.ALLOW && entry.permissions().contains(AclEntryPermission.READ_DATA)
            && !entry.principal().equals(owner) && !PRIVILEGED.contains(name.substring(name.lastIndexOf('\\') + 1));
    }
}
