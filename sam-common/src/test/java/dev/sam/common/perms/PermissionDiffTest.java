package dev.sam.common.perms;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.OptionalLong;

import org.junit.jupiter.api.Test;

/** H-09 / PERMISOS.md: la auditoría de un cambio de permisos guarda el valor anterior y el nuevo. */
class PermissionDiffTest {

    private static final PermissionSet.Grant SI = new PermissionSet.Grant(true, OptionalLong.empty(), false);

    @Test
    void sinCambiosNoHayNada() {
        var set = PermissionSet.empty().createGroup("vip", 5);
        assertThat(PermissionSet.diff(set, set)).isEmpty();
    }

    @Test
    void unGrupoCambiadoMuestraAntesYDespuesEnUnaLinea() {
        var antes = PermissionSet.empty().createGroup("vip", 5).addUserGroup("alex", "vip", OptionalLong.empty());
        var despues = antes.setGroupPermission("vip", "sam.homes.vip", SI);
        var diff = PermissionSet.diff(antes, despues);
        assertThat(diff).doesNotContain("alex").doesNotContain(";");
        assertThat(diff).startsWith("grupo vip: {").contains(" -> ").doesNotContain("\n");
        var partes = diff.split(" -> ");
        assertThat(partes[0]).doesNotContain("sam.homes.vip").contains("\"weight\":5");
        assertThat(partes[1]).contains("\"sam.homes.vip\"");
    }

    @Test
    void creadosYBorradosDicenQueNoExistian() {
        var antes = PermissionSet.empty();
        var creado = antes.createGroup("vip", 0);
        assertThat(PermissionSet.diff(antes, creado)).startsWith("grupo vip: (no existía) -> {");
        assertThat(PermissionSet.diff(creado, antes)).startsWith("grupo vip: {").endsWith(" -> (borrado)");
    }

    @Test
    void jugadoresYVariosCambiosSeparadosPorPuntoYComa() {
        var antes = PermissionSet.empty().createGroup("vip", 0).createGroup("staff", 1);
        var despues = antes.addUserGroup("steve", "vip", OptionalLong.empty()).setWeight("staff", 2).setWeight("vip", 3);
        var diff = PermissionSet.diff(antes, despues);
        assertThat(diff.split("; ")).hasSize(3);
        assertThat(diff.split("; ")[0]).startsWith("grupo staff: ");
        assertThat(diff.split("; ")[1]).startsWith("grupo vip: ");
        assertThat(diff.split("; ")[2]).startsWith("jugador steve: (no existía) -> {");
    }

    // ===== Separación de funciones (H-07): qué cambios tocan al propio admin =====

    private static final long AHORA = 1_000_000L;

    @Test
    void cambiarseASiMismoLoAfecta() {
        var antes = PermissionSet.empty().createGroup("staff", 1);
        assertThat(PermissionSet.affects(antes, antes.addUserGroup("steve", "staff", OptionalLong.empty()), "Steve", AHORA)).isTrue();
        assertThat(PermissionSet.affects(antes, antes.setUserPermission("steve", "*", SI), "steve", AHORA)).isTrue();
        assertThat(PermissionSet.affects(antes, antes.setUserPermission("alex", "*", SI), "steve", AHORA)).isFalse();
    }

    @Test
    void cambiarUnGrupoSuyoOUnAncestroLoAfecta() {
        var antes = PermissionSet.empty().createGroup("base", 0).createGroup("staff", 1).addParent("staff", "base")
            .createGroup("vip", 2).addUserGroup("steve", "staff", OptionalLong.empty());
        assertThat(PermissionSet.affects(antes, antes.setGroupPermission("staff", "*", SI), "steve", AHORA)).isTrue();
        assertThat(PermissionSet.affects(antes, antes.setGroupPermission("base", "*", SI), "steve", AHORA)).isTrue();
        assertThat(PermissionSet.affects(antes, antes.setGroupPermission("default", "*", SI), "steve", AHORA)).isTrue();
        assertThat(PermissionSet.affects(antes, antes.setGroupPermission("vip", "*", SI), "steve", AHORA)).isFalse();
        // Hacer que un grupo ajeno herede de... no lo toca; hacer que el suyo herede de otro sí
        assertThat(PermissionSet.affects(antes, antes.addParent("vip", "base"), "steve", AHORA)).isFalse();
        assertThat(PermissionSet.affects(antes, antes.addParent("staff", "vip"), "steve", AHORA)).isTrue();
    }

    @Test
    void unGrupoVencidoYaNoLoAfecta() {
        var antes = PermissionSet.empty().createGroup("temporal", 0).addUserGroup("steve", "temporal", OptionalLong.of(AHORA - 1));
        assertThat(PermissionSet.affects(antes, antes.setGroupPermission("temporal", "*", SI), "steve", AHORA)).isFalse();
    }

    // ===== Datos del jugador (RF-AUTH-07e, H-15) =====

    @Test
    void laEntradaDeUnJugadorEnJsonYSuBorrado() {
        var set = PermissionSet.empty().createGroup("vip", 0).addUserGroup("steve", "vip", OptionalLong.empty())
            .addUserGroup("alex", "vip", OptionalLong.empty());
        assertThat(set.userJson("Steve")).contains("{\"groups\":{\"vip\":{}},\"permissions\":{},\"meta\":{}}");
        assertThat(set.userJson("nadie")).isEmpty();
        var sin = set.withoutUser("STEVE");
        assertThat(sin.users()).containsOnlyKeys("alex");
        assertThat(sin.withoutUser("nadie")).isEqualTo(sin);
    }
}
