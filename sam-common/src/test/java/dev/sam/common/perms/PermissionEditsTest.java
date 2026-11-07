package dev.sam.common.perms;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.OptionalLong;

import org.junit.jupiter.api.Test;

import dev.sam.common.perms.PermissionSet.Grant;
import dev.sam.common.perms.PermissionSet.Meta;
import dev.sam.common.perms.PermissionSet.Value;

/**
 * Los cambios de {@code /sam perms} (docs/PERMISOS.md, sección 4): cada uno devuelve un conjunto nuevo y
 * válido, o falla con el motivo sin cambiar nada.
 */
class PermissionEditsTest {

    private static final Grant SI = new Grant(true, OptionalLong.empty(), false);
    private static final Grant NO = new Grant(false, OptionalLong.empty(), false);

    @Test
    void losGruposSeCreanPesanHeredanYBorran() {
        var set = PermissionSet.empty().createGroup("vip", 10).createGroup("mod", 50);
        assertThat(set.groups()).containsOnlyKeys("default", "vip", "mod");
        assertThat(set.groups().get("vip").weight()).isEqualTo(10);
        set = set.setWeight("vip", 20).addParent("mod", "vip").setGroupPermission("vip", "sam.command.fly", SI);
        assertThat(set.groups().get("mod").parents()).containsExactly("vip");
        assertThat(set.addUserGroup("steve", "mod", OptionalLong.empty()).check("steve", "sam.command.fly", 0, false).value())
            .isEqualTo(Value.TRUE);
        set = set.removeParent("mod", "vip");
        assertThat(set.groups().get("mod").parents()).isEmpty();
        // Borrar un grupo lo saca de los jugadores
        var conJugador = set.addUserGroup("steve", "vip", OptionalLong.empty()).addUserGroup("alex", "mod", OptionalLong.empty())
            .addUserGroup("alex", "vip", OptionalLong.empty()).deleteGroup("vip");
        assertThat(conJugador.groups()).doesNotContainKey("vip");
        assertThat(conJugador.users()).doesNotContainKey("steve");
        assertThat(conJugador.users().get("alex").groups()).containsOnlyKeys("mod");
        assertThat(PermissionSet.parse(conJugador.toJson())).isEqualTo(conJugador);
    }

    @Test
    void losCambiosDeGruposInvalidosFallan() {
        var set = PermissionSet.empty().createGroup("vip", 0).createGroup("mod", 0).addParent("mod", "vip");
        falla(() -> set.createGroup("vip", 1), "el grupo vip ya existe");
        falla(() -> set.createGroup("Mal", 1), "nombre de grupo inválido \"Mal\"");
        falla(() -> set.deleteGroup("default"), "el grupo default no se puede borrar");
        falla(() -> set.deleteGroup("vip"), "vip es padre de mod");
        falla(() -> set.deleteGroup("nada"), "no existe el grupo nada");
        falla(() -> set.setWeight("nada", 1), "no existe el grupo nada");
        falla(() -> set.addParent("vip", "mod"), "herencia circular");
        falla(() -> set.addParent("vip", "vip"), "herencia circular");
        falla(() -> set.addParent("mod", "vip"), "mod ya hereda de vip");
        falla(() -> set.addParent("mod", "nada"), "no existe el grupo nada");
        falla(() -> set.removeParent("vip", "mod"), "vip no hereda de mod");
        falla(() -> set.setGroupPermission("vip", "Mal", SI), "nodo inválido \"Mal\"");
        falla(() -> set.setGroupMeta("vip", "a.*", new Meta("1", OptionalLong.empty())), "meta inválida \"a.*\"");
        falla(() -> set.setGroupMeta("vip", "a", new Meta("x".repeat(257), OptionalLong.empty())), "supera los 256 caracteres");
        var lleno = PermissionSet.empty();
        for (var i = 0; i < 255; i++) {
            lleno = lleno.createGroup("g" + i, 0);
        }
        var casiLleno = lleno;
        falla(() -> casiLleno.createGroup("otro", 0), "como mucho 256 grupos");
        var padres = PermissionSet.empty();
        for (var i = 0; i < 16; i++) {
            padres = padres.createGroup("p" + i, 0).addParent("default", "p" + i);
        }
        var conPadres = padres.createGroup("x", 0);
        falla(() -> conPadres.addParent("default", "x"), "como mucho 16 padres");
    }

    @Test
    void nodosYMetasSeDanQuitanYReemplazan() {
        var set = PermissionSet.empty().setGroupPermission("default", "sam.command.home", SI)
            .setGroupPermission("default", "sam.command.home", NO).setGroupMeta("default", "sam.homes.limit", new Meta("3", OptionalLong.empty()));
        assertThat(set.check("x", "sam.command.home", 0, false).value()).isEqualTo(Value.FALSE);
        assertThat(set.meta("x", "sam.homes.limit", 0)).contains("3");
        set = set.unsetGroupPermission("default", "sam.command.home").unsetGroupMeta("default", "sam.homes.limit");
        assertThat(set).isEqualTo(PermissionSet.empty());
        falla(() -> PermissionSet.empty().unsetGroupPermission("default", "a"), "default no tiene el nodo a");
        falla(() -> PermissionSet.empty().unsetGroupMeta("default", "a"), "default no tiene la meta a");
        var lleno = PermissionSet.empty();
        for (var i = 0; i < 1024; i++) {
            lleno = lleno.setGroupPermission("default", "n" + i, SI);
        }
        var nodos = lleno;
        falla(() -> nodos.setGroupPermission("default", "otro", SI), "como mucho 1024 nodos");
        assertThat(nodos.setGroupPermission("default", "n0", NO).groups().get("default").permissions()).hasSize(1024);
        var metas = PermissionSet.empty();
        for (var i = 0; i < 256; i++) {
            metas = metas.setGroupMeta("default", "m" + i, new Meta("1", OptionalLong.empty()));
        }
        var llenas = metas;
        falla(() -> llenas.setGroupMeta("default", "otra", new Meta("1", OptionalLong.empty())), "como mucho 256 metas");
        assertThat(llenas.setGroupMeta("default", "m0", new Meta("2", OptionalLong.empty())).meta("x", "m0", 0)).contains("2");
    }

    @Test
    void losJugadoresTienenSusPropiosNodosMetasYGrupos() {
        var set = PermissionSet.empty().createGroup("vip", 10)
            .addUserGroup("Steve", "vip", OptionalLong.of(100))
            .setUserPermission("STEVE", "sam.command.nick", SI)
            .setUserMeta("steve", "sam.homes.limit", new Meta("8", OptionalLong.empty()));
        var steve = set.users().get("steve");
        assertThat(steve.groups()).containsEntry("vip", OptionalLong.of(100));
        assertThat(steve.permissions()).containsKey("sam.command.nick");
        assertThat(set.meta("steve", "sam.homes.limit", 0)).contains("8");
        // Volver a agregar cambia el vencimiento
        assertThat(set.addUserGroup("steve", "vip", OptionalLong.empty()).users().get("steve").groups()).containsEntry("vip", OptionalLong.empty());
        set = set.removeUserGroup("steve", "vip").unsetUserPermission("steve", "sam.command.nick").unsetUserMeta("steve", "sam.homes.limit");
        assertThat(set.users()).as("un jugador sin nada no queda en el archivo").isEmpty();
        falla(() -> PermissionSet.empty().addUserGroup("steve", "nada", OptionalLong.empty()), "no existe el grupo nada");
        falla(() -> PermissionSet.empty().addUserGroup("no válido", "default", OptionalLong.empty()), "nick inválido");
        falla(() -> PermissionSet.empty().removeUserGroup("steve", "default"), "steve no está en el grupo default");
        falla(() -> PermissionSet.empty().unsetUserPermission("steve", "a"), "steve no tiene el nodo a");
        falla(() -> PermissionSet.empty().unsetUserMeta("steve", "a"), "steve no tiene la meta a");
        falla(() -> PermissionSet.empty().setUserPermission("steve", "a..b", SI), "nodo inválido");
        assertThat(PermissionSet.parse(set.createGroup("x", 1).addUserGroup("alex", "x", OptionalLong.empty()).toJson()).users())
            .containsOnlyKeys("alex");
    }

    @Test
    void lasDuracionesSeLeen() {
        assertThat(PermissionSet.duration("90s")).isEqualTo(90);
        assertThat(PermissionSet.duration("45m")).isEqualTo(2700);
        assertThat(PermissionSet.duration("12h")).isEqualTo(43_200);
        assertThat(PermissionSet.duration("30d")).isEqualTo(2_592_000);
        assertThat(PermissionSet.duration("1d12h30m5s")).isEqualTo(86_400 + 43_200 + 1800 + 5);
        assertThat(PermissionSet.duration("3650d")).isEqualTo(315_360_000);
        for (var mala : new String[] {"", "0s", "10", "1x", "d", "1d1d", "3651d", "1s1d", "99999999999d"}) {
            assertThatThrownBy(() -> PermissionSet.duration(mala)).as(mala).isInstanceOf(IllegalArgumentException.class)
                .hasMessage("duración inválida \"" + mala + "\": por ejemplo 30d, 12h, 45m, 90s o 1d12h (hasta 3650d)");
        }
    }

    private static void falla(org.assertj.core.api.ThrowableAssert.ThrowingCallable cambio, String motivo) {
        assertThatThrownBy(cambio).isInstanceOf(IllegalArgumentException.class).hasMessageContaining(motivo);
    }
}
