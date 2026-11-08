package dev.sam.common.audit;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.Map;

import org.junit.jupiter.api.Test;

/** RF-ADM-06a (H-09): qué comandos vanilla van a la auditoría. */
class SensitiveCommandsTest {

    private final SensitiveCommands porDefecto = SensitiveCommands.fromConfig(Map.of());

    @Test
    void lasRaicesPorDefecto() {
        for (var c : new String[] {"op Steve", "/deop Steve", "ban Alex griefing", "gamemode creative", "give @s diamond 64",
            "stop", "whitelist add x", "tp Steve 0 64 0"}) {
            assertThat(porDefecto.matches(c)).as(c).isTrue();
        }
        for (var c : new String[] {"help", "msg Steve hola", "list", "operator", "me baila", ""}) {
            assertThat(porDefecto.matches(c)).as(c).isFalse();
        }
    }

    @Test
    void tambienDentroDeExecute() {
        assertThat(porDefecto.matches("execute as @a run op Steve")).isTrue();
        assertThat(porDefecto.matches("/execute at @p run gamemode survival @p")).isTrue();
        assertThat(porDefecto.matches("execute as @a run say hola")).isFalse();
        assertThat(porDefecto.matches("execute as @a")).isFalse();
        assertThat(porDefecto.matches("execute as @a run")).isFalse();
        assertThat(porDefecto.matches("say que no te den op")).isFalse();
    }

    @Test
    void laListaSeConfiguraYNoDistingueMayusculas() {
        var propia = SensitiveCommands.fromConfig(Map.of("SAM_AUDIT_COMMANDS", " , Kick ,, weather"));
        assertThat(propia.matches("weather rain")).isTrue();
        assertThat(propia.matches("KICK Steve")).isTrue();
        assertThat(propia.matches("op Steve")).isFalse();
        assertThat(propia.matches("")).isFalse();
        assertThat(propia.matches("   ")).isFalse();
        assertThat(SensitiveCommands.fromConfig(Map.of("SAM_AUDIT_COMMANDS", "")).matches("op Steve")).isFalse();
    }
}
