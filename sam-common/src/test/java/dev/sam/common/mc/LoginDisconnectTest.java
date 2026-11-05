package dev.sam.common.mc;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.HexFormat;

import org.junit.jupiter.api.Test;

/** Paquete de desconexión en fase login (clientbound, id 0x00): un text component JSON. */
class LoginDisconnectTest {

    static final String MENSAJE = "Este servidor requiere SAM Client: https://github.com/sam/releases [SAM-K001]";

    @Test
    void coincideConElVectorDeReferencia() {
        assertThat(HexFormat.of().formatHex(LoginDisconnect.frame(MENSAJE))).isEqualTo(
            "5a00587b2274657874223a2245737465207365727669646f722072657175696572652053414d20436c69656e743a2068747470733a2f2f6769746875622e636f6d2f73616d2f72656c6561736573205b53414d2d4b3030315d227d");
    }

    @Test
    void escapaComillasBarrasYSaltosDeLineaComoJson() {
        assertThat(LoginDisconnect.textComponent("Dice \"hola\" \\ ruta\nñ"))
            .isEqualTo("{\"text\":\"Dice \\\"hola\\\" \\\\ ruta\\nñ\"}");
        assertThat(HexFormat.of().formatHex(LoginDisconnect.frame("Dice \"hola\" \\ ruta\nñ")))
            .isEqualTo("2600247b2274657874223a2244696365205c22686f6c615c22205c5c20727574615c6ec3b1227d");
    }

    @Test
    void escapaLosDemasCaracteresDeControl() {
        assertThat(LoginDisconnect.textComponent("a\tb\rc\bd\fe\u0001f\u001fg\u007fh"))
            .isEqualTo("{\"text\":\"a\\tb\\rc\\bd\\fe\\u0001f\\u001fg\u007fh\"}");
    }
}
