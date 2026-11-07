package dev.sam.common.lua;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

/** El tope de {@code sam:lua_msg} por jugador y script (PROTOCOLO.md 5.7): 20 por segundo, ráfaga de 40. */
class MessageBudgetTest {

    @Test
    void unaRafagaDe40YDespuesUnoPorTick() {
        var tope = new MessageBudget();
        for (var i = 0; i < 40; i++) {
            assertThat(tope.take(100)).as("mensaje %d", i).isTrue();
        }
        assertThat(tope.take(100)).isFalse();
        assertThat(tope.take(101)).isTrue();
        assertThat(tope.take(101)).isFalse();
        // Tras 3 ticks hay 3 más
        assertThat(tope.take(104)).isTrue();
        assertThat(tope.take(104)).isTrue();
        assertThat(tope.take(104)).isTrue();
        assertThat(tope.take(104)).isFalse();
        // Nunca acumula más de 40
        for (var i = 0; i < 40; i++) {
            assertThat(tope.take(10_000)).isTrue();
        }
        assertThat(tope.take(10_000)).isFalse();
    }
}
