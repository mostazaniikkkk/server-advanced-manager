package dev.sam.common.lua;

/**
 * El tope de {@code sam:lua_msg} que acepta el servidor por jugador y script (PROTOCOLO.md 5.7): un cubo de
 * 40 fichas que recupera una por tick (20 por segundo). No es seguro entre hilos: se usa en el del servidor.
 */
public final class MessageBudget {

    private static final int BURST = 40;

    private long tokens = BURST;
    /** Antes del primer mensaje, "en el futuro": no recupera nada (los ticks nunca son negativos). */
    private long last = Long.MAX_VALUE;

    /** @return si el mensaje que llegó en este tick entra en el tope */
    public boolean take(long tick) {
        tokens = Math.min(BURST, tokens + Math.max(0, tick - last));
        last = tick;
        if (tokens == 0) {
            return false;
        }
        tokens--;
        return true;
    }
}
