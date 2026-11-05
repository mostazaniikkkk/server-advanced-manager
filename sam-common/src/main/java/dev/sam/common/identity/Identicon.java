package dev.sam.common.identity;

import java.util.List;
import java.util.Objects;

/**
 * Identicon de 5×5 simétrico de izquierda a derecha (PROTOCOLO.md 3.5).
 *
 * @param cellMask bit {@code fila * 5 + columna} encendido si la celda está pintada
 * @param rgb      color de las celdas pintadas, siempre de {@link #PALETTE}
 */
public record Identicon(int cellMask, int rgb) {

    public static final int SIZE = 5;

    /**
     * Paleta fija de 16 colores legibles sobre fondo claro. Parte del protocolo: se eligió una
     * paleta en lugar de HSL para que no haya diferencias de redondeo entre implementaciones.
     */
    public static final List<Integer> PALETTE = List.of(
        0xC62828, 0xAD1457, 0x6A1B9A, 0x4527A0, 0x283593, 0x1565C0, 0x0277BD, 0x00838F,
        0x00695C, 0x2E7D32, 0x558B2F, 0x9E9D24, 0xF9A825, 0xEF6C00, 0xD84315, 0x4E342E);

    public boolean isFilled(int row, int column) {
        Objects.checkIndex(row, SIZE);
        Objects.checkIndex(column, SIZE);
        return (cellMask >>> (row * SIZE + column) & 1) == 1;
    }

    /**
     * @param cellBits  16 bits; se usan los 15 más altos (3 columnas izquierdas × 5 filas)
     * @param colorByte se usan sus 4 bits bajos como índice de la paleta
     */
    static Identicon fromBits(int cellBits, int colorByte) {
        int mask = 0;
        for (int row = 0; row < SIZE; row++) {
            for (int column = 0; column < SIZE; column++) {
                int source = row * 3 + Math.min(column, SIZE - 1 - column);
                if ((cellBits >>> (15 - source) & 1) == 1) {
                    mask |= 1 << (row * SIZE + column);
                }
            }
        }
        return new Identicon(mask, PALETTE.get(colorByte & 0x0F));
    }
}
