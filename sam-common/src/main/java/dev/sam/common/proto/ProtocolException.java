package dev.sam.common.proto;

/**
 * Mensaje SAM mal formado (PROTOCOLO.md 4.1, RS-NET-11): se desconecta con {@value #MALFORMED} y se
 * audita. El mensaje describe el problema sin incluir los bytes recibidos.
 */
public final class ProtocolException extends RuntimeException {

    public static final String MALFORMED = "SAM-P001";
    public static final String OUT_OF_STATE = "SAM-P002";

    private static final long serialVersionUID = 1L;

    private final String code;

    public ProtocolException(String code, String message) {
        super(message);
        this.code = code;
    }

    static ProtocolException malformed(String message) {
        return new ProtocolException(MALFORMED, message);
    }

    /**
     * Construye lo leído: si el valor no cumple sus reglas ({@link IllegalArgumentException} del
     * constructor), el mensaje es mal formado, con el mismo detalle.
     */
    public static <T> T fromRead(java.util.function.Supplier<T> value) {
        try {
            return value.get();
        } catch (IllegalArgumentException e) {
            throw malformed(e.getMessage());
        }
    }

    public String code() {
        return code;
    }
}
