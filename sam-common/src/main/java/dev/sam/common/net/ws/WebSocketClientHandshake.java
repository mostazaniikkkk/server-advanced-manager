package dev.sam.common.net.ws;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.function.Consumer;

import io.netty.buffer.ByteBuf;
import io.netty.buffer.ByteBufUtil;
import io.netty.buffer.Unpooled;
import io.netty.channel.ChannelHandlerContext;
import io.netty.handler.codec.ByteToMessageDecoder;
import io.netty.handler.codec.http.websocketx.WebSocket13FrameDecoder;
import io.netty.handler.codec.http.websocketx.WebSocket13FrameEncoder;

/**
 * El handshake WebSocket del cliente (PROTOCOLO.md 2.3, RF-WS-04): pide {@code GET <ruta>} con el
 * subprotocolo {@code sam.v1} y valida el {@code 101} (aceptación RFC 6455 y subprotocolo). Si todo
 * está bien, queda en su lugar el túnel de mensajes binarios ({@link WebSocketTunnel}) y se avisa a
 * {@code onUpgraded}, que pone encima el TLS de SAM. Cualquier otra respuesta cierra la conexión.
 */
public final class WebSocketClientHandshake extends ByteToMessageDecoder {

    public static final String NAME = "sam_ws_client";
    /** Una respuesta de handshake real ocupa unos cientos de bytes. */
    public static final int MAX_RESPONSE_BYTES = 8 * 1024;

    static final String ENCODER_NAME = "sam_ws_client_encoder";
    static final String DECODER_NAME = "sam_ws_client_decoder";

    private static final byte[] END_OF_HEADER = {'\r', '\n', '\r', '\n'};
    /** El proxy (CDN, túnel) respondió pero no llegó al servidor; 530 es Cloudflare con el túnel caído. */
    private static final List<String> PROXY_WITHOUT_ORIGIN = List.of("502", "503", "504", "530");

    private final String host;
    private final String path;
    private final String key;
    private final Consumer<ChannelHandlerContext> onUpgraded;
    private final Consumer<String> onFailure;

    /**
     * @param host valor de la cabecera {@code Host} (con el puerto si no es el de por defecto)
     * @param onUpgraded se llama con el contexto del túnel ya instalado
     * @param onFailure se llama con el motivo antes de cerrar
     */
    public WebSocketClientHandshake(String host, String path, SecureRandom random, Consumer<ChannelHandlerContext> onUpgraded,
            Consumer<String> onFailure) {
        this.host = host;
        this.path = path;
        var nonce = new byte[16];
        random.nextBytes(nonce);
        this.key = Base64.getEncoder().encodeToString(nonce);
        this.onUpgraded = onUpgraded;
        this.onFailure = onFailure;
    }

    /** Se agrega con el canal ya activo (el cliente lo pone al activarse la conexión): pide el upgrade. */
    @Override
    public void handlerAdded(ChannelHandlerContext ctx) {
        var request = "GET " + path + " HTTP/1.1\r\nHost: " + host + "\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
            + "Sec-WebSocket-Key: " + key + "\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Protocol: "
            + WebSocketUpgrade.SUBPROTOCOL + "\r\n\r\n";
        ctx.writeAndFlush(Unpooled.wrappedBuffer(request.getBytes(StandardCharsets.US_ASCII)));
    }

    @Override
    protected void decode(ChannelHandlerContext ctx, ByteBuf in, List<Object> out) {
        // Sobre un slice: el índice es relativo a lo que falta leer
        var end = ByteBufUtil.indexOf(Unpooled.wrappedBuffer(END_OF_HEADER), in.slice());
        if (end < 0) {
            if (in.readableBytes() > MAX_RESPONSE_BYTES) {
                fail(ctx, in, "respuesta del handshake WebSocket demasiado larga");
            }
            return;
        }
        var header = in.readCharSequence(end + END_OF_HEADER.length, StandardCharsets.ISO_8859_1).toString();
        var problem = check(header);
        if (problem != null) {
            fail(ctx, in, problem);
            return;
        }
        var pipeline = ctx.pipeline();
        pipeline.addAfter(ctx.name(), ENCODER_NAME, new WebSocket13FrameEncoder(true));
        pipeline.addAfter(ENCODER_NAME, DECODER_NAME, new WebSocket13FrameDecoder(false, false, WebSocketTunnel.MAX_MESSAGE));
        pipeline.addAfter(DECODER_NAME, WebSocketTunnel.NAME, new WebSocketTunnel());
        onUpgraded.accept(pipeline.context(WebSocketTunnel.NAME));
        // Al quitarse, lo que llegó pegado al encabezado (el primer frame) sigue hacia el decodificador
        pipeline.remove(this);
    }

    /** @return el motivo del rechazo, o {@code null} si el 101 es válido */
    private String check(String header) {
        // Con límite -1: una respuesta vacía da una línea de estado vacía, no un arreglo vacío
        var lines = header.split("\r\n", -1);
        if (!lines[0].startsWith("HTTP/1.1 101")) {
            if (PROXY_WITHOUT_ORIGIN.stream().anyMatch(code -> lines[0].startsWith("HTTP/1.1 " + code + " "))) {
                return "el servidor de Minecraft no está disponible detrás del proxy (respondió «" + lines[0] + "»)";
            }
            return "el servidor respondió «" + lines[0] + "» (¿ruta del WebSocket correcta?)";
        }
        var headers = new HashMap<String, String>();
        for (var line : Arrays.copyOfRange(lines, 1, lines.length)) {
            var parts = line.split(":", 2);
            if (parts.length == 2) {
                headers.put(parts[0].strip().toLowerCase(Locale.ROOT), parts[1].strip());
            }
        }
        var connection = Arrays.stream(headers.getOrDefault("connection", "").split(","))
            .anyMatch(token -> token.strip().equalsIgnoreCase("upgrade"));
        if (!"websocket".equalsIgnoreCase(headers.get("upgrade")) || !connection) {
            return "el servidor no aceptó el upgrade a WebSocket";
        }
        if (!WebSocketUpgrade.acceptKey(key).equals(headers.get("sec-websocket-accept"))) {
            return "aceptación WebSocket inválida";
        }
        if (!WebSocketUpgrade.SUBPROTOCOL.equals(headers.get("sec-websocket-protocol"))) {
            return "el servidor no aceptó el subprotocolo " + WebSocketUpgrade.SUBPROTOCOL;
        }
        return null;
    }

    private void fail(ChannelHandlerContext ctx, ByteBuf in, String reason) {
        in.skipBytes(in.readableBytes());
        onFailure.accept(reason);
        ctx.close();
    }
}
