package dev.sam.common.net.ws;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.TimeUnit;
import java.util.regex.Pattern;

import dev.sam.common.net.IngressPolicy;
import dev.sam.common.net.IngressPolicy.Transport;
import dev.sam.common.net.gate.IngressGateHandler;
import dev.sam.common.net.gate.IngressRoutes;
import dev.sam.common.net.ip.RealIpResolver;
import io.netty.buffer.ByteBuf;
import io.netty.channel.ChannelFutureListener;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInboundHandlerAdapter;
import io.netty.handler.codec.http.DefaultFullHttpResponse;
import io.netty.handler.codec.http.HttpContent;
import io.netty.handler.codec.http.HttpHeaderNames;
import io.netty.handler.codec.http.HttpHeaderValues;
import io.netty.handler.codec.http.HttpRequest;
import io.netty.handler.codec.http.HttpResponseStatus;
import io.netty.handler.codec.http.HttpServerCodec;
import io.netty.handler.codec.http.HttpVersion;
import io.netty.handler.codec.http.LastHttpContent;
import io.netty.handler.codec.http.websocketx.WebSocket13FrameDecoder;
import io.netty.handler.codec.http.websocketx.WebSocket13FrameEncoder;
import io.netty.handler.codec.http.websocketx.WebSocketDecoderConfig;
import io.netty.util.ReferenceCountUtil;
import io.netty.util.concurrent.ScheduledFuture;

/**
 * Handshake HTTP de WebSocket en el mismo puerto (PROTOCOLO.md 2.3, RF-WS-01/02, RS-WS-03/05).
 *
 * <p>Detrás de la compuerta se instala: un límite de bytes de la petición, el codec HTTP y el
 * validador. Si la petición es válida se responde {@code 101} con el subprotocolo {@code sam.v1}
 * y el pipeline pasa a ser: codec de frames → {@link WebSocketTunnel} → una compuerta interna que
 * solo admite el TLS de SAM (RS-WS-01). Cualquier rechazo responde un estado genérico y cierra.
 */
public final class WebSocketUpgrade {

    public static final String SUBPROTOCOL = "sam.v1";
    /** Petición HTTP completa (línea inicial y cabeceras), RS-WS-03. */
    public static final int MAX_REQUEST_BYTES = 8 * 1024;
    /** {@code SAM_WS_HANDSHAKE_TIMEOUT} por defecto: desde la compuerta hasta el 101 (RS-WS-03). */
    public static final java.time.Duration HANDSHAKE_TIMEOUT = java.time.Duration.ofSeconds(5);

    public static final String LIMIT_NAME = "sam_ws_limit";
    public static final String HTTP_NAME = "sam_ws_http";
    public static final String UPGRADE_NAME = "sam_ws_upgrade";
    public static final String ENCODER_NAME = "sam_ws_encoder";
    public static final String DECODER_NAME = "sam_ws_decoder";
    public static final String INNER_GATE_NAME = "sam_ws_gate";

    private static final String RFC6455_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
    private static final int KEY_BYTES = 16;
    /** Ruta del endpoint: caracteres no reservados de RFC 3986 y barras, hasta 128 en total. */
    private static final Pattern PATH = Pattern.compile("/[A-Za-z0-9._~/-]{0,127}");
    /** Dentro del túnel la política no depende de los interruptores: solo pasa TLS. */
    private static final IngressPolicy INSIDE = new IngressPolicy(false, true);

    private WebSocketUpgrade() {
    }

    /** {@code Sec-WebSocket-Accept} de RFC 6455 4.2.2. */
    public static String acceptKey(String key) {
        try {
            var sha1 = MessageDigest.getInstance("SHA-1").digest((key + RFC6455_GUID).getBytes(StandardCharsets.US_ASCII));
            return Base64.getEncoder().encodeToString(sha1);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("La JDK no trae SHA-1", e);
        }
    }

    /** @throws IllegalArgumentException si la ruta configurada ({@code SAM_WS_PATH}) no es segura */
    public static String validatePath(String path) {
        if (!PATH.matcher(path).matches()) {
            throw new IllegalArgumentException("SAM_WS_PATH debe empezar con / y usar solo A-Z a-z 0-9 . _ ~ - / (máximo 128)");
        }
        return path;
    }

    /** Instala el handshake detrás de la compuerta {@code gate}. */
    public static void install(ChannelHandlerContext gate, String path, IngressRoutes routes, RealIpResolver realIp) {
        var pipeline = gate.pipeline();
        pipeline.addAfter(gate.name(), UPGRADE_NAME, new UpgradeHandler(path, routes, realIp));
        pipeline.addAfter(gate.name(), HTTP_NAME, new HttpServerCodec(MAX_REQUEST_BYTES, MAX_REQUEST_BYTES, MAX_REQUEST_BYTES));
        pipeline.addAfter(gate.name(), LIMIT_NAME, new RequestByteLimit());
    }

    /** Valida la petición; {@code null} si se acepta, o el estado del rechazo. */
    static HttpResponseStatus check(HttpRequest request, String path) {
        var headers = request.headers();
        if (request.decoderResult().isFailure() || !HttpVersion.HTTP_1_1.equals(request.protocolVersion())) {
            return HttpResponseStatus.BAD_REQUEST;
        }
        // Primero Origin: una página web no aprende nada sobre la ruta (RS-WS-05)
        if (headers.contains(HttpHeaderNames.ORIGIN)) {
            return HttpResponseStatus.FORBIDDEN;
        }
        if (!path.equals(request.uri())) {
            return HttpResponseStatus.NOT_FOUND;
        }
        var upgrade = single(request, HttpHeaderNames.UPGRADE);
        var version = single(request, HttpHeaderNames.SEC_WEBSOCKET_VERSION);
        var protocol = single(request, HttpHeaderNames.SEC_WEBSOCKET_PROTOCOL);
        var valid = "websocket".equalsIgnoreCase(upgrade)
            && hasToken(headers.getAll(HttpHeaderNames.CONNECTION), "upgrade")
            && "13".equals(version)
            && SUBPROTOCOL.equals(protocol)
            && validKey(single(request, HttpHeaderNames.SEC_WEBSOCKET_KEY));
        return valid ? null : HttpResponseStatus.BAD_REQUEST;
    }

    /** El valor de una cabecera que debe aparecer exactamente una vez, o {@code null}. */
    private static String single(HttpRequest request, CharSequence name) {
        var values = request.headers().getAll(name);
        return values.size() == 1 ? values.get(0).trim() : null;
    }

    private static boolean hasToken(List<String> values, String token) {
        for (var value : values) {
            for (var part : value.split(",")) {
                if (part.trim().toLowerCase(Locale.ROOT).equals(token)) {
                    return true;
                }
            }
        }
        return false;
    }

    private static boolean validKey(String key) {
        if (key == null) {
            return false;
        }
        try {
            return Base64.getDecoder().decode(key).length == KEY_BYTES;
        } catch (IllegalArgumentException e) {
            return false;
        }
    }

    /** Corta la conexión si la petición HTTP supera {@link #MAX_REQUEST_BYTES}. */
    static final class RequestByteLimit extends ChannelInboundHandlerAdapter {
        private int received;

        @Override
        public void channelRead(ChannelHandlerContext ctx, Object msg) {
            received += ((ByteBuf) msg).readableBytes();
            if (received > MAX_REQUEST_BYTES) {
                ReferenceCountUtil.release(msg);
                ctx.close();
                return;
            }
            ctx.fireChannelRead(msg);
        }
    }

    static final class UpgradeHandler extends ChannelInboundHandlerAdapter {
        private final String path;
        private final IngressRoutes routes;
        private final RealIpResolver realIp;
        private String acceptedKey;
        private boolean rejected;
        private ScheduledFuture<?> timeout;

        UpgradeHandler(String path, IngressRoutes routes, RealIpResolver realIp) {
            this.path = path;
            this.routes = routes;
            this.realIp = realIp;
        }

        @Override
        public void handlerAdded(ChannelHandlerContext ctx) {
            // El codec HTTP consume lo que recibe en cuanto llega: al cerrar no le quedan bytes que
            // reenviar a Minecraft (lo prueban los tests de "nada llega a Minecraft")
            // Lambda con bloque: un Runnable (sin valor de retorno que nadie lee)
            timeout = ctx.executor().schedule(() -> {
                ctx.close();
            }, HANDSHAKE_TIMEOUT.toNanos(), TimeUnit.NANOSECONDS);
        }

        @Override
        public void handlerRemoved(ChannelHandlerContext ctx) {
            timeout.cancel(false);
        }


        @Override
        public void channelRead(ChannelHandlerContext ctx, Object msg) {
            try {
                if (rejected) {
                    return;
                }
                if (msg instanceof HttpRequest request) {
                    // Antes de validar: el intento de falsificar la IP se audita aunque se rechace
                    realIp.apply(ctx.channel(), request.headers());
                    var status = check(request, path);
                    if (status != null) {
                        reject(ctx, status);
                        return;
                    }
                    acceptedKey = request.headers().get(HttpHeaderNames.SEC_WEBSOCKET_KEY).trim();
                }
                if (msg instanceof HttpContent content) {
                    // Un GET de WebSocket no lleva cuerpo
                    if (content.content().isReadable()) {
                        reject(ctx, HttpResponseStatus.BAD_REQUEST);
                    } else if (content instanceof LastHttpContent) {
                        upgrade(ctx);
                    }
                }
            } finally {
                ReferenceCountUtil.release(msg);
            }
        }

        private void reject(ChannelHandlerContext ctx, HttpResponseStatus status) {
            rejected = true;
            var response = new DefaultFullHttpResponse(HttpVersion.HTTP_1_1, status);
            response.headers().set(HttpHeaderNames.CONTENT_LENGTH, 0).set(HttpHeaderNames.CONNECTION, HttpHeaderValues.CLOSE);
            ctx.writeAndFlush(response).addListener(ChannelFutureListener.CLOSE);
        }

        private void upgrade(ChannelHandlerContext ctx) {
            var response = new DefaultFullHttpResponse(HttpVersion.HTTP_1_1, HttpResponseStatus.SWITCHING_PROTOCOLS);
            response.headers()
                .set(HttpHeaderNames.UPGRADE, HttpHeaderValues.WEBSOCKET)
                .set(HttpHeaderNames.CONNECTION, HttpHeaderValues.UPGRADE)
                .set(HttpHeaderNames.SEC_WEBSOCKET_ACCEPT, acceptKey(acceptedKey))
                .set(HttpHeaderNames.SEC_WEBSOCKET_PROTOCOL, SUBPROTOCOL);
            ctx.writeAndFlush(response);
            var decoderConfig = WebSocketDecoderConfig.newBuilder()
                .maxFramePayloadLength(WebSocketTunnel.MAX_MESSAGE)
                .expectMaskedFrames(true)
                .allowMaskMismatch(false)
                .allowExtensions(false)
                // Sin cierre propio: la excepción llega al túnel, que cierra sin propagarla (RS-WS-04)
                .closeOnProtocolViolation(false)
                .build();
            var pipeline = ctx.pipeline();
            pipeline.addAfter(HTTP_NAME, ENCODER_NAME, new WebSocket13FrameEncoder(false));
            pipeline.addAfter(ENCODER_NAME, DECODER_NAME, new WebSocket13FrameDecoder(decoderConfig));
            pipeline.addAfter(DECODER_NAME, WebSocketTunnel.NAME, new WebSocketTunnel());
            pipeline.addAfter(WebSocketTunnel.NAME, INNER_GATE_NAME,
                new IngressGateHandler(INSIDE, Transport.INSIDE_WEBSOCKET, routes, ""));
            pipeline.remove(LIMIT_NAME);
            pipeline.remove(this);
            // Al final: si quedaron bytes tras la petición, el codec HTTP los reenvía a los frames
            pipeline.remove(HTTP_NAME);
        }
    }
}
