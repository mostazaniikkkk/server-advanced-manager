package dev.sam.server.qa;

import static dev.sam.server.qa.QaWire.HOST;
import static dev.sam.server.qa.QaWire.PORT;
import static dev.sam.server.qa.QaWire.PROTOCOL_1_21_1;
import static dev.sam.server.qa.QaWire.handshake;
import static dev.sam.server.qa.QaWire.leerFrame;
import static dev.sam.server.qa.QaWire.loginStart;
import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import java.io.InputStream;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import dev.sam.common.net.tls.SamTls;
import dev.sam.common.net.tls.ServerCertificateObserver;
import io.netty.bootstrap.Bootstrap;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import io.netty.channel.Channel;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInboundHandlerAdapter;
import io.netty.channel.ChannelInitializer;
import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.channel.socket.nio.NioSocketChannel;
import io.netty.handler.ssl.SslHandler;

/**
 * De punta a punta contra QA Server SAM: un cliente con el perfil TLS de SAM (TLS 1.3, ALPN
 * {@code sam/1}) conecta al mismo puerto que Minecraft. Dentro del túnel el ping de estado llega a
 * Minecraft y el login recibe SAM-K006 hasta que exista la autenticación. Requiere que el servidor
 * haya arrancado con {@code SAM_IDENTITY_PASSPHRASE} definida.
 */
class SamClientTlsQaTest {

    private static NioEventLoopGroup grupo;

    @BeforeAll
    static void grupo() {
        grupo = new NioEventLoopGroup(1);
    }

    @AfterAll
    static void cerrarGrupo() {
        grupo.shutdownGracefully(0, 1, TimeUnit.SECONDS).syncUninterruptibly();
    }

    @Test
    void unPingDeEstadoPorTlsVeElServidorYSuIdentidad() throws Exception {
        var observador = new ServerCertificateObserver();
        try (var conexion = Conexion.abrir(observador)) {
            conexion.enviar(handshake(1), QaWire.STATUS_REQUEST);
            var respuesta = leerFrame(conexion.entrada());
            assertThat(respuesta.id()).isZero();
            assertThat(respuesta.texto()).contains("SAM QA").contains("\"protocol\":" + PROTOCOL_1_21_1);
        }
        assertThat(observador.observed()).as("el servidor presentó su identidad SAM").isPresent();
    }

    @Test
    void unLoginPorTlsRecibeSamK006YSeCierra() throws Exception {
        try (var conexion = Conexion.abrir(new ServerCertificateObserver())) {
            conexion.enviar(handshake(2), loginStart("QaSam"));
            var entrada = conexion.entrada();
            var respuesta = leerFrame(entrada);
            assertThat(respuesta.id()).isZero();
            assertThat(respuesta.texto()).contains("SAM-K006");
            assertThat(entrada.read()).as("el servidor cierra tras el kick").isEqualTo(-1);
        }
    }

    @Test
    void unClienteTlsSinAlpnSamEsCerradoSinRecibirDatos() throws Exception {
        var contexto = SSLContext.getInstance(SamTls.PROTOCOL);
        contexto.init(null, new TrustManager[] {new AceptaTodo()}, new SecureRandom());
        try (var socket = (SSLSocket) contexto.getSocketFactory().createSocket(HOST, PORT)) {
            socket.setSoTimeout(5000);
            socket.startHandshake();
            var out = socket.getOutputStream();
            out.write(handshake(1));
            out.write(QaWire.STATUS_REQUEST);
            out.flush();
            int leido;
            try {
                leido = socket.getInputStream().read();
            } catch (IOException cerrado) {
                leido = -1;
            }
            assertThat(leido).as("sin ALPN sam/1 el servidor cierra sin responder").isEqualTo(-1);
        }
    }

    // ===== Cliente Netty con el perfil TLS de SAM y lectura bloqueante =====

    private static final class Conexion implements AutoCloseable {
        private static final byte[] FIN = new byte[0];
        private final Channel canal;
        private final BlockingQueue<byte[]> recibido;

        private Conexion(Channel canal, BlockingQueue<byte[]> recibido) {
            this.canal = canal;
            this.recibido = recibido;
        }

        static Conexion abrir(ServerCertificateObserver observador) throws Exception {
            var recibido = new LinkedBlockingQueue<byte[]>();
            var tls = new SslHandler(SamTls.clientEngine(observador, HOST, PORT));
            var canal = new Bootstrap().group(grupo).channel(NioSocketChannel.class)
                .handler(new ChannelInitializer<Channel>() {
                    @Override
                    protected void initChannel(Channel ch) {
                        ch.pipeline().addLast(tls, new ChannelInboundHandlerAdapter() {
                            @Override
                            public void channelRead(ChannelHandlerContext ctx, Object msg) {
                                var buf = (ByteBuf) msg;
                                var bytes = new byte[buf.readableBytes()];
                                buf.readBytes(bytes);
                                buf.release();
                                recibido.add(bytes);
                            }

                            @Override
                            public void channelInactive(ChannelHandlerContext ctx) {
                                recibido.add(FIN);
                            }
                        });
                    }
                })
                .connect(HOST, PORT).sync().channel();
            assertThat(tls.handshakeFuture().await(5, TimeUnit.SECONDS)).as("handshake TLS a tiempo").isTrue();
            assertThat(tls.handshakeFuture().isSuccess()).as("handshake TLS exitoso: %s", tls.handshakeFuture().cause()).isTrue();
            assertThat(tls.engine().getApplicationProtocol()).isEqualTo(SamTls.ALPN);
            return new Conexion(canal, recibido);
        }

        void enviar(byte[]... partes) {
            for (var parte : partes) {
                canal.write(Unpooled.wrappedBuffer(parte));
            }
            canal.flush();
        }

        InputStream entrada() {
            return new InputStream() {
                private byte[] actual = new byte[0];
                private int pos;
                private boolean fin;

                @Override
                public int read() throws IOException {
                    while (!fin && pos == actual.length) {
                        try {
                            var siguiente = recibido.poll(5, TimeUnit.SECONDS);
                            if (siguiente == null) {
                                throw new IOException("el servidor no respondió en 5 s");
                            }
                            if (siguiente == FIN) {
                                fin = true;
                            } else {
                                actual = siguiente;
                                pos = 0;
                            }
                        } catch (InterruptedException e) {
                            Thread.currentThread().interrupt();
                            throw new IOException(e);
                        }
                    }
                    return fin ? -1 : actual[pos++] & 0xFF;
                }
            };
        }

        @Override
        public void close() {
            canal.close().syncUninterruptibly();
        }
    }

    /** Solo para el cliente TLS genérico (sin ALPN): no valida nada. */
    private static final class AceptaTodo implements X509TrustManager {
        @Override
        public void checkClientTrusted(X509Certificate[] chain, String authType) {
        }

        @Override
        public void checkServerTrusted(X509Certificate[] chain, String authType) {
        }

        @Override
        public X509Certificate[] getAcceptedIssuers() {
            return new X509Certificate[0];
        }
    }
}
