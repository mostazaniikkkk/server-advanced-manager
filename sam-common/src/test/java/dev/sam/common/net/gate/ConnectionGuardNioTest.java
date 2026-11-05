package dev.sam.common.net.gate;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.util.ArrayList;
import java.util.concurrent.TimeUnit;

import org.junit.jupiter.api.Test;

import dev.sam.common.net.IngressPolicy;
import dev.sam.common.net.IngressPolicy.Transport;
import io.netty.bootstrap.ServerBootstrap;
import io.netty.channel.Channel;
import io.netty.channel.ChannelInitializer;
import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.channel.socket.nio.NioServerSocketChannel;

/**
 * El guardia con sockets reales (NIO), como en el servidor: la conexión que excede el límite por IP
 * se cierra en el acto, no al vencer el plazo de clasificación.
 */
class ConnectionGuardNioTest {

    @Test
    void conSocketsRealesLaQueExcedeElLimiteSeCierraEnElActo() throws Exception {
        var guardia = new ConnectionGuard(2, 256, ip -> false);
        var grupo = new NioEventLoopGroup(2);
        try {
            var servidor = new ServerBootstrap().group(grupo).channel(NioServerSocketChannel.class)
                .childHandler(new ChannelInitializer<Channel>() {
                    @Override
                    protected void initChannel(Channel ch) {
                        IngressGate.install(ch.pipeline(), new IngressPolicy(true, false), Transport.DIRECT_TCP,
                            IngressRoutes.closing(), "kick", guardia);
                    }
                })
                .bind("127.0.0.1", 0).sync().channel();
            var puerto = ((InetSocketAddress) servidor.localAddress()).getPort();
            var abiertas = new ArrayList<Socket>();
            try {
                for (int i = 0; i < 2; i++) {
                    abiertas.add(new Socket("127.0.0.1", puerto));
                }
                try (var tercera = new Socket("127.0.0.1", puerto)) {
                    tercera.setSoTimeout(3000);
                    int leido;
                    try {
                        leido = tercera.getInputStream().read();
                    } catch (IOException reset) {
                        leido = -1;
                    }
                    assertThat(leido).isEqualTo(-1);
                }
                assertThat(guardia.pending()).isEqualTo(2);
            } finally {
                for (var s : abiertas) {
                    s.close();
                }
                servidor.close().sync();
            }
        } finally {
            grupo.shutdownGracefully(0, 1, TimeUnit.SECONDS).sync();
        }
    }
}
