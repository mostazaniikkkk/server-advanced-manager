package dev.sam.client;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import dev.sam.client.auth.SamClientAuth;
import dev.sam.client.net.SamClientNet;
import dev.sam.common.auth.Argon2Params;
import dev.sam.common.auth.Argon2id;
import dev.sam.common.identity.Wordlist;
import net.fabricmc.api.ClientModInitializer;
import net.fabricmc.loader.api.FabricLoader;

/** Punto de entrada del mod en el cliente. */
public final class SamClient implements ClientModInitializer {

    public static final String MOD_ID = "sam-client";
    public static final Logger LOGGER = LoggerFactory.getLogger("SAM");

    @Override
    public void onInitializeClient() {
        var version = FabricLoader.getInstance().getModContainer(MOD_ID)
            .map(mod -> mod.getMetadata().getVersion().getFriendlyString())
            .orElse("?");
        LOGGER.info("SAM Client {} cargado. Núcleo: {}", version, coreSmokeCheck());
        SamClientNet.init(FabricLoader.getInstance().getConfigDir().resolve("sam-client/pins.json"), LOGGER);
        SamClientAuth.install(LOGGER, version);
        devQuitAfterJoin();
        devQuitOnDisconnect();
    }

    /**
     * Solo en el entorno de desarrollo de Loom: {@code -Dsam.dev.quitAfterJoin=N} cierra el juego N
     * segundos después de entrar al mundo, para la prueba de punta a punta automática.
     */
    private static void devQuitAfterJoin() {
        var seconds = Integer.getInteger("sam.dev.quitAfterJoin");
        if (!FabricLoader.getInstance().isDevelopmentEnvironment() || seconds == null) {
            return;
        }
        net.fabricmc.fabric.api.client.networking.v1.ClientPlayConnectionEvents.JOIN.register((handler, sender, client) -> {
            LOGGER.info("[dev] En el mundo como {}; el juego se cierra en {} s", client.getUser().getName(), seconds);
            var timer = new Thread(() -> {
                try {
                    Thread.sleep(seconds * 1000L);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
                client.execute(client::stop);
            }, "SAM dev quit");
            timer.setDaemon(true);
            timer.start();
        });
    }

    /**
     * Solo en desarrollo, con {@code sam.dev.quitAfterJoin} o {@code sam.dev.screenshot}: si la conexión
     * termina en la pantalla de desconexión, se captura (con el motivo) y se cierra el juego.
     */
    private static void devQuitOnDisconnect() {
        if (!FabricLoader.getInstance().isDevelopmentEnvironment()
                || (System.getProperty("sam.dev.quitAfterJoin") == null && System.getProperty("sam.dev.screenshot") == null)) {
            return;
        }
        net.fabricmc.fabric.api.client.screen.v1.ScreenEvents.AFTER_INIT.register((client, screen, width, height) -> {
            if (!(screen instanceof net.minecraft.client.gui.screens.DisconnectedScreen)) {
                return;
            }
            var ticks = new int[1];
            net.fabricmc.fabric.api.client.screen.v1.ScreenEvents.afterTick(screen).register(shown -> {
                if (++ticks[0] != 30) {
                    return;
                }
                var name = System.getProperty("sam.dev.screenshot", "desconexion");
                net.minecraft.client.Screenshot.grab(client.gameDirectory, name + ".png", client.getMainRenderTarget(),
                    message -> LOGGER.info("[dev] Desconectado; captura: {}", message.getString()));
                client.execute(client::stop);
            });
        });
    }

    /** Igual que en el servidor: comprueba que el núcleo embebido carga. */
    static String coreSmokeCheck() {
        var words = Wordlist.spanish().size();
        var argon2 = Argon2id.hash(new byte[] {1}, new byte[8], new Argon2Params(8, 1, 1), 16).length;
        return words + " palabras de huella, Argon2 " + (argon2 == 16 ? "OK" : "FALLA");
    }
}
