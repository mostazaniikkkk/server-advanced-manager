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
        dev.sam.client.scripts.SamClientScripts.install(LOGGER, FabricLoader.getInstance().getGameDir().resolve("sam-client/script-cache"),
            FabricLoader.getInstance().getConfigDir().resolve("sam-client/scripts.properties"));
        dev.sam.client.account.SamClientAccount.install(LOGGER);
        dev.sam.client.account.SamClientAccount.devHook();
        dev.sam.client.account.SamClientAccount.devMenu();
        devQuitAfterJoin();
        devQuitOnDisconnect();
        devServerList();
    }

    /**
     * Solo en desarrollo: {@code -Dsam.dev.serverList=dirección} abre la lista de servidores con solo
     * esa entrada, captura la lista a los 100 ticks (con {@code sam.dev.screenshot}) y cierra el juego.
     */
    private static void devServerList() {
        var address = System.getProperty("sam.dev.serverList");
        if (!FabricLoader.getInstance().isDevelopmentEnvironment() || address == null) {
            return;
        }
        var opened = new boolean[1];
        net.fabricmc.fabric.api.client.screen.v1.ScreenEvents.AFTER_INIT.register((client, screen, width, height) -> {
            if (screen instanceof net.minecraft.client.gui.screens.TitleScreen && !opened[0]) {
                opened[0] = true;
                var list = new net.minecraft.client.multiplayer.ServerList(client);
                list.load();
                while (list.size() > 0) {
                    list.remove(list.get(0));
                }
                list.add(new net.minecraft.client.multiplayer.ServerData("SAM dev", address,
                    net.minecraft.client.multiplayer.ServerData.Type.OTHER), false);
                list.save();
                client.execute(() -> client.setScreen(
                    new net.minecraft.client.gui.screens.multiplayer.JoinMultiplayerScreen(screen)));
            } else if (screen instanceof net.minecraft.client.gui.screens.multiplayer.JoinMultiplayerScreen) {
                var ticks = new int[1];
                net.fabricmc.fabric.api.client.screen.v1.ScreenEvents.afterTick(screen).register(shown -> {
                    if (++ticks[0] != 100) {
                        return;
                    }
                    var name = System.getProperty("sam.dev.screenshot", "lista");
                    net.minecraft.client.Screenshot.grab(client.gameDirectory, name + ".png", client.getMainRenderTarget(),
                        message -> LOGGER.info("[dev] Lista de servidores; captura: {}", message.getString()));
                    client.execute(client::stop);
                });
            }
        });
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
            // -Dsam.dev.command="hola mundo|otro": ejecuta comandos al entrar (pruebas de los comandos de scripts)
            var command = System.getProperty("sam.dev.command");
            // Varios comandos separados por "|", en orden; con closeScreenAfter, después de cerrar la pantalla
            Runnable commands = () -> {
                if (command != null) {
                    for (var each : command.split("\\|")) {
                        client.execute(() -> handler.sendCommand(each.strip()));
                    }
                }
            };
            // -Dsam.dev.closeScreenAfter=N: a los N s cierra la pantalla que haya (la de otro mod al entrar)
            var close = Integer.getInteger("sam.dev.closeScreenAfter");
            if (close == null) {
                commands.run();
            } else {
                var closer = new Thread(() -> {
                    try {
                        Thread.sleep(close * 1000L);
                    } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                    }
                    client.execute(() -> client.setScreen(null));
                    commands.run();
                }, "SAM dev close");
                closer.setDaemon(true);
                closer.start();
            }
            var timer = new Thread(() -> {
                try {
                    Thread.sleep(seconds * 1000L);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
                // -Dsam.dev.worldScreenshot=nombre: cierra la pantalla abierta (si otro mod abrió una), espera un
                // segundo y captura el mundo con el HUD de los scripts antes de cerrar
                var shot = System.getProperty("sam.dev.worldScreenshot");
                // -Dsam.dev.keepScreen=true: captura con la pantalla abierta (la de un script) y después la cierra
                var keep = Boolean.getBoolean("sam.dev.keepScreen");
                if (shot != null && keep) {
                    // Captura la pantalla abierta tal como está (la de otro mod se cierra antes con closeScreenAfter)
                    client.execute(() -> net.minecraft.client.Screenshot.grab(client.gameDirectory, shot + ".png",
                        client.getMainRenderTarget(), message -> LOGGER.info("[dev] Captura: {}", message.getString())));
                }
                if (shot != null) {
                    client.execute(() -> client.setScreen(null));
                    try {
                        Thread.sleep(1000);
                    } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                    }
                }
                client.execute(() -> {
                    // Con keepScreen, la segunda captura es el mundo ya sin la pantalla (el HUD de los scripts)
                    if (shot != null) {
                        net.minecraft.client.Screenshot.grab(client.gameDirectory, shot + (keep ? "-hud" : "") + ".png",
                            client.getMainRenderTarget(), message -> LOGGER.info("[dev] Captura: {}", message.getString()));
                    }
                    client.stop();
                });
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
