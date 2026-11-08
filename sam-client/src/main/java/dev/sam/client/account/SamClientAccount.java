package dev.sam.client.account;

import java.util.function.Consumer;
import java.util.function.Function;

import org.slf4j.Logger;

import dev.sam.client.auth.GoogleFlow;
import dev.sam.client.net.SamPayload;
import dev.sam.common.proto.ProtocolException;
import dev.sam.common.proto.SamReader;
import dev.sam.common.proto.SamWriter;
import dev.sam.common.proto.account.AccountEmail;
import dev.sam.common.proto.account.AccountInfo;
import dev.sam.common.proto.account.AccountResult;
import dev.sam.common.proto.account.AccountUnlink;
import dev.sam.common.proto.account.OAuthCode;
import dev.sam.common.proto.account.OAuthStart;
import dev.sam.common.proto.account.OAuthUrl;
import dev.sam.common.proto.account.TotpBegin;
import dev.sam.common.proto.account.TotpConfirm;
import dev.sam.common.proto.account.TotpDisable;
import dev.sam.common.proto.account.TotpEnroll;
import io.netty.buffer.ByteBufUtil;
import io.netty.buffer.Unpooled;
import net.fabricmc.fabric.api.client.networking.v1.ClientPlayNetworking;
import net.fabricmc.fabric.api.client.screen.v1.ScreenEvents;
import net.fabricmc.fabric.api.client.screen.v1.Screens;
import net.fabricmc.fabric.api.networking.v1.PayloadTypeRegistry;
import net.minecraft.client.gui.screens.inventory.CreativeModeInventoryScreen;
import net.minecraft.client.gui.screens.inventory.InventoryScreen;
import net.minecraft.network.protocol.common.custom.CustomPacketPayload;

/**
 * "Opciones de cuenta" en el cliente (RF-AUTH-07d, PROTOCOLO.md 5.7): el botón del inventario, la
 * pantalla y sus mensajes en la fase play. El botón solo aparece si el servidor atiende la cuenta de SAM.
 */
public final class SamClientAccount {

    public static final CustomPacketPayload.Type<SamPayload> REQUEST = SamPayload.type("account_request");
    public static final CustomPacketPayload.Type<SamPayload> INFO = SamPayload.type(AccountInfo.ID);
    public static final CustomPacketPayload.Type<SamPayload> EMAIL = SamPayload.type(AccountEmail.ID);
    public static final CustomPacketPayload.Type<SamPayload> UNLINK = SamPayload.type(AccountUnlink.ID);
    public static final CustomPacketPayload.Type<SamPayload> RESULT = SamPayload.type(AccountResult.ID);
    public static final CustomPacketPayload.Type<SamPayload> OAUTH_START = SamPayload.type(OAuthStart.ID);
    public static final CustomPacketPayload.Type<SamPayload> OAUTH_URL = SamPayload.type(OAuthUrl.ID);
    public static final CustomPacketPayload.Type<SamPayload> OAUTH_CODE = SamPayload.type(OAuthCode.ID);
    public static final CustomPacketPayload.Type<SamPayload> TOTP_BEGIN = SamPayload.type(TotpBegin.ID);
    public static final CustomPacketPayload.Type<SamPayload> TOTP_ENROLL = SamPayload.type(TotpEnroll.ID);
    public static final CustomPacketPayload.Type<SamPayload> TOTP_CONFIRM = SamPayload.type(TotpConfirm.ID);
    public static final CustomPacketPayload.Type<SamPayload> TOTP_DISABLE = SamPayload.type(TotpDisable.ID);

    private static final int MAX_SERVER_MESSAGE = 4096;

    private static Logger log;

    private SamClientAccount() {
    }

    public static void install(Logger logger) {
        log = logger;
        PayloadTypeRegistry.playC2S().register(REQUEST, SamPayload.codec(REQUEST, 0));
        PayloadTypeRegistry.playC2S().register(EMAIL, SamPayload.codec(EMAIL, AccountEmail.MAX_BYTES));
        PayloadTypeRegistry.playC2S().register(UNLINK, SamPayload.codec(UNLINK, AccountUnlink.MAX_BYTES));
        PayloadTypeRegistry.playC2S().register(OAUTH_START, SamPayload.codec(OAUTH_START, OAuthStart.MAX_BYTES));
        PayloadTypeRegistry.playC2S().register(OAUTH_CODE, SamPayload.codec(OAUTH_CODE, OAuthCode.MAX_BYTES));
        PayloadTypeRegistry.playC2S().register(TOTP_BEGIN, SamPayload.codec(TOTP_BEGIN, TotpBegin.MAX_BYTES));
        PayloadTypeRegistry.playC2S().register(TOTP_CONFIRM, SamPayload.codec(TOTP_CONFIRM, TotpConfirm.MAX_BYTES));
        PayloadTypeRegistry.playC2S().register(TOTP_DISABLE, SamPayload.codec(TOTP_DISABLE, TotpDisable.MAX_BYTES));
        PayloadTypeRegistry.playS2C().register(TOTP_ENROLL, SamPayload.codec(TOTP_ENROLL, MAX_SERVER_MESSAGE));
        ClientPlayNetworking.registerGlobalReceiver(TOTP_ENROLL, (payload, context) -> {
            var enroll = decode(payload, TotpEnroll::read);
            if (enroll != null && context.client().screen instanceof AccountScreen screen) {
                screen.onEnroll(enroll);
            }
        });
        PayloadTypeRegistry.playS2C().register(INFO, SamPayload.codec(INFO, MAX_SERVER_MESSAGE));
        PayloadTypeRegistry.playS2C().register(RESULT, SamPayload.codec(RESULT, MAX_SERVER_MESSAGE));
        PayloadTypeRegistry.playS2C().register(OAUTH_URL, SamPayload.codec(OAUTH_URL, MAX_SERVER_MESSAGE));

        ClientPlayNetworking.registerGlobalReceiver(INFO, (payload, context) -> {
            var info = decode(payload, AccountInfo::read);
            if (info != null && context.client().screen instanceof AccountScreen screen) {
                screen.onInfo(info);
            } else if (info != null && context.client().screen instanceof TotpEnrollScreen screen) {
                screen.onInfo(info);
            }
        });
        ClientPlayNetworking.registerGlobalReceiver(RESULT, (payload, context) -> {
            var result = decode(payload, AccountResult::read);
            if (result != null && context.client().screen instanceof AccountScreen screen) {
                screen.onResult(result);
            } else if (result != null && context.client().screen instanceof TotpEnrollScreen screen) {
                screen.onResult(result);
            }
        });
        ClientPlayNetworking.registerGlobalReceiver(OAUTH_URL, (payload, context) -> {
            var url = decode(payload, OAuthUrl::read);
            if (url != null) {
                GoogleFlow.onUrl(url.url());
            }
        });

        // El botón en el inventario (supervivencia y creativo), abajo a la derecha de la pantalla
        ScreenEvents.AFTER_INIT.register((client, screen, width, height) -> {
            if ((screen instanceof InventoryScreen || screen instanceof CreativeModeInventoryScreen) && ClientPlayNetworking.canSend(REQUEST)) {
                var buttons = Screens.getButtons(screen);
                var menu = new java.util.ArrayList<net.minecraft.client.gui.components.AbstractWidget>();
                var x = width - AccountButton.SIZE - 4;
                var y = height - AccountButton.SIZE - 4;
                buttons.add(new AccountButton(x, y, () -> {
                    var plugins = AccountMenu.pluginItems();
                    // Sin entradas de plugins, el botón abre Opciones de cuenta como siempre
                    if (plugins.isEmpty()) {
                        client.setScreen(new AccountScreen(screen));
                        return;
                    }
                    // Con entradas, es un menú desplegable hacia arriba: Opciones de cuenta y después los plugins
                    if (!menu.isEmpty()) {
                        buttons.removeAll(menu);
                        menu.clear();
                        return;
                    }
                    var items = new java.util.ArrayList<AccountMenu.Item>();
                    items.add(new AccountMenu.Item("Opciones de cuenta", () -> client.setScreen(new AccountScreen(screen)), null));
                    items.addAll(plugins);
                    var right = x + AccountButton.SIZE;
                    for (var i = 0; i < items.size(); i++) {
                        var item = items.get(i);
                        var top = y - (items.size() - i) * 21;
                        menu.add(new MenuItemButton(right - MenuItemButton.WIDTH, top, item));
                    }
                    buttons.addAll(menu);
                }));
            }
        });
    }

    /**
     * Solo en desarrollo: {@code -Dsam.dev.menu=nombre} abre el inventario, aprieta el botón de cuenta (captura
     * {@code nombre-menu} con el desplegable), elige la última entrada (la de un plugin) y captura {@code nombre}.
     */
    public static void devMenu() {
        var name = System.getProperty("sam.dev.menu");
        if (!net.fabricmc.loader.api.FabricLoader.getInstance().isDevelopmentEnvironment() || name == null) {
            return;
        }
        net.fabricmc.fabric.api.client.networking.v1.ClientPlayConnectionEvents.JOIN.register((handler, sender, client) -> {
            var thread = new Thread(() -> {
                pause(4000);
                client.execute(() -> client.setScreen(new InventoryScreen(client.player)));
                pause(1000);
                client.execute(() -> Screens.getButtons(client.screen).stream().filter(AccountButton.class::isInstance).findFirst()
                    .ifPresent(button -> ((AccountButton) button).onPress()));
                pause(800);
                client.execute(() -> grab(client, name + "-menu"));
                pause(500);
                client.execute(() -> {
                    var items = Screens.getButtons(client.screen).stream().filter(MenuItemButton.class::isInstance).toList();
                    if (!items.isEmpty()) {
                        ((MenuItemButton) items.getLast()).onPress();
                    }
                });
                pause(1500);
                client.execute(() -> grab(client, name));
            }, "SAM dev menu");
            thread.setDaemon(true);
            thread.start();
        });
    }

    /**
     * Solo en desarrollo: {@code -Dsam.dev.account=ver|correo} abre el inventario tras entrar, lo captura,
     * abre "Opciones de cuenta" y la captura; con {@code correo}, antes cambia el correo a
     * {@code sam.dev.email} con {@code sam.dev.password}.
     */
    public static void devHook() {
        var mode = System.getProperty("sam.dev.account");
        if (!net.fabricmc.loader.api.FabricLoader.getInstance().isDevelopmentEnvironment() || mode == null) {
            return;
        }
        net.fabricmc.fabric.api.client.networking.v1.ClientPlayConnectionEvents.JOIN.register((handler, sender, client) -> {
            var thread = new Thread(() -> {
                pause(3000);
                // Si quedó muerto de una corrida anterior, reaparece antes de abrir el inventario
                client.execute(() -> {
                    if (client.player != null && client.player.isDeadOrDying()) {
                        client.player.respawn();
                    }
                });
                pause(2000);
                client.execute(() -> client.setScreen(new InventoryScreen(client.player)));
                pause(1500);
                client.execute(() -> grab(client, "cuenta-inventario"));
                pause(1000);
                client.execute(() -> client.setScreen(new AccountScreen(client.screen)));
                pause(2000);
                if (mode.equals("totp")) {
                    client.execute(() -> {
                        if (client.screen instanceof AccountScreen screen) {
                            screen.devEnableTotp(System.getProperty("sam.dev.password", ""));
                        }
                    });
                    pause(9000);
                }
                if (mode.equals("correo")) {
                    client.execute(() -> {
                        if (client.screen instanceof AccountScreen screen) {
                            screen.devChangeEmail(System.getProperty("sam.dev.email", "nuevo@example.com"),
                                System.getProperty("sam.dev.accountPassword", System.getProperty("sam.dev.password", "")));
                        }
                    });
                    pause(5000);
                }
                client.execute(() -> grab(client, "cuenta-" + mode));
            }, "SAM dev cuenta");
            thread.setDaemon(true);
            thread.start();
        });
    }

    private static void pause(long ms) {
        try {
            Thread.sleep(ms);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    private static void grab(net.minecraft.client.Minecraft client, String name) {
        net.minecraft.client.Screenshot.grab(client.gameDirectory, name + ".png", client.getMainRenderTarget(),
            message -> log.info("[dev] Captura: {}", message.getString()));
    }

    static void send(CustomPacketPayload.Type<SamPayload> type, Consumer<SamWriter> message) {
        var buf = Unpooled.buffer();
        message.accept(new SamWriter(buf));
        ClientPlayNetworking.send(new SamPayload(type, ByteBufUtil.getBytes(buf)));
    }

    private static <T> T decode(SamPayload payload, Function<SamReader, T> reader) {
        try {
            return SamReader.decode(Unpooled.wrappedBuffer(payload.data()), MAX_SERVER_MESSAGE, reader);
        } catch (ProtocolException e) {
            log.error("Mensaje {} mal formado del servidor: {} ({})", payload.type().id(), e.code(), e.getMessage());
            return null;
        }
    }
}
