package dev.sam.client.account;

import java.util.List;

import dev.sam.client.auth.DevTotp;
import dev.sam.common.proto.account.AccountInfo;
import dev.sam.common.proto.account.AccountResult;
import dev.sam.common.proto.account.TotpConfirm;
import dev.sam.common.proto.account.TotpEnroll;
import io.nayuki.qrcodegen.QrCode;
import net.minecraft.client.gui.GuiGraphics;
import net.minecraft.client.gui.components.Button;
import net.minecraft.client.gui.components.EditBox;
import net.minecraft.client.gui.screens.Screen;
import net.minecraft.network.chat.Component;

/**
 * Activar el 2FA (RF-AUTH-04): el QR para la app, la clave en texto por si no se puede escanear, los 10
 * códigos de respaldo (solo se muestran aquí) y el primer código, que lo activa. El secreto solo vive en
 * esta pantalla: no se guarda en el cliente.
 */
final class TotpEnrollScreen extends Screen {

    private static final int PANEL_WIDTH = 300;
    private static final int PANEL_HEIGHT = 210;
    private static final int MODULE = 2;
    private static final int WHITE = 0xFFFFFF;
    private static final int GRAY = 0xA0A0A0;
    private static final int YELLOW = 0xFFDD55;
    private static final int RED = 0xFF5555;

    private final AccountScreen parent;
    private final String secret;
    private final List<String> backupCodes;
    private final QrCode qr;
    private EditBox code;
    private Button confirm;
    private boolean busy;
    private String status = "";
    private int statusColor = YELLOW;
    private int left;
    private int panelTop;

    TotpEnrollScreen(AccountScreen parent, TotpEnroll enroll) {
        super(Component.literal("Activar 2FA"));
        this.parent = parent;
        this.secret = DevTotp.secretOf(enroll.uri());
        this.backupCodes = enroll.backupCodes();
        this.qr = QrCode.encodeText(enroll.uri(), QrCode.Ecc.LOW);
    }

    @Override
    protected void init() {
        left = (width - PANEL_WIDTH) / 2;
        panelTop = Math.max(4, (height - PANEL_HEIGHT) / 2);
        var y = panelTop + PANEL_HEIGHT - 50;
        var value = code == null ? "" : code.getValue();
        code = new EditBox(font, left + 12, y, 90, 20, Component.literal("Código"));
        code.setMaxLength(6);
        code.setHint(Component.literal("123456").withStyle(s -> s.withColor(0x707070)));
        code.setValue(value);
        code.setResponder(text -> refresh());
        addRenderableWidget(code);
        confirm = addRenderableWidget(Button.builder(Component.literal("Activar"), b -> confirm())
            .bounds(left + 106, y, 88, 20).build());
        addRenderableWidget(Button.builder(Component.literal("Cancelar"), b -> onClose())
            .bounds(left + 198, y, 90, 20).build());
        setInitialFocus(code);
        refresh();
    }

    private int ticks;

    @Override
    public void tick() {
        super.tick();
        ticks++;
        devConfirm();
    }

    private void refresh() {
        if (confirm != null) {
            confirm.active = !busy && code.getValue().matches("[0-9]{6}");
        }
    }

    private void confirm() {
        busy = true;
        status = "Comprobando el código…";
        statusColor = YELLOW;
        refresh();
        SamClientAccount.send(SamClientAccount.TOTP_CONFIRM, new TotpConfirm(code.getValue())::write);
        code.setValue("");
    }

    void onResult(AccountResult result) {
        busy = false;
        if (result.status() == AccountResult.Status.OK) {
            parent.onTotpEnabled();
            minecraft.setScreen(parent);
            return;
        }
        status = result.detail().orElse("No se pudo activar") + ". Prueba con el código siguiente.";
        statusColor = RED;
        refresh();
    }

    void onInfo(AccountInfo info) {
        parent.onInfo(info);
    }

    @Override
    public void onClose() {
        minecraft.setScreen(parent);
    }

    @Override
    public boolean isPauseScreen() {
        return false;
    }

    /** Solo en desarrollo ({@code sam.dev.account=totp}): confirma con el código y guarda el secreto. */
    private void devConfirm() {
        var file = System.getProperty("sam.dev.totpFile");
        if (!net.fabricmc.loader.api.FabricLoader.getInstance().isDevelopmentEnvironment() || file == null || busy
                || !"totp".equals(System.getProperty("sam.dev.account"))) {
            return;
        }
        // Primero la captura (ya dibujada), después el código
        if (ticks == 20) {
            net.minecraft.client.Screenshot.grab(minecraft.gameDirectory, "cuenta-2fa-qr.png", minecraft.getMainRenderTarget(), m -> { });
        } else if (ticks == 25) {
            DevTotp.save(java.nio.file.Path.of(file), secret);
            code.setValue(DevTotp.codeFor(secret, 0));
            confirm();
        }
    }

    @Override
    public void renderBackground(GuiGraphics graphics, int mouseX, int mouseY, float delta) {
        super.renderBackground(graphics, mouseX, mouseY, delta);
        graphics.fill(left, panelTop, left + PANEL_WIDTH, panelTop + PANEL_HEIGHT, 0xD0101014);
        graphics.renderOutline(left, panelTop, PANEL_WIDTH, PANEL_HEIGHT, 0xFF4A4A55);
    }

    @Override
    public void render(GuiGraphics graphics, int mouseX, int mouseY, float delta) {
        super.render(graphics, mouseX, mouseY, delta);
        graphics.drawCenteredString(font, "Activar 2FA", width / 2, panelTop + 7, WHITE);

        // El QR, con su margen blanco
        var size = qr.size * MODULE;
        var qrX = left + 14;
        var qrY = panelTop + 24;
        // Margen de 4 módulos, como pide el estándar, para que las apps lo lean bien
        graphics.fill(qrX - 4 * MODULE, qrY - 4 * MODULE, qrX + size + 4 * MODULE, qrY + size + 4 * MODULE, 0xFFFFFFFF);
        for (var y = 0; y < qr.size; y++) {
            for (var x = 0; x < qr.size; x++) {
                if (qr.getModule(x, y)) {
                    graphics.fill(qrX + x * MODULE, qrY + y * MODULE, qrX + (x + 1) * MODULE, qrY + (y + 1) * MODULE, 0xFF000000);
                }
            }
        }

        // A la derecha: la clave en texto y los códigos de respaldo
        var textX = qrX + size + 4 * MODULE + 8;
        graphics.drawString(font, "1. Escanéalo con tu app", textX, qrY - 2, WHITE);
        graphics.drawString(font, "o escribe esta clave:", textX, qrY + 9, GRAY);
        var grouped = secret.replaceAll("(.{4})", "$1 ").strip();
        var half = grouped.length() / 2;
        var cut = grouped.indexOf(' ', half);
        graphics.drawString(font, grouped.substring(0, cut), textX, qrY + 20, YELLOW);
        graphics.drawString(font, grouped.substring(cut + 1), textX, qrY + 30, YELLOW);
        graphics.drawString(font, "2. Guarda tus códigos", textX, qrY + 44, WHITE);
        graphics.drawString(font, "de respaldo (solo ahora):", textX, qrY + 54, GRAY);
        for (var i = 0; i < backupCodes.size(); i++) {
            graphics.drawString(font, backupCodes.get(i), textX + (i % 2) * 64, qrY + 66 + (i / 2) * 10, WHITE);
        }
        graphics.drawString(font, "3. Escribe el código que muestra tu app:", left + 12, panelTop + PANEL_HEIGHT - 62, WHITE);
        if (!status.isEmpty()) {
            graphics.drawCenteredString(font, status, width / 2, panelTop + PANEL_HEIGHT - 24, statusColor);
        }
    }
}
