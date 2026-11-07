package dev.sam.client.account;

import java.util.Arrays;
import java.util.concurrent.CompletableFuture;
import java.util.function.Consumer;
import java.util.regex.Pattern;

import dev.sam.client.auth.GoogleFlow;
import dev.sam.client.net.SamClientNet;
import dev.sam.common.auth.PasswordDerivation;
import dev.sam.common.proto.account.AccountEmail;
import dev.sam.common.proto.account.AccountInfo;
import dev.sam.common.proto.account.AccountResult;
import dev.sam.common.proto.account.AccountUnlink;
import dev.sam.common.proto.account.OAuthCode;
import dev.sam.common.proto.account.OAuthProvider;
import dev.sam.common.proto.account.OAuthStart;
import net.minecraft.Util;
import net.minecraft.client.gui.GuiGraphics;
import net.minecraft.client.gui.components.Button;
import net.minecraft.client.gui.components.EditBox;
import net.minecraft.client.gui.components.PlayerFaceRenderer;
import net.minecraft.client.gui.screens.Screen;
import net.minecraft.network.chat.Component;
import net.minecraft.network.chat.Style;
import net.minecraft.util.FormattedCharSequence;

/**
 * "Opciones de cuenta" (RF-AUTH-07d): el correo (enmascarado), cambiarlo con la contraseña (RF-AUTH-07b,
 * nunca pide el correo anterior) y vincular o desvincular Google (RF-OAUTH-02). K se deriva fuera del
 * hilo de render y se borra después de enviarla.
 */
final class AccountScreen extends Screen {

    private static final int PANEL_WIDTH = 300;
    private static final int FIELD_WIDTH = 260;
    private static final int AVATAR = 16;
    /** Cabe en la ventana por defecto (854×480 a escala automática: 240 de alto). */
    private static final int PANEL_HEIGHT = 218;
    private static final int WHITE = 0xFFFFFF;
    private static final int GRAY = 0xA0A0A0;
    private static final int DARK_GRAY = 0x707070;
    private static final int GREEN = 0x55FF55;
    private static final int RED = 0xFF5555;
    private static final int YELLOW = 0xFFDD55;
    private static final Pattern EMAIL = Pattern.compile("[^@\\s]+@[^@\\s.]+(\\.[^@\\s.]+)+");

    private final Screen parent;
    private AccountInfo info;
    private EditBox newEmail;
    private EditBox password;
    private Button changeEmail;
    private Button googleButton;
    private Button toggle;
    private boolean visible;
    private boolean busy;
    private String status = "Cargando tu cuenta…";
    private int statusColor = YELLOW;
    private int panelTop;
    private int top;

    AccountScreen(Screen parent) {
        super(Component.literal("Opciones de cuenta"));
        this.parent = parent;
    }

    @Override
    protected void init() {
        panelTop = Math.max(4, (height - PANEL_HEIGHT) / 2);
        top = panelTop + 28;
        var x = (width - FIELD_WIDTH) / 2;
        var emailValue = newEmail == null ? "" : newEmail.getValue();
        var passwordValue = password == null ? "" : password.getValue();

        newEmail = new EditBox(font, x, top + 22, FIELD_WIDTH, 20, Component.literal("Correo nuevo"));
        newEmail.setMaxLength(254);
        newEmail.setHint(Component.literal("tucorreo@ejemplo.com").withStyle(s -> s.withColor(DARK_GRAY)));
        newEmail.setValue(emailValue);
        newEmail.setResponder(text -> refresh());
        addRenderableWidget(newEmail);

        password = new EditBox(font, x, top + 56, FIELD_WIDTH - 50, 20, Component.literal("Tu contraseña"));
        password.setMaxLength(128);
        password.setHint(Component.literal("Tu contraseña actual").withStyle(s -> s.withColor(DARK_GRAY)));
        password.setValue(passwordValue);
        password.setResponder(text -> refresh());
        addRenderableWidget(password);
        toggle = addRenderableWidget(Button.builder(Component.literal(visible ? "Ocultar" : "Ver"), b -> {
            visible = !visible;
            b.setMessage(Component.literal(visible ? "Ocultar" : "Ver"));
            applyMask();
        }).bounds(x + FIELD_WIDTH - 46, top + 56, 46, 20).build());
        applyMask();

        changeEmail = addRenderableWidget(Button.builder(Component.literal("Cambiar correo"), b -> changeEmail())
            .bounds(x, top + 80, FIELD_WIDTH, 20).build());
        googleButton = addRenderableWidget(Button.builder(Component.literal("Google"), b -> google())
            .bounds(x, top + 127, FIELD_WIDTH, 20).build());
        addRenderableWidget(Button.builder(Component.literal("Volver"), b -> onClose())
            .bounds(x, panelTop + PANEL_HEIGHT - 26, FIELD_WIDTH, 20).build());
        if (info == null) {
            SamClientAccount.send(SamClientAccount.REQUEST, w -> { });
        }
        refresh();
    }

    void onInfo(AccountInfo newInfo) {
        info = newInfo;
        if (status.startsWith("Cargando")) {
            status = "";
        }
        refresh();
    }

    void onResult(AccountResult result) {
        busy = false;
        if (result.status() == AccountResult.Status.OK) {
            setStatus("Listo.", GREEN);
            newEmail.setValue("");
        } else {
            setStatus(result.detail().orElse("No se pudo completar"), RED);
        }
        password.setValue("");
        refresh();
    }

    private void refresh() {
        if (changeEmail == null) {
            return;
        }
        var loaded = info != null;
        var hasPassword = !password.getValue().isEmpty();
        changeEmail.active = loaded && !busy && hasPassword && EMAIL.matcher(newEmail.getValue().strip()).matches();
        var google = loaded ? info.google() : AccountInfo.Google.UNAVAILABLE;
        googleButton.visible = google != AccountInfo.Google.UNAVAILABLE;
        googleButton.setMessage(Component.literal(google == AccountInfo.Google.LINKED ? "Desvincular Google" : "Vincular Google"));
        googleButton.active = loaded && !busy && (google == AccountInfo.Google.AVAILABLE || hasPassword);
    }

    private void applyMask() {
        password.setFormatter((text, start) -> FormattedCharSequence.forward(visible ? text : "*".repeat(text.length()), Style.EMPTY));
    }

    private void changeEmail() {
        var mail = newEmail.getValue().strip();
        withKey(k -> SamClientAccount.send(SamClientAccount.EMAIL, new AccountEmail(k, mail)::write), "Cambiando tu correo");
    }

    private void google() {
        if (info.google() == AccountInfo.Google.LINKED) {
            withKey(k -> SamClientAccount.send(SamClientAccount.UNLINK, new AccountUnlink(k, OAuthProvider.GOOGLE)::write),
                "Desvinculando Google");
            return;
        }
        busy = true;
        refresh();
        setStatus("Abriendo el navegador: elige tu cuenta de Google", YELLOW);
        GoogleFlow.begin(new GoogleFlow.Callbacks() {
            @Override
            public void sendStart(OAuthStart start) {
                SamClientAccount.send(SamClientAccount.OAUTH_START, start::write);
            }

            @Override
            public void sendCode(OAuthCode code) {
                setStatus("Verificando tu cuenta de Google", YELLOW);
                SamClientAccount.send(SamClientAccount.OAUTH_CODE, code::write);
            }

            @Override
            public void failed(String reason) {
                busy = false;
                setStatus(reason, RED);
                refresh();
            }
        });
    }

    /** Deriva K de la contraseña escrita (PROTOCOLO.md 6.1) fuera del hilo de render y la envía. */
    private void withKey(Consumer<byte[]> send, String working) {
        var serverId = SamClientNet.lastVerified();
        if (busy || serverId.isEmpty()) {
            return;
        }
        busy = true;
        refresh();
        setStatus(working + "…", YELLOW);
        var chars = password.getValue().toCharArray();
        password.setValue("");
        var nick = minecraft.getUser().getName();
        CompletableFuture.supplyAsync(() -> PasswordDerivation.deriveClientKey(chars, serverId.get(), nick), Util.backgroundExecutor())
            .whenComplete((k, error) -> {
                Arrays.fill(chars, '\0');
                minecraft.execute(() -> {
                    if (error != null) {
                        busy = false;
                        setStatus("No se pudo preparar la contraseña", RED);
                        refresh();
                        return;
                    }
                    try {
                        send.accept(k);
                    } finally {
                        Arrays.fill(k, (byte) 0);
                    }
                });
            });
    }

    /** Solo para el gancho de desarrollo de {@link SamClientAccount#devHook}. */
    void devChangeEmail(String email, String devPassword) {
        newEmail.setValue(email);
        password.setValue(devPassword);
        if (changeEmail.active) {
            changeEmail();
        }
    }

    private void setStatus(String message, int color) {
        status = message;
        statusColor = color;
    }

    @Override
    public void onClose() {
        GoogleFlow.cancel();
        minecraft.setScreen(parent);
    }

    @Override
    public boolean isPauseScreen() {
        return false;
    }

    @Override
    public void renderBackground(GuiGraphics graphics, int mouseX, int mouseY, float delta) {
        super.renderBackground(graphics, mouseX, mouseY, delta);
        var left = (width - PANEL_WIDTH) / 2;
        graphics.fill(left, panelTop, left + PANEL_WIDTH, panelTop + PANEL_HEIGHT, 0xD0101014);
        graphics.renderOutline(left, panelTop, PANEL_WIDTH, PANEL_HEIGHT, 0xFF4A4A55);
    }

    @Override
    public void render(GuiGraphics graphics, int mouseX, int mouseY, float delta) {
        super.render(graphics, mouseX, mouseY, delta);
        var center = width / 2;
        var x = (width - FIELD_WIDTH) / 2;
        var skin = minecraft.getSkinManager().getInsecureSkin(minecraft.getGameProfile());
        var title = "Opciones de cuenta · " + minecraft.getUser().getName();
        var titleLeft = center - (AVATAR + 6 + font.width(title)) / 2;
        PlayerFaceRenderer.draw(graphics, skin, titleLeft, panelTop + 6, AVATAR);
        graphics.drawString(font, title, titleLeft + AVATAR + 6, panelTop + 10, WHITE);

        var email = info == null ? "…" : info.email() + (info.emailVerified() ? "" : "  (sin verificar)");
        graphics.drawString(font, "Correo: " + email, x, top, GRAY);
        graphics.drawString(font, "Correo nuevo", x, top + 12, WHITE);
        graphics.drawString(font, "Tu contraseña (para confirmar)", x, top + 46, WHITE);
        graphics.drawString(font, "No hace falta acceso a tu correo anterior.", x, top + 103, DARK_GRAY);

        var google = info == null ? "…" : switch (info.google()) {
            case LINKED -> "Google: vinculado ✔";
            case AVAILABLE -> "Google: sin vincular";
            case UNAVAILABLE -> "Google: no disponible en este servidor";
        };
        graphics.drawString(font, google, x, top + 116, info != null && info.google() == AccountInfo.Google.LINKED ? GREEN : GRAY);
        if (!status.isEmpty()) {
            graphics.drawCenteredString(font, status, center, top + 152, statusColor);
        }
    }
}
