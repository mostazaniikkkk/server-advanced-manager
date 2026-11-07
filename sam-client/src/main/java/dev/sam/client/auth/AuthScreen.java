package dev.sam.client.auth;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.regex.Pattern;

import org.lwjgl.glfw.GLFW;

import dev.sam.client.SamClient;
import dev.sam.client.net.SamClientNet;
import dev.sam.common.auth.PasswordDerivation;
import dev.sam.common.proto.account.OAuthCode;
import dev.sam.common.proto.account.OAuthStart;
import dev.sam.common.proto.auth.AccountState;
import dev.sam.common.proto.auth.AuthMethod;
import dev.sam.common.proto.auth.AuthResult;
import dev.sam.common.proto.auth.Hello;
import dev.sam.common.proto.auth.LoginPassword;
import dev.sam.common.proto.auth.Register;
import net.fabricmc.fabric.api.networking.v1.PacketSender;
import net.fabricmc.loader.api.FabricLoader;
import net.minecraft.Util;
import net.minecraft.client.Screenshot;
import net.minecraft.client.gui.GuiGraphics;
import net.minecraft.client.gui.components.Button;
import net.minecraft.client.gui.components.EditBox;
import net.minecraft.client.gui.components.PlayerFaceRenderer;
import net.minecraft.client.gui.screens.Screen;
import net.minecraft.network.Connection;
import net.minecraft.network.chat.Component;
import net.minecraft.network.chat.Style;
import net.minecraft.util.FormattedCharSequence;

/**
 * La AuthScreen del MVP (RF-AUTH-01, PROTOCOLO.md 5.3 y 6.1): registro (contraseña, confirmación y
 * correo) o login con contraseña. La pantalla explica qué pasa, valida en vivo y solo deja enviar
 * lo que el servidor va a aceptar. K se deriva fuera del hilo de render, se envía y se borra.
 */
public final class AuthScreen extends Screen {

    private static final int PANEL_WIDTH = 280;
    private static final int FIELD_WIDTH = 240;
    private static final int TOGGLE_WIDTH = 46;
    private static final int MAX_PASSWORD = 128;
    private static final int LABEL_GAP = 11;
    private static final int ROW = 33;
    private static final int AVATAR = 24;
    private static final int HEADER = 46 + AVATAR + 4;

    private static final int WHITE = 0xFFFFFF;
    private static final int GRAY = 0xA0A0A0;
    private static final int DARK_GRAY = 0x707070;
    private static final int GREEN = 0x55FF55;
    private static final int RED = 0xFF5555;
    private static final int YELLOW = 0xFFDD55;

    private static final Pattern EMAIL = Pattern.compile("[^@\\s]+@[^@\\s.]+(\\.[^@\\s.]+)+");

    private enum Tone { INFO, BUSY, ERROR, OK }

    private final Hello hello;
    private final String nick;
    private final PacketSender sender;
    private final Connection connection;
    private final boolean registering;
    private EditBox password;
    private EditBox confirm;
    private EditBox email;
    private Button submit;
    private Button toggle;
    private Button google;
    private boolean visible;
    private boolean busy;
    private Component status = Component.empty();
    private Tone tone = Tone.INFO;
    private int panelTop;
    private int panelHeight;
    private int fieldsTop;
    private int ticks;
    /** Bloq Mayús según la última tecla (GLFW solo lo informa con GLFW_LOCK_KEY_MODS activo). */
    private boolean capsLock;
    private int previousLockKeyMods = -1;

    /**
     * @param sender para responder y desconectarse desde la pantalla
     * @param connection la conexión en configuration: en vanilla la atiende la ConnectScreen, que esta
     *     pantalla reemplaza; sin atenderla, una desconexión (Salir, expulsión) no llega nunca al jugador
     */
    public AuthScreen(Hello hello, String nick, PacketSender sender, Connection connection) {
        super(Component.literal(hello.accountState() == AccountState.NEW ? "Crear cuenta" : "Iniciar sesión"));
        this.hello = hello;
        this.nick = nick;
        this.sender = sender;
        this.connection = connection;
        this.registering = hello.accountState() == AccountState.NEW;
    }

    @Override
    protected void init() {
        // Alto del panel: cabecera, campos (con su validación en la misma línea de la etiqueta),
        // botones, estado y pie. Cabe en la ventana por defecto (854×480 a escala automática).
        var rows = registering ? 3 : 1;
        panelHeight = HEADER + rows * ROW + 2 + 20 + 30 + (googleOffered() ? 24 : 0);
        panelTop = Math.max(4, (height - panelHeight) / 2);
        fieldsTop = panelTop + HEADER;
        var x = (width - FIELD_WIDTH) / 2;

        var y = fieldsTop + LABEL_GAP;
        password = masked(x, y, FIELD_WIDTH - TOGGLE_WIDTH - 4, "Tu contraseña");
        toggle = addRenderableWidget(Button.builder(Component.literal("Ver"), b -> toggleVisible())
            .bounds(x + FIELD_WIDTH - TOGGLE_WIDTH, y, TOGGLE_WIDTH, 20).build());
        if (registering) {
            confirm = masked(x, y + ROW, FIELD_WIDTH, "Escríbela otra vez");
            email = new EditBox(font, x, y + 2 * ROW, FIELD_WIDTH, 20, Component.literal("Correo"));
            email.setMaxLength(254);
            email.setHint(Component.literal("tucorreo@ejemplo.com").withStyle(s -> s.withColor(DARK_GRAY)));
            email.setResponder(text -> refresh());
            addRenderableWidget(email);
        }
        var buttonsY = fieldsTop + rows * ROW + 2;
        submit = addRenderableWidget(Button.builder(Component.literal(registering ? "Crear cuenta y entrar" : "Entrar"),
            b -> submit()).bounds(x, buttonsY, FIELD_WIDTH * 2 / 3 - 2, 20).build());
        addRenderableWidget(Button.builder(Component.literal("Salir"), b -> leave())
            .bounds(x + FIELD_WIDTH * 2 / 3 + 2, buttonsY, FIELD_WIDTH / 3 - 2, 20).build());
        if (googleOffered()) {
            google = addRenderableWidget(Button.builder(Component.literal("Entrar con Google"), b -> signInWithGoogle())
                .bounds(x, buttonsY + 24, FIELD_WIDTH, 20).build());
        }
        setInitialFocus(password);
        var window = minecraft.getWindow().getWindow();
        if (previousLockKeyMods < 0) {
            previousLockKeyMods = GLFW.glfwGetInputMode(window, GLFW.GLFW_LOCK_KEY_MODS);
            GLFW.glfwSetInputMode(window, GLFW.GLFW_LOCK_KEY_MODS, GLFW.GLFW_TRUE);
        }
        applyMask();
        refresh();
        devAutofill();
    }

    private EditBox masked(int x, int y, int width, String hint) {
        var box = new EditBox(font, x, y, width, 20, Component.literal(hint));
        box.setMaxLength(MAX_PASSWORD);
        box.setHint(Component.literal(hint).withStyle(s -> s.withColor(DARK_GRAY)));
        box.setResponder(text -> refresh());
        return addRenderableWidget(box);
    }

    private void toggleVisible() {
        visible = !visible;
        toggle.setMessage(Component.literal(visible ? "Ocultar" : "Ver"));
        applyMask();
    }

    private void applyMask() {
        for (var box : passwordBoxes()) {
            if (visible) {
                box.setFormatter((text, start) -> FormattedCharSequence.forward(text, Style.EMPTY));
            } else {
                box.setFormatter((text, start) -> FormattedCharSequence.forward("*".repeat(text.length()), Style.EMPTY));
            }
        }
    }

    private List<EditBox> passwordBoxes() {
        var boxes = new ArrayList<EditBox>();
        boxes.add(password);
        if (confirm != null) {
            boxes.add(confirm);
        }
        return boxes;
    }

    // ===== Validación en vivo =====

    private boolean longEnough() {
        return password.getValue().length() >= hello.policy().minPassword();
    }

    private boolean matches() {
        return !confirm.getValue().isEmpty() && confirm.getValue().equals(password.getValue());
    }

    private boolean validEmail() {
        return EMAIL.matcher(email.getValue().strip()).matches();
    }

    private boolean ready() {
        if (registering) {
            return longEnough() && matches() && validEmail();
        }
        return !password.getValue().isEmpty();
    }

    private void refresh() {
        if (submit != null) {
            submit.active = !busy && ready();
        }
        if (google != null) {
            google.active = !busy;
        }
    }

    // ===== Entrar con Google (REQUERIMIENTOS 5.5) =====

    /** Solo a quien ya tiene cuenta: no hay registro con Google (RF-OAUTH-01). */
    private boolean googleOffered() {
        return !registering && hello.policy().methods().contains(AuthMethod.GOOGLE);
    }

    private void signInWithGoogle() {
        if (busy) {
            return;
        }
        busy = true;
        refresh();
        setStatus("Abriendo el navegador: elige tu cuenta de Google", Tone.BUSY);
        GoogleFlow.begin(new GoogleFlow.Callbacks() {
            @Override
            public void sendStart(OAuthStart start) {
                SamClientAuth.send(SamClientAuth.OAUTH_START, start::write);
            }

            @Override
            public void sendCode(OAuthCode code) {
                setStatus("Verificando tu cuenta de Google", Tone.BUSY);
                SamClientAuth.send(SamClientAuth.OAUTH_CODE, code::write);
            }

            @Override
            public void failed(String reason) {
                fail(reason);
            }
        });
    }

    // ===== Envío =====

    private void submit() {
        if (busy || !ready()) {
            return;
        }
        busy = true;
        refresh();
        setStatus(registering ? "Creando tu cuenta…" : "Comprobando tu contraseña…", Tone.BUSY);
        var chars = password.getValue().toCharArray();
        var mail = registering ? email.getValue().strip() : "";
        for (var box : passwordBoxes()) {
            box.setValue("");
        }
        var serverId = hello.serverId();
        // Argon2 del cliente (64 MiB) fuera del hilo de render (PROTOCOLO.md 6.1)
        CompletableFuture.supplyAsync(() -> PasswordDerivation.deriveClientKey(chars, serverId, nick), Util.backgroundExecutor())
            .whenComplete((k, error) -> {
                Arrays.fill(chars, '\0');
                minecraft.execute(() -> {
                    if (error != null) {
                        fail("No se pudo preparar la contraseña: " + error.getMessage());
                        return;
                    }
                    try {
                        if (registering) {
                            SamClientAuth.send(SamClientAuth.REGISTER, new Register(k, mail)::write);
                        } else {
                            SamClientAuth.send(SamClientAuth.LOGIN_PASSWORD, new LoginPassword(k, Optional.empty())::write);
                        }
                    } finally {
                        Arrays.fill(k, (byte) 0);
                    }
                });
            });
    }

    void onResult(AuthResult result) {
        if (result.status() == AuthResult.Status.OK) {
            setStatus(registering ? "¡Cuenta creada! Entrando al mundo…" : "¡Listo! Entrando al mundo…", Tone.OK);
            return;
        }
        fail(result.detail().orElse("No se pudo iniciar sesión") + ". Inténtalo de nuevo.");
    }

    private void fail(String message) {
        busy = false;
        setStatus(message, Tone.ERROR);
        refresh();
        setFocused(password);
    }

    private void setStatus(String message, Tone newTone) {
        status = Component.literal(message);
        tone = newTone;
    }

    private void leave() {
        sender.disconnect(Component.literal("Saliste antes de iniciar sesión"));
    }

    @Override
    public void removed() {
        GoogleFlow.cancel();
        if (previousLockKeyMods >= 0) {
            GLFW.glfwSetInputMode(minecraft.getWindow().getWindow(), GLFW.GLFW_LOCK_KEY_MODS, previousLockKeyMods);
        }
        super.removed();
    }

    private void trackCapsLock(int modifiers) {
        capsLock = (modifiers & GLFW.GLFW_MOD_CAPS_LOCK) != 0;
    }

    @Override
    public boolean charTyped(char character, int modifiers) {
        trackCapsLock(modifiers);
        return super.charTyped(character, modifiers);
    }

    @Override
    public boolean keyReleased(int key, int scanCode, int modifiers) {
        trackCapsLock(modifiers);
        return super.keyReleased(key, scanCode, modifiers);
    }

    @Override
    public boolean keyPressed(int key, int scanCode, int modifiers) {
        trackCapsLock(modifiers);
        if ((key == GLFW.GLFW_KEY_ENTER || key == GLFW.GLFW_KEY_KP_ENTER) && submit.active) {
            submit();
            return true;
        }
        return super.keyPressed(key, scanCode, modifiers);
    }

    @Override
    public boolean shouldCloseOnEsc() {
        return false;
    }

    // ===== Dibujo =====

    @Override
    public void renderBackground(GuiGraphics graphics, int mouseX, int mouseY, float delta) {
        super.renderBackground(graphics, mouseX, mouseY, delta);
        var left = (width - PANEL_WIDTH) / 2;
        graphics.fill(left, panelTop, left + PANEL_WIDTH, panelTop + panelHeight, 0xD0101014);
        graphics.fill(left, panelTop, left + PANEL_WIDTH, panelTop + 1, 0xFF4A4A55);
        graphics.fill(left, panelTop + panelHeight - 1, left + PANEL_WIDTH, panelTop + panelHeight, 0xFF4A4A55);
        graphics.fill(left, panelTop, left + 1, panelTop + panelHeight, 0xFF4A4A55);
        graphics.fill(left + PANEL_WIDTH - 1, panelTop, left + PANEL_WIDTH, panelTop + panelHeight, 0xFF4A4A55);
    }

    @Override
    public void render(GuiGraphics graphics, int mouseX, int mouseY, float delta) {
        super.render(graphics, mouseX, mouseY, delta);
        var center = width / 2;
        var x = (width - FIELD_WIDTH) / 2;

        // Cabecera: quién eres, dónde estás y qué hacer
        var skin = minecraft.getSkinManager().getInsecureSkin(minecraft.getGameProfile());
        var avatarTop = panelTop + 8;
        graphics.fill(center - AVATAR / 2 - 1, avatarTop - 1, center + AVATAR / 2 + 1, avatarTop + AVATAR + 1, 0xFF4A4A55);
        PlayerFaceRenderer.draw(graphics, skin, center - AVATAR / 2, avatarTop, AVATAR);
        var headerTop = panelTop + AVATAR + 4;
        graphics.drawCenteredString(font, Component.literal(hello.serverName().isBlank() ? "Servidor" : hello.serverName()),
            center, headerTop + 8, WHITE);
        var greeting = registering
            ? "Es tu primera vez aquí, " + nick + ". Crea tu cuenta."
            : "Hola de nuevo, " + nick + ". Escribe tu contraseña.";
        graphics.drawCenteredString(font, Component.literal(greeting), center, headerTop + 20, GRAY);
        var help = registering ? "La usarás cada vez que entres aquí." : "Es la que creaste al registrarte aquí.";
        graphics.drawCenteredString(font, Component.literal(help), center, headerTop + 31, DARK_GRAY);

        // Etiquetas de los campos y, a la derecha, su validación en vivo
        var right = x + FIELD_WIDTH;
        graphics.drawString(font, "Contraseña", x, fieldsTop, WHITE);
        if (capsLock || Boolean.getBoolean("sam.dev.capsLock") && isDev()) {
            // Va en la línea de la etiqueta, a la derecha: en el registro, en lugar del contador
            var warning = "⚠ Bloq Mayús activado";
            graphics.drawString(font, warning, right - font.width(warning), fieldsTop, YELLOW);
        } else if (registering) {
            var min = hello.policy().minPassword();
            var length = password.getValue().length();
            check(graphics, right, fieldsTop, length == 0, longEnough(),
                longEnough() ? "✔ " + length + " caracteres" : "mínimo " + min + " (" + length + ")");
        }
        if (registering) {
            graphics.drawString(font, "Repite la contraseña", x, fieldsTop + ROW, WHITE);
            check(graphics, right, fieldsTop + ROW, confirm.getValue().isEmpty(), matches(),
                matches() ? "✔ coinciden" : "✖ no coinciden");
            graphics.drawString(font, "Correo de recuperación", x, fieldsTop + 2 * ROW, WHITE);
            check(graphics, right, fieldsTop + 2 * ROW, email.getValue().isBlank(), validEmail(),
                validEmail() ? "✔" : "✖ incompleto");
        }

        // Estado
        if (!status.getString().isEmpty()) {
            var dots = tone == Tone.BUSY ? ".".repeat(ticks / 6 % 4) : "";
            graphics.drawCenteredString(font, Component.literal(status.getString() + dots), center,
                panelTop + panelHeight - 25, color(tone));
        }

        // Pie: la identidad verificada del servidor (PROTOCOLO.md 3.5)
        SamClientNet.lastFingerprint().ifPresent(fingerprint -> graphics.drawCenteredString(font,
            Component.literal("Servidor verificado · " + fingerprint), center, panelTop + panelHeight - 12,
            DARK_GRAY));
    }

    /** Texto alineado a la derecha: gris mientras el campo está vacío, verde o rojo después. */
    private void check(GuiGraphics graphics, int right, int y, boolean pending, boolean ok, String text) {
        graphics.drawString(font, text, right - font.width(text), y, pending ? DARK_GRAY : ok ? GREEN : RED);
    }

    private static int color(Tone tone) {
        return switch (tone) {
            case INFO, BUSY -> YELLOW;
            case ERROR -> RED;
            case OK -> GREEN;
        };
    }

    // ===== Solo en el entorno de desarrollo de Loom (nunca en el jar publicado) =====

    /**
     * {@code -Dsam.dev.password} rellena la pantalla y la envía (o solo la rellena con
     * {@code sam.dev.fillOnly}); {@code sam.dev.confirm} y {@code sam.dev.email} cambian esos campos.
     */
    private void devAutofill() {
        var devPassword = System.getProperty("sam.dev.password");
        if (!isDev() || devPassword == null || busy) {
            return;
        }
        password.setValue(devPassword);
        if (registering) {
            confirm.setValue(System.getProperty("sam.dev.confirm", devPassword));
            email.setValue(System.getProperty("sam.dev.email", "dev@example.com"));
        }
        if (!Boolean.getBoolean("sam.dev.fillOnly")) {
            submit();
        }
    }

    /**
     * {@code -Dsam.dev.screenshot=nombre} guarda una captura de esta pantalla a los
     * {@code sam.dev.screenshotDelay} ticks (30 por defecto) y cierra el juego.
     */
    @Override
    public void tick() {
        super.tick();
        // Lo mismo que hace la ConnectScreen con la conexión mientras está abierta
        if (connection.isConnected()) {
            connection.tick();
        } else {
            connection.handleDisconnection();
        }
        ticks++;
        // {@code -Dsam.dev.leave=true}: pulsa Salir a los 20 ticks (prueba de punta a punta)
        if (isDev() && Boolean.getBoolean("sam.dev.leave") && ticks == 20) {
            leave();
            return;
        }
        // {@code -Dsam.dev.repeat=true}: si el intento falló, lo reenvía cada 20 ticks (prueba del tope de intentos)
        if (isDev() && Boolean.getBoolean("sam.dev.repeat") && !busy && ticks % 20 == 0) {
            devAutofill();
        }
        var name = System.getProperty("sam.dev.screenshot");
        if (isDev() && name != null && ticks == Integer.getInteger("sam.dev.screenshotDelay", 30)) {
            Screenshot.grab(minecraft.gameDirectory, name + ".png", minecraft.getMainRenderTarget(),
                message -> SamClient.LOGGER.info("[dev] Captura: {}", message.getString()));
            minecraft.execute(minecraft::stop);
        }
    }

    private static boolean isDev() {
        return FabricLoader.getInstance().isDevelopmentEnvironment();
    }
}
