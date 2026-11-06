package dev.sam.client.auth;

import java.util.Arrays;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;

import dev.sam.common.auth.PasswordDerivation;
import dev.sam.client.net.SamClientNet;
import dev.sam.common.proto.auth.AccountState;
import dev.sam.common.proto.auth.AuthResult;
import dev.sam.common.proto.auth.Hello;
import dev.sam.common.proto.auth.LoginPassword;
import dev.sam.common.proto.auth.Register;
import net.fabricmc.fabric.api.networking.v1.PacketSender;
import net.minecraft.Util;
import net.minecraft.client.gui.GuiGraphics;
import net.minecraft.client.gui.components.Button;
import net.minecraft.client.gui.components.EditBox;
import net.minecraft.client.gui.screens.Screen;
import net.minecraft.network.chat.Component;
import net.minecraft.network.chat.Style;
import net.minecraft.util.FormattedCharSequence;

/**
 * La AuthScreen del MVP (RF-AUTH-01, PROTOCOLO.md 5.3 y 6.1): registro (contraseña, confirmación y
 * correo) o login con contraseña. K se deriva fuera del hilo de render, se envía y se borra.
 */
public final class AuthScreen extends Screen {

    private static final int WIDTH = 220;
    private static final int MAX_PASSWORD = 128;

    private final Hello hello;
    private final String nick;
    private final PacketSender sender;
    private final boolean registering;
    private EditBox password;
    private EditBox confirm;
    private EditBox email;
    private Button submit;
    private Component status = Component.empty();
    private boolean busy;

    /** @param sender la conexión en configuration: para desconectarse desde la pantalla */
    public AuthScreen(Hello hello, String nick, PacketSender sender) {
        super(Component.literal(hello.accountState() == AccountState.NEW ? "Crear cuenta" : "Iniciar sesión"));
        this.hello = hello;
        this.nick = nick;
        this.sender = sender;
        this.registering = hello.accountState() == AccountState.NEW;
    }

    @Override
    protected void init() {
        var x = (width - WIDTH) / 2;
        var y = height / 2 - (registering ? 60 : 30);
        password = masked(x, y, "Contraseña");
        if (registering) {
            confirm = masked(x, y + 30, "Repite la contraseña");
            email = new EditBox(font, x, y + 60, WIDTH, 20, Component.literal("Correo"));
            email.setMaxLength(254);
            email.setHint(Component.literal("Correo electrónico"));
            addRenderableWidget(email);
        }
        var buttonsY = y + (registering ? 95 : 35);
        submit = addRenderableWidget(Button.builder(Component.literal(registering ? "Registrarme" : "Entrar"), b -> submit())
            .bounds(x, buttonsY, WIDTH / 2 - 2, 20).build());
        addRenderableWidget(Button.builder(Component.literal("Desconectar"), b -> disconnect())
            .bounds(x + WIDTH / 2 + 2, buttonsY, WIDTH / 2 - 2, 20).build());
        setInitialFocus(password);
        submit.active = !busy;
        devAutofill();
    }

    /**
     * Solo en el entorno de desarrollo de Loom (nunca en el jar publicado): {@code -Dsam.dev.password}
     * rellena y envía la pantalla, para la prueba de punta a punta automática.
     */
    private void devAutofill() {
        var devPassword = System.getProperty("sam.dev.password");
        if (!net.fabricmc.loader.api.FabricLoader.getInstance().isDevelopmentEnvironment() || devPassword == null || busy) {
            return;
        }
        password.setValue(devPassword);
        if (registering) {
            confirm.setValue(devPassword);
            email.setValue(System.getProperty("sam.dev.email", "dev@example.com"));
        }
        submit();
    }

    private EditBox masked(int x, int y, String hint) {
        var box = new EditBox(font, x, y, WIDTH, 20, Component.literal(hint));
        box.setMaxLength(MAX_PASSWORD);
        box.setHint(Component.literal(hint));
        box.setFormatter((text, start) -> FormattedCharSequence.forward("•".repeat(text.length()), Style.EMPTY));
        return addRenderableWidget(box);
    }

    private void submit() {
        if (busy) {
            return;
        }
        var text = password.getValue();
        if (text.length() < hello.policy().minPassword()) {
            status = Component.literal("La contraseña debe tener al menos " + hello.policy().minPassword() + " caracteres");
            return;
        }
        if (registering && !text.equals(confirm.getValue())) {
            status = Component.literal("Las contraseñas no coinciden");
            return;
        }
        var mail = registering ? email.getValue().strip() : "";
        if (registering && !mail.contains("@")) {
            status = Component.literal("Escribe un correo válido");
            return;
        }
        busy = true;
        submit.active = false;
        status = Component.literal("Verificando…");
        var chars = text.toCharArray();
        password.setValue("");
        if (confirm != null) {
            confirm.setValue("");
        }
        var serverId = hello.serverId();
        // Argon2 del cliente (64 MiB) fuera del hilo de render (PROTOCOLO.md 6.1)
        CompletableFuture.supplyAsync(() -> PasswordDerivation.deriveClientKey(chars, serverId, nick), Util.backgroundExecutor())
            .whenComplete((k, error) -> {
                Arrays.fill(chars, '\0');
                minecraft.execute(() -> {
                    if (error != null) {
                        fail("No se pudo derivar la clave: " + error.getMessage());
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
            status = Component.literal("Listo. Entrando…");
            return;
        }
        fail(result.detail().orElse("No se pudo iniciar sesión"));
    }

    private void fail(String message) {
        busy = false;
        submit.active = true;
        status = Component.literal(message);
    }

    private void disconnect() {
        sender.disconnect(Component.literal("Saliste del login"));
    }

    @Override
    public void render(GuiGraphics graphics, int mouseX, int mouseY, float delta) {
        super.render(graphics, mouseX, mouseY, delta);
        var x = width / 2;
        var top = height / 2 - (registering ? 110 : 80);
        graphics.drawCenteredString(font, title, x, top, 0xFFFFFF);
        graphics.drawCenteredString(font, Component.literal(hello.serverName() + " · " + nick), x, top + 14, 0xAAAAAA);
        SamClientNet.lastFingerprint().ifPresent(fingerprint ->
            graphics.drawCenteredString(font, Component.literal("Huella: " + fingerprint), x, top + 28, 0x777777));
        graphics.drawCenteredString(font, status, x, height / 2 + (registering ? 75 : 65), 0xFFDD55);
    }

    @Override
    public boolean shouldCloseOnEsc() {
        return false;
    }

}
