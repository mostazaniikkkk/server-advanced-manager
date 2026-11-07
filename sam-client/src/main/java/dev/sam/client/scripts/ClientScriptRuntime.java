package dev.sam.client.scripts;

import java.time.Duration;

import org.slf4j.Logger;

import dev.sam.common.lua.ScriptHost;
import dev.sam.common.lua.ScriptLimits;
import net.fabricmc.fabric.api.client.event.lifecycle.v1.ClientTickEvents;
import net.fabricmc.fabric.api.client.networking.v1.ClientPlayConnectionEvents;
import net.fabricmc.fabric.api.client.rendering.v1.HudRenderCallback;
import net.minecraft.client.Minecraft;
import net.minecraft.client.gui.GuiGraphics;

/**
 * Los scripts aceptados corren en el juego (API de cliente v0, PROTOCOLO.md 8.3): se cargan al entrar al
 * mundo, avanzan con el tick del cliente y se descargan al salir (RF-LUA-09b). El HUD dibuja lo último
 * que dejaron los scripts, sin ejecutar Lua en el render, y nunca con una pantalla abierta (RS-LUA-07).
 */
final class ClientScriptRuntime {

    /** Un frame dura ~16 ms: una llamada no puede llevarse más que eso (RS-LUA-03). */
    private static final ScriptLimits LIMITS = new ScriptLimits(Duration.ofMillis(10), 32L * 1024 * 1024, 64 * 1024);

    private final Logger log;
    private final ScriptHost host;
    private boolean running;

    ClientScriptRuntime(Logger log) {
        this.log = log;
        this.host = ScriptHost.client((script, text) -> log.info("[script {}] {}", script, text), LIMITS);
    }

    void install() {
        ClientPlayConnectionEvents.JOIN.register((handler, sender, client) -> client.execute(this::start));
        ClientPlayConnectionEvents.DISCONNECT.register((handler, client) -> client.execute(this::stop));
        ClientTickEvents.END_CLIENT_TICK.register(client -> {
            if (running) {
                host.tick();
            }
        });
        HudRenderCallback.EVENT.register((graphics, delta) -> render(graphics));
    }

    private void start() {
        var accepted = SamClientScripts.accepted();
        host.load(accepted.stream().map(r -> r.script()).toList());
        running = !accepted.isEmpty();
        for (var status : host.status()) {
            log.info("Script {} del servidor: {}", status.id(), status.state());
            status.errors().forEach(error -> log.warn("Script {}: {}", status.id(), error));
        }
    }

    private void stop() {
        running = false;
        host.load(java.util.List.of());
    }

    private void render(GuiGraphics graphics) {
        var minecraft = Minecraft.getInstance();
        if (!running || minecraft.screen != null || minecraft.options.hideGui) {
            return;
        }
        var font = minecraft.font;
        var width = graphics.guiWidth();
        var height = graphics.guiHeight();
        for (var text : host.hud()) {
            var textWidth = font.width(text.text());
            var x = switch (text.anchor()) {
                case TOP_LEFT, LEFT, BOTTOM_LEFT -> 2;
                case TOP, CENTER, BOTTOM -> (width - textWidth) / 2;
                case TOP_RIGHT, RIGHT, BOTTOM_RIGHT -> width - textWidth - 2;
            };
            var y = switch (text.anchor()) {
                case TOP_LEFT, TOP, TOP_RIGHT -> 2;
                case LEFT, CENTER, RIGHT -> (height - font.lineHeight) / 2;
                case BOTTOM_LEFT, BOTTOM, BOTTOM_RIGHT -> height - font.lineHeight - 2;
            };
            graphics.drawString(font, text.text(), x + text.x(), y + text.y(), 0xFF000000 | text.color());
        }
    }
}
