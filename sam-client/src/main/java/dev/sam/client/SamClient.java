package dev.sam.client;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

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
    }

    /** Igual que en el servidor: comprueba que el núcleo embebido carga. */
    static String coreSmokeCheck() {
        var words = Wordlist.spanish().size();
        var argon2 = Argon2id.hash(new byte[] {1}, new byte[8], new Argon2Params(8, 1, 1), 16).length;
        return words + " palabras de huella, Argon2 " + (argon2 == 16 ? "OK" : "FALLA");
    }
}
