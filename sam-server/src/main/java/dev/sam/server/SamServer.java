package dev.sam.server;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import dev.sam.common.auth.Argon2Params;
import dev.sam.common.auth.Argon2id;
import dev.sam.common.identity.Wordlist;
import net.fabricmc.api.DedicatedServerModInitializer;
import net.fabricmc.loader.api.FabricLoader;

/** Punto de entrada del mod en el servidor dedicado. */
public final class SamServer implements DedicatedServerModInitializer {

    public static final String MOD_ID = "sam-server";
    public static final Logger LOGGER = LoggerFactory.getLogger("SAM");

    @Override
    public void onInitializeServer() {
        var version = FabricLoader.getInstance().getModContainer(MOD_ID)
            .map(mod -> mod.getMetadata().getVersion().getFriendlyString())
            .orElse("?");
        LOGGER.info("SAM Server {} cargado. Núcleo: {}", version, coreSmokeCheck());
    }

    /**
     * Comprueba que el núcleo embebido (sam-common y BouncyCastle, jar-in-jar) carga: lee un
     * recurso del jar anidado y ejecuta un Argon2 mínimo.
     */
    static String coreSmokeCheck() {
        var words = Wordlist.spanish().size();
        var argon2 = Argon2id.hash(new byte[] {1}, new byte[8], new Argon2Params(8, 1, 1), 16).length;
        return words + " palabras de huella, Argon2 " + (argon2 == 16 ? "OK" : "FALLA");
    }
}
