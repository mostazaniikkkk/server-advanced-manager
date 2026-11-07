package dev.sam.common.scripts;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;

import dev.sam.common.proto.ProtocolException;
import dev.sam.common.proto.scripts.ScriptChunk;
import dev.sam.common.proto.scripts.ScriptRef;
import dev.sam.common.proto.scripts.ScriptsConsent;
import dev.sam.common.proto.scripts.ScriptsOffer;
import dev.sam.common.proto.scripts.ScriptsWant;

/**
 * La entrega de scripts de cliente en una conexión (PROTOCOLO.md 5.5): oferta → pedido → fragmentos →
 * consentimiento. Lo fuera de orden o no ofrecido es {@code SAM-P002}; el rechazo lo decide
 * {@code SAM_SCRIPTS_CLIENT_ON_REJECT} (RS-LUA-05).
 */
public final class ServerDelivery {

    public static final String KICK_REJECTED = "Debes aceptar los scripts requeridos. [SAM-K010]";
    private static final int MAX_SCRIPTS = 128;

    /** Qué pasa si el jugador no acepta todos los scripts. */
    public enum OnReject {
        /** Rechazar cualquiera expulsa. */
        KICK,
        /** Entra sin los que rechazó. */
        ALLOW,
        /** Solo expulsa si rechaza uno {@code "required": true}. */
        PER_SCRIPT;

        public static OnReject parse(String value) {
            try {
                return valueOf(value.strip().toUpperCase(Locale.ROOT));
            } catch (IllegalArgumentException e) {
                throw new IllegalArgumentException("SAM_SCRIPTS_CLIENT_ON_REJECT debe ser kick, allow o per_script");
            }
        }
    }

    /** Lo que se ofrece a todas las conexiones hasta el próximo reload: la oferta y cada paquete por su hash en hex. */
    public record Catalog(ScriptsOffer offer, Map<String, byte[]> packages) {

        /** @throws IllegalArgumentException si no caben en una conexión (128 scripts, 16 MiB) */
        public static Catalog of(List<ScriptCatalog.ClientScript> scripts, SignedBlob keylist) {
            if (scripts.size() > MAX_SCRIPTS) {
                throw new IllegalArgumentException("hay más de " + MAX_SCRIPTS + " scripts de cliente");
            }
            var refs = new ArrayList<ScriptRef>();
            var packages = new LinkedHashMap<String, byte[]>();
            var total = 0L;
            for (var script : scripts) {
                var pkg = ScriptPackage.encode(script.files());
                total += pkg.length;
                var manifest = script.manifest();
                var sha = ScriptPackage.sha256(pkg);
                refs.add(new ScriptRef(manifest.id(), manifest.version(), sha, pkg.length, manifest.required(), manifest.capabilities()));
                packages.put(HexFormat.of().formatHex(sha), pkg);
            }
            if (total > ScriptPackage.MAX_TOTAL) {
                throw new IllegalArgumentException("los scripts de cliente suman más de 16 MiB");
            }
            return new Catalog(new ScriptsOffer(keylist, refs), Map.copyOf(packages));
        }
    }

    /** El resultado del consentimiento: expulsar, o los ids aceptados (en el orden de la oferta). */
    public record Reply(Optional<String> kick, List<String> accepted) {
    }

    private enum Step {
        OFFERED, SENT, DONE
    }

    private final Catalog catalog;
    private final OnReject policy;
    private Step step = Step.OFFERED;

    public ServerDelivery(Catalog catalog, OnReject policy) {
        this.catalog = catalog;
        this.policy = policy;
    }

    /** Los fragmentos de los paquetes pedidos, en orden. */
    public List<ScriptChunk> onWant(ScriptsWant want) {
        if (step != Step.OFFERED) {
            throw outOfState("scripts_want repetido");
        }
        var seen = new HashSet<String>();
        var chunks = new ArrayList<ScriptChunk>();
        for (var sha : want.hashes()) {
            var hex = HexFormat.of().formatHex(sha);
            var pkg = catalog.packages().get(hex);
            if (pkg == null || !seen.add(hex)) {
                throw outOfState("pedido de un script no ofrecido");
            }
            var parts = ScriptPackage.chunks(pkg);
            for (var i = 0; i < parts.size(); i++) {
                chunks.add(new ScriptChunk(sha, i, parts.size(), parts.get(i)));
            }
        }
        step = Step.SENT;
        return chunks;
    }

    public Reply onConsent(ScriptsConsent consent) {
        if (step != Step.SENT) {
            throw outOfState("scripts_consent fuera de orden");
        }
        step = Step.DONE;
        var offered = catalog.offer().scripts();
        var ids = offered.stream().map(ScriptRef::id).toList();
        if (!ids.containsAll(consent.accepted())) {
            throw outOfState("consentimiento de un script no ofrecido");
        }
        var accepted = ids.stream().filter(consent.accepted()::contains).toList();
        var rejectedRequired = offered.stream().anyMatch(r -> r.required() && !accepted.contains(r.id()));
        var kick = switch (policy) {
            case KICK -> accepted.size() < offered.size();
            case PER_SCRIPT -> rejectedRequired;
            case ALLOW -> false;
        };
        return kick ? new Reply(Optional.of(KICK_REJECTED), List.of()) : new Reply(Optional.empty(), accepted);
    }

    private static ProtocolException outOfState(String message) {
        return new ProtocolException(ProtocolException.OUT_OF_STATE, message);
    }
}
