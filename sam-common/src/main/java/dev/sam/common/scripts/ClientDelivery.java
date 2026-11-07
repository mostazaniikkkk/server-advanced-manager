package dev.sam.common.scripts;

import java.util.HashSet;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

import dev.sam.common.identity.ServerPublicKey;
import dev.sam.common.lua.ScriptHost;
import dev.sam.common.proto.ProtocolException;
import dev.sam.common.proto.scripts.ScriptChunk;
import dev.sam.common.proto.scripts.ScriptRef;
import dev.sam.common.proto.scripts.ScriptsOffer;
import dev.sam.common.proto.scripts.ScriptsWant;

/**
 * Lo que el cliente hace con {@code sam:scripts_offer} (PROTOCOLO.md 5.5, RF-LUA-05): verifica la keylist
 * con la identidad fijada, toma de la caché lo que todavía verifica, pide el resto y verifica cada paquete
 * al llegar (RS-SIG-05). Lo que deja de verificar se borra de la caché (RN-31, RS-SIG-06).
 */
public final class ClientDelivery {

    /** Un script listo para el consentimiento: verificado, con la etiqueta de la clave que lo firmó. */
    public record Ready(ScriptHost.Package script, String signer) {
    }

    /** El veredicto sobre un paquete: listo, o el motivo del rechazo. */
    private record Verdict(Ready ready, String reason) {
        static Verdict fail(String reason) {
            return new Verdict(null, reason);
        }
    }

    private final List<KeyList.Entry> keys;
    private final ScriptCache cache;
    private final List<ScriptRef> offered;
    private final Map<String, ScriptRef> wanted = new LinkedHashMap<>();
    private final Map<String, Verdict> verdicts = new LinkedHashMap<>();
    private final ScriptPackage.Assembler assembler;

    private ClientDelivery(List<KeyList.Entry> keys, ScriptCache cache, List<ScriptRef> offered) {
        this.keys = keys;
        this.cache = cache;
        this.offered = offered;
        var sizes = new LinkedHashMap<String, Integer>();
        for (var ref : offered) {
            var hex = HexFormat.of().formatHex(ref.sha256());
            var cached = cache.read(hex).map(pkg -> check(ref, pkg)).filter(v -> v.ready() != null);
            if (cached.isPresent()) {
                verdicts.put(ref.id(), cached.get());
            } else {
                cache.delete(hex);
                wanted.put(hex, ref);
                sizes.put(hex, ref.size());
            }
        }
        try {
            this.assembler = new ScriptPackage.Assembler(sizes);
        } catch (IllegalArgumentException e) {
            throw new ProtocolException(ProtocolException.MALFORMED, e.getMessage());
        }
    }

    /** @throws ProtocolException si la keylist no la firmó el servidor fijado o la oferta repite scripts */
    public static ClientDelivery open(ScriptsOffer offer, ServerPublicKey pinned, ScriptCache cache) {
        var keys = KeyList.verify(offer.keylist(), pinned)
            .orElseThrow(() -> new ProtocolException(ProtocolException.MALFORMED, "la lista de claves no la firmó este servidor"));
        var ids = new HashSet<String>();
        var hashes = new HashSet<String>();
        for (var ref : offer.scripts()) {
            if (!ids.add(ref.id()) || !hashes.add(HexFormat.of().formatHex(ref.sha256()))) {
                throw new ProtocolException(ProtocolException.MALFORMED, "oferta con scripts repetidos");
            }
        }
        return new ClientDelivery(keys, cache, offer.scripts());
    }

    /** Los paquetes que hay que descargar. */
    public ScriptsWant want() {
        return new ScriptsWant(wanted.keySet().stream().map(HexFormat.of()::parseHex).toList());
    }

    /** @throws ProtocolException si el fragmento no corresponde (SAM-P002) */
    public void chunk(ScriptChunk chunk) {
        assembler.accept(chunk.sha256(), chunk.index(), chunk.total(), chunk.data()).ifPresent(pkg -> {
            var ref = wanted.get(HexFormat.of().formatHex(chunk.sha256()));
            var verdict = check(ref, pkg);
            if (verdict.ready() != null) {
                cache.write(pkg);
            }
            verdicts.put(ref.id(), verdict);
        });
    }

    /** Llegaron todos los paquetes pedidos. */
    public boolean complete() {
        return assembler.done();
    }

    /** Los scripts verificados, en el orden de la oferta. */
    public List<Ready> ready() {
        return offered.stream().map(ref -> verdicts.get(ref.id())).filter(Objects::nonNull).map(Verdict::ready)
            .filter(Objects::nonNull).toList();
    }

    /** Los que llegaron y no verificaron, con el motivo, en el orden de la oferta. */
    public List<ScriptCatalog.Rejected> failed() {
        return offered.stream().filter(ref -> verdicts.containsKey(ref.id()) && verdicts.get(ref.id()).ready() == null)
            .map(ref -> new ScriptCatalog.Rejected(ref.id(), verdicts.get(ref.id()).reason())).toList();
    }

    private Verdict check(ScriptRef ref, byte[] pkg) {
        Map<String, byte[]> files;
        try {
            files = ScriptPackage.decode(pkg);
        } catch (ProtocolException e) {
            return Verdict.fail("el paquete está mal formado");
        }
        var manifestBytes = files.get(ScriptCatalog.MANIFEST);
        if (manifestBytes == null) {
            return Verdict.fail("falta manifest.json");
        }
        try {
            var manifest = ScriptManifest.parse(ref.id(), manifestBytes);
            if (!manifest.runsOnClient()) {
                return Verdict.fail("no es un script de cliente");
            }
            if (!manifest.version().equals(ref.version()) || manifest.required() != ref.required()
                    || !manifest.capabilities().equals(ref.caps())) {
                return Verdict.fail("no coincide con lo que anunció el servidor");
            }
            var verdict = ScriptVerifier.verify(files, keys.stream().map(KeyList.Entry::key).toList());
            if (verdict instanceof ScriptVerifier.Result.Invalid invalid) {
                return Verdict.fail(ScriptCatalog.describe(invalid.reason()));
            }
            var keyId = ((ScriptVerifier.Result.Valid) verdict).keyId();
            var signer = keys.stream().filter(k -> k.key().keyId().equals(keyId)).findFirst().orElseThrow().label();
            return new Verdict(new Ready(new ScriptHost.Package(manifest, ScriptCatalog.sources(files)), signer), null);
        } catch (IllegalArgumentException e) {
            return Verdict.fail(e.getMessage());
        }
    }
}
