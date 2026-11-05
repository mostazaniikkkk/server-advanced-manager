package dev.sam.common.identity;

import java.time.Instant;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

import dev.sam.common.net.ServerAddress;

/**
 * Almacén de pins del cliente (RS-NET-07, PROTOCOLO.md 3.3): decide si se confía en el servidor
 * presentado en cada conexión TLS.
 *
 * <p>Inmutable: toda modificación devuelve un almacén nuevo. Invariante: toda dirección apunta a
 * un servidor fijado.
 *
 * <p>Las direcciones son {@link ServerAddress}: normalizadas por construcción.
 */
public final class PinStore {

    /** Resultado de {@link #verify}. */
    public sealed interface Verdict {

        /**
         * Es el servidor fijado.
         *
         * @param newAddress el servidor es conocido pero llegó por una dirección no registrada
         *                   (por ejemplo, por WebSocket): el llamador debería {@link #addAddress}
         */
        record Trusted(PinnedServer server, boolean newAddress) implements Verdict {
        }

        /** Servidor nunca visto: requiere la pantalla de primera conexión (PROTOCOLO.md 3.4). */
        record FirstContact(ServerId id, ServerPublicKey key) implements Verdict {
        }

        /**
         * La clave cambió con una cadena de rotación válida (PROTOCOLO.md 3.7): el llamador debe
         * aplicar {@link #replaceKey} y continuar sin alertar al jugador.
         */
        record Rotated(PinnedServer previous, ServerPublicKey newKey, int chainLength) implements Verdict {
        }

        /** La dirección fijada presenta otro server_id. */
        record IdentityMismatch(ServerId expected, ServerId presented) implements Verdict {
            public String code() {
                return "SAM-C001";
            }
        }

        /** Un server_id fijado se presenta con otra clave, sin rotación válida. */
        record KeyChanged(PinnedServer pinned, ServerPublicKey presented) implements Verdict {
            public String code() {
                return "SAM-C002";
            }
        }
    }

    private static final PinStore EMPTY = new PinStore(Map.of(), Map.of());

    private final Map<ServerId, PinnedServer> servers;
    private final Map<ServerAddress, ServerId> addresses;

    private PinStore(Map<ServerId, PinnedServer> servers, Map<ServerAddress, ServerId> addresses) {
        this.servers = Map.copyOf(servers);
        this.addresses = Map.copyOf(addresses);
    }

    public static PinStore empty() {
        return EMPTY;
    }

    public Verdict verify(ServerAddress address, ServerId id, ServerPublicKey key) {
        return verify(address, id, key, List.of());
    }

    /**
     * @param rotations declaraciones de rotación que envió el servidor en {@code sam:hello}
     */
    public Verdict verify(ServerAddress address, ServerId id, ServerPublicKey key, List<RotationStatement> rotations) {
        var addressOwner = addresses.get(address);
        if (addressOwner != null && !addressOwner.equals(id)) {
            return new Verdict.IdentityMismatch(addressOwner, id);
        }
        var pinned = servers.get(id);
        if (pinned == null) {
            return new Verdict.FirstContact(id, key);
        }
        if (pinned.key().equals(key)) {
            return new Verdict.Trusted(pinned, addressOwner == null);
        }
        return switch (RotationVerifier.resolve(pinned, key, rotations)) {
            case RotationVerifier.Result.Rotated rotated ->
                new Verdict.Rotated(pinned, rotated.newKey(), rotated.chainLength());
            case RotationVerifier.Result.Rejected rejected -> new Verdict.KeyChanged(pinned, key);
        };
    }

    /**
     * Fija un servidor tras la confirmación del jugador. Si ya estaba fijado con la misma clave,
     * solo registra la dirección y conserva el nombre y la fecha originales.
     *
     * @throws IllegalStateException si el server_id ya está fijado con otra clave (usar
     *                               {@link #replaceKey}) o la dirección pertenece a otro servidor
     */
    public PinStore trust(ServerAddress address, ServerId id, ServerPublicKey key, String name, Instant firstSeen) {
        var pinned = servers.get(id);
        if (pinned != null && !pinned.key().equals(key)) {
            throw new IllegalStateException(
                "El servidor " + id.hex() + " ya está fijado con otra clave: usar replaceKey");
        }
        requireAddressFreeOrOwnedBy(address, id);
        var newServers = new HashMap<>(servers);
        newServers.putIfAbsent(id, new PinnedServer(id, key, name, firstSeen));
        var newAddresses = new HashMap<>(addresses);
        newAddresses.put(address, id);
        return new PinStore(newServers, newAddresses);
    }

    /** Asocia otra dirección a un servidor ya fijado (RF-WS-05). */
    public PinStore addAddress(ServerAddress address, ServerId id) {
        if (!servers.containsKey(id)) {
            throw new IllegalArgumentException("El servidor " + id.hex() + " no está fijado");
        }
        requireAddressFreeOrOwnedBy(address, id);
        var newAddresses = new HashMap<>(addresses);
        newAddresses.put(address, id);
        return new PinStore(servers, newAddresses);
    }

    /**
     * Reemplaza la clave de un servidor fijado. Solo tras una rotación válida
     * ({@link Verdict.Rotated}) o la confirmación fuerte del jugador (RS-NET-08).
     */
    public PinStore replaceKey(ServerId id, ServerPublicKey newKey) {
        var pinned = servers.get(id);
        if (pinned == null) {
            throw new IllegalArgumentException("El servidor " + id.hex() + " no está fijado");
        }
        var newServers = new HashMap<>(servers);
        newServers.put(id, pinned.withKey(newKey));
        return new PinStore(newServers, addresses);
    }

    /** Olvida un servidor y todas sus direcciones (borrado manual del pin, RS-NET-10). */
    public PinStore forget(ServerId id) {
        var newServers = new HashMap<>(servers);
        newServers.remove(id);
        var newAddresses = new HashMap<>(addresses);
        newAddresses.values().removeIf(id::equals);
        return new PinStore(newServers, newAddresses);
    }

    public boolean isPinned(ServerAddress address) {
        return addresses.containsKey(address);
    }

    public Optional<PinnedServer> server(ServerId id) {
        return Optional.ofNullable(servers.get(id));
    }

    /** Vista inmutable de los servidores fijados. */
    public Map<ServerId, PinnedServer> servers() {
        return servers;
    }

    /** Vista inmutable de las direcciones registradas. */
    public Map<ServerAddress, ServerId> addresses() {
        return addresses;
    }

    /**
     * Agrega un servidor sin dirección (al cargar {@code pins.json}, si sus direcciones se
     * descartaron). Si el server_id ya existe, no cambia nada.
     */
    PinStore withServer(PinnedServer server) {
        if (servers.containsKey(server.id())) {
            return this;
        }
        var newServers = new HashMap<>(servers);
        newServers.put(server.id(), server);
        return new PinStore(newServers, addresses);
    }

    @Override
    public boolean equals(Object other) {
        return other instanceof PinStore that && servers.equals(that.servers) && addresses.equals(that.addresses);
    }

    @Override
    public int hashCode() {
        return Objects.hash(servers, addresses);
    }

    @Override
    public String toString() {
        return "PinStore[servers=" + servers.size() + ", addresses=" + addresses.size() + "]";
    }

    private void requireAddressFreeOrOwnedBy(ServerAddress address, ServerId id) {
        var owner = addresses.get(address);
        if (owner != null && !owner.equals(id)) {
            throw new IllegalStateException(
                "La dirección " + address + " ya pertenece al servidor " + owner.hex());
        }
    }
}
