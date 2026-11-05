package dev.sam.common.identity;

import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

/**
 * Almacén de pins del cliente (RS-NET-07, PROTOCOLO.md 3.3): decide si se confía en el servidor
 * presentado en cada conexión TLS.
 *
 * <p>Inmutable: toda modificación devuelve un almacén nuevo. Invariante: toda dirección apunta a
 * un servidor fijado.
 *
 * <p>Las direcciones se usan como claves opacas: deben llegar ya normalizadas.
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
        record FirstContact(ServerId id, Pin pin) implements Verdict {
        }

        /** La dirección fijada presenta otro server_id. */
        record IdentityMismatch(ServerId expected, ServerId presented) implements Verdict {
            public String code() {
                return "SAM-C001";
            }
        }

        /** Un server_id fijado se presenta con otra clave. */
        record KeyChanged(PinnedServer pinned, Pin presented) implements Verdict {
            public String code() {
                return "SAM-C002";
            }
        }
    }

    private static final PinStore EMPTY = new PinStore(Map.of(), Map.of());

    private final Map<ServerId, PinnedServer> servers;
    private final Map<String, ServerId> addresses;

    private PinStore(Map<ServerId, PinnedServer> servers, Map<String, ServerId> addresses) {
        this.servers = Map.copyOf(servers);
        this.addresses = Map.copyOf(addresses);
    }

    public static PinStore empty() {
        return EMPTY;
    }

    public Verdict verify(String address, ServerId id, Pin pin) {
        var addressOwner = addresses.get(address);
        if (addressOwner != null && !addressOwner.equals(id)) {
            return new Verdict.IdentityMismatch(addressOwner, id);
        }
        var pinned = servers.get(id);
        if (pinned == null) {
            return new Verdict.FirstContact(id, pin);
        }
        if (!pinned.pin().equals(pin)) {
            return new Verdict.KeyChanged(pinned, pin);
        }
        return new Verdict.Trusted(pinned, addressOwner == null);
    }

    /**
     * Fija un servidor tras la confirmación del jugador. Si ya estaba fijado con la misma clave,
     * solo registra la dirección y conserva el nombre y la fecha originales.
     *
     * @throws IllegalStateException si el server_id ya está fijado con otra clave (usar
     *                               {@link #replacePin}) o la dirección pertenece a otro servidor
     */
    public PinStore trust(String address, ServerId id, Pin pin, String name, Instant firstSeen) {
        var pinned = servers.get(id);
        if (pinned != null && !pinned.pin().equals(pin)) {
            throw new IllegalStateException(
                "El servidor " + id.hex() + " ya está fijado con otra clave: usar replacePin");
        }
        requireAddressFreeOrOwnedBy(address, id);
        var newServers = new HashMap<>(servers);
        newServers.putIfAbsent(id, new PinnedServer(id, pin, name, firstSeen));
        var newAddresses = new HashMap<>(addresses);
        newAddresses.put(address, id);
        return new PinStore(newServers, newAddresses);
    }

    /** Asocia otra dirección a un servidor ya fijado (RF-WS-05). */
    public PinStore addAddress(String address, ServerId id) {
        if (!servers.containsKey(id)) {
            throw new IllegalArgumentException("El servidor " + id.hex() + " no está fijado");
        }
        requireAddressFreeOrOwnedBy(address, id);
        var newAddresses = new HashMap<>(addresses);
        newAddresses.put(address, id);
        return new PinStore(servers, newAddresses);
    }

    /**
     * Reemplaza la clave de un servidor fijado. Solo tras la confirmación fuerte del jugador
     * (RS-NET-08) o una rotación firmada válida (PROTOCOLO.md 3.7).
     */
    public PinStore replacePin(ServerId id, Pin newPin) {
        var pinned = servers.get(id);
        if (pinned == null) {
            throw new IllegalArgumentException("El servidor " + id.hex() + " no está fijado");
        }
        var newServers = new HashMap<>(servers);
        newServers.put(id, pinned.withPin(newPin));
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

    public boolean isPinned(String address) {
        return addresses.containsKey(address);
    }

    public Optional<PinnedServer> server(ServerId id) {
        return Optional.ofNullable(servers.get(id));
    }

    private void requireAddressFreeOrOwnedBy(String address, ServerId id) {
        var owner = addresses.get(address);
        if (owner != null && !owner.equals(id)) {
            throw new IllegalStateException(
                "La dirección " + address + " ya pertenece al servidor " + owner.hex());
        }
    }
}
