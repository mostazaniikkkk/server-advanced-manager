package dev.sam.common.identity;

import static dev.sam.common.identity.TestKeys.K1;
import static dev.sam.common.identity.TestKeys.K2;
import static dev.sam.common.identity.TestKeys.K3;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.time.Instant;
import java.util.HexFormat;
import java.util.List;

import org.junit.jupiter.api.Test;

import dev.sam.common.identity.PinStore.Verdict;
import dev.sam.common.net.ServerAddress;
import net.jqwik.api.ForAll;
import net.jqwik.api.Property;
import net.jqwik.api.constraints.Size;

/**
 * RS-NET-07 / PROTOCOLO.md 3.3 y 3.7: decisión de confianza en cada conexión TLS.
 *
 * <p>Las direcciones son ServerAddress (normalizadas por construcción).
 */
class PinStoreTest {

    private static final ServerAddress DIR_TCP = ServerAddress.parse("play.ejemplo.com:25565");
    private static final ServerAddress DIR_WS = ServerAddress.parse("wss://mc.ejemplo.com/a1b2c3");
    private static final ServerAddress DIR_OTRA = ServerAddress.parse("otro.ejemplo.com:25565");

    private static final ServerId ID_A = ServerId.fromHex("00000000000000000000000000000001");
    private static final ServerId ID_B = ServerId.fromHex("0000000000000000000000000000000b");
    private static final ServerPublicKey KEY_1 = K1.publicKey();
    private static final ServerPublicKey KEY_2 = K2.publicKey();
    private static final Instant T0 = Instant.parse("2026-11-04T18:00:00Z");
    private static final Instant T1 = Instant.parse("2026-12-01T10:00:00Z");

    /** Rotación K1 → K2 de ID_A (vector de RotationVerifierTest). */
    private static final RotationStatement ROT_K1_K2 = new RotationStatement(ID_A, KEY_1.pin(), KEY_2, 1793800000L,
        HexFormat.of().parseHex("b31a237a3262c30491bb6c2abba4de49bb1c7db822814e9f466ed721d117ff3835f42d54ba1f5c580894acf933fa1ce254997125c59a00461e60ae9b9fa9fc0d"));

    // ===== Primera conexión =====

    @Test
    void unServidorNuncaVistoEsPrimerContacto() {
        assertThat(PinStore.empty().verify(DIR_TCP, ID_A, KEY_1)).isEqualTo(new Verdict.FirstContact(ID_A, KEY_1));
    }

    @Test
    void trasConfiarElMismoServidorEsDeConfianza() {
        var store = PinStore.empty().trust(DIR_TCP, ID_A, KEY_1, "Mi Servidor", T0);
        var veredicto = store.verify(DIR_TCP, ID_A, KEY_1);
        assertThat(veredicto).isEqualTo(new Verdict.Trusted(new PinnedServer(ID_A, KEY_1, "Mi Servidor", T0), false));
    }

    @Test
    void elServidorFijadoExponeSuPin() {
        var store = PinStore.empty().trust(DIR_TCP, ID_A, KEY_1, "Mi Servidor", T0);
        assertThat(store.server(ID_A).orElseThrow().pin()).isEqualTo(KEY_1.pin());
    }

    @Test
    void confiarDevuelveUnAlmacenNuevoSinTocarElOriginal() {
        var vacio = PinStore.empty();
        var conPin = vacio.trust(DIR_TCP, ID_A, KEY_1, "Mi Servidor", T0);
        assertThat(vacio.verify(DIR_TCP, ID_A, KEY_1)).isInstanceOf(Verdict.FirstContact.class);
        assertThat(conPin.verify(DIR_TCP, ID_A, KEY_1)).isInstanceOf(Verdict.Trusted.class);
        assertThat(vacio.isPinned(DIR_TCP)).isFalse();
        assertThat(conPin.isPinned(DIR_TCP)).isTrue();
    }

    // ===== Mismo servidor por otra dirección (RF-WS-05) =====

    @Test
    void elMismoServidorPorOtraDireccionEsDeConfianzaPeroAvisaQueLaDireccionEsNueva() {
        var store = PinStore.empty().trust(DIR_TCP, ID_A, KEY_1, "Mi Servidor", T0);
        var veredicto = (Verdict.Trusted) store.verify(DIR_WS, ID_A, KEY_1);
        assertThat(veredicto.newAddress()).isTrue();
        assertThat(store.isPinned(DIR_WS)).isFalse();
    }

    @Test
    void registrarLaDireccionNuevaLaAsociaAlMismoServidor() {
        var store = PinStore.empty().trust(DIR_TCP, ID_A, KEY_1, "Mi Servidor", T0).addAddress(DIR_WS, ID_A);
        assertThat(((Verdict.Trusted) store.verify(DIR_WS, ID_A, KEY_1)).newAddress()).isFalse();
        assertThat(store.isPinned(DIR_WS)).isTrue();
    }

    @Test
    void noSePuedeRedirigirEnSilencioUnaDireccionDeUnServidorAOtro() {
        // Si no, addAddress sería una puerta trasera para el secuestro que SAM-C001 bloquea
        var store = PinStore.empty()
            .trust(DIR_TCP, ID_A, KEY_1, "Servidor A", T0)
            .trust(DIR_OTRA, ID_B, KEY_2, "Servidor B", T0);
        assertThatThrownBy(() -> store.addAddress(DIR_TCP, ID_B))
            .isInstanceOf(IllegalStateException.class)
            .hasMessageContaining(DIR_TCP.canonical());
    }

    @Test
    void agregarUnaDireccionQueYaEsDelMismoServidorNoCambiaNada() {
        var store = PinStore.empty().trust(DIR_TCP, ID_A, KEY_1, "Servidor A", T0).addAddress(DIR_TCP, ID_A);
        assertThat(((Verdict.Trusted) store.verify(DIR_TCP, ID_A, KEY_1)).newAddress()).isFalse();
    }

    @Test
    void unServidorFijadoNoAdmiteCamposNulos() {
        assertThatThrownBy(() -> new PinnedServer(null, KEY_1, "S", T0)).isInstanceOf(NullPointerException.class);
        assertThatThrownBy(() -> new PinnedServer(ID_A, null, "S", T0)).isInstanceOf(NullPointerException.class);
        assertThatThrownBy(() -> new PinnedServer(ID_A, KEY_1, null, T0)).isInstanceOf(NullPointerException.class);
        assertThatThrownBy(() -> new PinnedServer(ID_A, KEY_1, "S", null)).isInstanceOf(NullPointerException.class);
    }

    @Test
    void noSePuedeAgregarUnaDireccionAUnServidorDesconocido() {
        assertThatThrownBy(() -> PinStore.empty().addAddress(DIR_WS, ID_A))
            .isInstanceOf(IllegalArgumentException.class);
    }

    // ===== SAM-C002: cambio de clave =====

    @Test
    void elMismoServerIdConOtraClaveEsCambioDeClave() {
        var store = PinStore.empty().trust(DIR_TCP, ID_A, KEY_1, "Mi Servidor", T0);
        var veredicto = store.verify(DIR_TCP, ID_A, KEY_2);
        assertThat(veredicto).isEqualTo(new Verdict.KeyChanged(new PinnedServer(ID_A, KEY_1, "Mi Servidor", T0), KEY_2));
        assertThat(((Verdict.KeyChanged) veredicto).code()).isEqualTo("SAM-C002");
    }

    @Test
    void unServerIdConocidoReclamadoDesdeOtraDireccionConOtraClaveSeBloquea() {
        // Un servidor falso que copia el server_id de uno conocido (RN-09 / AMENAZAS 7.1)
        var store = PinStore.empty().trust(DIR_TCP, ID_A, KEY_1, "Mi Servidor", T0);
        assertThat(store.verify(DIR_OTRA, ID_A, KEY_2)).isInstanceOf(Verdict.KeyChanged.class);
    }

    // ===== Rotación firmada (PROTOCOLO.md 3.7) =====

    @Test
    void unaRotacionValidaDaElVeredictoRotated() {
        var store = PinStore.empty().trust(DIR_TCP, ID_A, KEY_1, "Mi Servidor", T0);
        var veredicto = store.verify(DIR_TCP, ID_A, KEY_2, List.of(ROT_K1_K2));
        assertThat(veredicto).isEqualTo(new Verdict.Rotated(new PinnedServer(ID_A, KEY_1, "Mi Servidor", T0), KEY_2, 1));
    }

    @Test
    void trasAplicarLaRotacionLaClaveNuevaEsDeConfianza() {
        var store = PinStore.empty().trust(DIR_TCP, ID_A, KEY_1, "Mi Servidor", T0);
        var rotado = (Verdict.Rotated) store.verify(DIR_TCP, ID_A, KEY_2, List.of(ROT_K1_K2));
        var actualizado = store.replaceKey(ID_A, rotado.newKey());
        assertThat(actualizado.verify(DIR_TCP, ID_A, KEY_2)).isInstanceOf(Verdict.Trusted.class);
    }

    @Test
    void unaRotacionInvalidaSigueSiendoCambioDeClave() {
        var store = PinStore.empty().trust(DIR_TCP, ID_A, KEY_1, "Mi Servidor", T0);
        // Llega a K3, pero la declaración solo cubre K1 → K2
        assertThat(store.verify(DIR_TCP, ID_A, K3.publicKey(), List.of(ROT_K1_K2))).isInstanceOf(Verdict.KeyChanged.class);
    }

    @Test
    void conLaMismaClaveLasDeclaracionesSeIgnoran() {
        var store = PinStore.empty().trust(DIR_TCP, ID_A, KEY_1, "Mi Servidor", T0);
        assertThat(store.verify(DIR_TCP, ID_A, KEY_1, List.of(ROT_K1_K2))).isInstanceOf(Verdict.Trusted.class);
    }

    @Test
    void unServidorNuevoConDeclaracionesSigueSiendoPrimerContacto() {
        assertThat(PinStore.empty().verify(DIR_TCP, ID_A, KEY_2, List.of(ROT_K1_K2)))
            .isEqualTo(new Verdict.FirstContact(ID_A, KEY_2));
    }

    @Test
    void laRotacionNoSaltaElControlDeIdentidadDeLaDireccion() {
        // DIR_TCP es de B. Aunque A presente una rotación válida, por esa dirección no puede responder A
        var store = PinStore.empty()
            .trust(DIR_TCP, ID_B, K3.publicKey(), "Servidor B", T0)
            .trust(DIR_OTRA, ID_A, KEY_1, "Servidor A", T0);
        assertThat(store.verify(DIR_TCP, ID_A, KEY_2, List.of(ROT_K1_K2)))
            .isEqualTo(new Verdict.IdentityMismatch(ID_B, ID_A));
    }

    // ===== SAM-C001: la dirección presenta otra identidad =====

    @Test
    void unaDireccionFijadaQuePresentaOtroServerIdEsIdentidadDistinta() {
        var store = PinStore.empty().trust(DIR_TCP, ID_A, KEY_1, "Mi Servidor", T0);
        var veredicto = store.verify(DIR_TCP, ID_B, KEY_2);
        assertThat(veredicto).isEqualTo(new Verdict.IdentityMismatch(ID_A, ID_B));
        assertThat(((Verdict.IdentityMismatch) veredicto).code()).isEqualTo("SAM-C001");
    }

    @Test
    void identidadDistintaAunqueElOtroServidorTambienSeaDeConfianza() {
        var store = PinStore.empty()
            .trust(DIR_TCP, ID_A, KEY_1, "Servidor A", T0)
            .trust(DIR_OTRA, ID_B, KEY_2, "Servidor B", T0);
        assertThat(store.verify(DIR_TCP, ID_B, KEY_2)).isEqualTo(new Verdict.IdentityMismatch(ID_A, ID_B));
    }

    // ===== Invariantes de trust =====

    @Test
    void confiarEnUnServerIdYaFijadoConOtraClaveExigeReemplazoExplicito() {
        var store = PinStore.empty().trust(DIR_TCP, ID_A, KEY_1, "Mi Servidor", T0);
        assertThatThrownBy(() -> store.trust(DIR_OTRA, ID_A, KEY_2, "Mi Servidor", T1))
            .isInstanceOf(IllegalStateException.class)
            .hasMessageContaining("replaceKey");
    }

    @Test
    void confiarEnUnaDireccionFijadaAOtroServidorSeRechaza() {
        var store = PinStore.empty().trust(DIR_TCP, ID_A, KEY_1, "Mi Servidor", T0);
        assertThatThrownBy(() -> store.trust(DIR_TCP, ID_B, KEY_2, "Otro", T1))
            .isInstanceOf(IllegalStateException.class);
    }

    @Test
    void volverAConfiarEnLoMismoNoCambiaNada() {
        var store = PinStore.empty().trust(DIR_TCP, ID_A, KEY_1, "Mi Servidor", T0);
        var otraVez = store.trust(DIR_TCP, ID_A, KEY_1, "Nombre nuevo", T1);
        assertThat(otraVez.server(ID_A)).contains(new PinnedServer(ID_A, KEY_1, "Mi Servidor", T0));
    }

    // ===== Reemplazo manual de clave (RS-NET-08) =====

    @Test
    void reemplazarLaClaveAceptaLaNuevaYRechazaLaVieja() {
        var store = PinStore.empty().trust(DIR_TCP, ID_A, KEY_1, "Mi Servidor", T0).replaceKey(ID_A, KEY_2);
        assertThat(store.verify(DIR_TCP, ID_A, KEY_2)).isInstanceOf(Verdict.Trusted.class);
        assertThat(store.verify(DIR_TCP, ID_A, KEY_1)).isInstanceOf(Verdict.KeyChanged.class);
        assertThat(store.server(ID_A)).contains(new PinnedServer(ID_A, KEY_2, "Mi Servidor", T0));
    }

    @Test
    void noSePuedeReemplazarLaClaveDeUnServidorDesconocido() {
        assertThatThrownBy(() -> PinStore.empty().replaceKey(ID_A, KEY_2))
            .isInstanceOf(IllegalArgumentException.class);
    }

    // ===== Olvidar un servidor (RS-NET-10: borrar el pin a mano) =====

    @Test
    void olvidarUnServidorBorraSuPinYTodasSusDirecciones() {
        var store = PinStore.empty()
            .trust(DIR_TCP, ID_A, KEY_1, "Servidor A", T0)
            .addAddress(DIR_WS, ID_A)
            .trust(DIR_OTRA, ID_B, KEY_2, "Servidor B", T0)
            .forget(ID_A);
        assertThat(store.verify(DIR_TCP, ID_A, KEY_1)).isInstanceOf(Verdict.FirstContact.class);
        assertThat(store.isPinned(DIR_TCP)).isFalse();
        assertThat(store.isPinned(DIR_WS)).isFalse();
        assertThat(store.server(ID_A)).isEmpty();
        assertThat(store.verify(DIR_OTRA, ID_B, KEY_2)).isInstanceOf(Verdict.Trusted.class);
    }

    @Test
    void olvidarUnServidorDesconocidoNoCambiaNada() {
        var store = PinStore.empty().trust(DIR_TCP, ID_A, KEY_1, "Servidor A", T0);
        assertThat(store.forget(ID_B).verify(DIR_TCP, ID_A, KEY_1)).isInstanceOf(Verdict.Trusted.class);
    }

    // ===== Igualdad =====

    @Test
    void dosAlmacenesSonIgualesSoloConLosMismosServidoresYDirecciones() {
        var base = PinStore.empty().trust(DIR_TCP, ID_A, KEY_1, "Mi Servidor", T0);
        assertThat(base).isEqualTo(PinStore.empty().trust(DIR_TCP, ID_A, KEY_1, "Mi Servidor", T0))
            .hasSameHashCodeAs(PinStore.empty().trust(DIR_TCP, ID_A, KEY_1, "Mi Servidor", T0));
        var otraDireccion = base.addAddress(DIR_WS, ID_A);
        var otroServidor = base.withServer(new PinnedServer(ID_B, KEY_2, "B", T0));
        var otraClave = base.replaceKey(ID_A, KEY_2);
        for (var distinto : List.of(PinStore.empty(), otraDireccion, otroServidor, otraClave)) {
            assertThat(distinto).isNotEqualTo(base);
            assertThat(distinto.hashCode()).isNotEqualTo(base.hashCode());
        }
        assertThat((Object) base).isNotEqualTo("no es un almacén");
        assertThat(otraDireccion).hasToString("PinStore[servers=1, addresses=2]");
    }

    @Test
    void agregarUnServidorQueYaExisteNoLoReemplaza() {
        var base = PinStore.empty().trust(DIR_TCP, ID_A, KEY_1, "Mi Servidor", T0);
        assertThat(base.withServer(new PinnedServer(ID_A, KEY_2, "Impostor", T1))).isSameAs(base);
        var sinDireccion = PinStore.empty().withServer(new PinnedServer(ID_B, KEY_2, "B", T0));
        assertThat(sinDireccion.servers()).containsOnlyKeys(ID_B);
        assertThat(sinDireccion.addresses()).isEmpty();
    }

    // ===== Propiedades =====

    @Property(tries = 200)
    void despuesDeConfiarSoloElMismoParIdClaveEsDeConfianza(
            @ForAll @Size(16) byte[] id, @ForAll @Size(32) byte[] semilla,
            @ForAll @Size(16) byte[] otroId, @ForAll @Size(32) byte[] otraSemilla) {
        var serverId = ServerId.of(id);
        var clave = TestKeys.fromSeed(semilla).publicKey();
        var otraClave = TestKeys.fromSeed(otraSemilla).publicKey();
        var store = PinStore.empty().trust(DIR_TCP, serverId, clave, "S", T0);

        assertThat(store.verify(DIR_TCP, serverId, clave)).isInstanceOf(Verdict.Trusted.class);
        if (!otraClave.equals(clave)) {
            assertThat(store.verify(DIR_TCP, serverId, otraClave)).isInstanceOf(Verdict.KeyChanged.class);
        }
        if (!ServerId.of(otroId).equals(serverId)) {
            assertThat(store.verify(DIR_TCP, ServerId.of(otroId), otraClave))
                .isInstanceOf(Verdict.IdentityMismatch.class);
        }
    }
}
