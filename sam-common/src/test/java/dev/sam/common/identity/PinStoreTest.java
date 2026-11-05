package dev.sam.common.identity;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.time.Instant;

import org.junit.jupiter.api.Test;

import dev.sam.common.identity.PinStore.Verdict;
import net.jqwik.api.ForAll;
import net.jqwik.api.Property;
import net.jqwik.api.constraints.Size;

/**
 * RS-NET-07 / PROTOCOLO.md 3.3: decisión de confianza en cada conexión TLS.
 *
 * <p>Las direcciones llegan ya normalizadas (eso es otra pieza).
 */
class PinStoreTest {

    private static final String DIR_TCP = "play.ejemplo.com:25565";
    private static final String DIR_WS = "wss://mc.ejemplo.com/a1b2c3";
    private static final String DIR_OTRA = "otro.ejemplo.com:25565";

    private static final ServerId ID_A = ServerId.fromHex("0000000000000000000000000000000a");
    private static final ServerId ID_B = ServerId.fromHex("0000000000000000000000000000000b");
    private static final Pin PIN_1 = pin(1);
    private static final Pin PIN_2 = pin(2);
    private static final Instant T0 = Instant.parse("2026-11-04T18:00:00Z");
    private static final Instant T1 = Instant.parse("2026-12-01T10:00:00Z");

    // ===== Primera conexión =====

    @Test
    void unServidorNuncaVistoEsPrimerContacto() {
        assertThat(PinStore.empty().verify(DIR_TCP, ID_A, PIN_1))
            .isEqualTo(new Verdict.FirstContact(ID_A, PIN_1));
    }

    @Test
    void trasConfiarElMismoServidorEsDeConfianza() {
        var store = PinStore.empty().trust(DIR_TCP, ID_A, PIN_1, "Mi Servidor", T0);
        var veredicto = store.verify(DIR_TCP, ID_A, PIN_1);
        assertThat(veredicto).isInstanceOf(Verdict.Trusted.class);
        var trusted = (Verdict.Trusted) veredicto;
        assertThat(trusted.newAddress()).isFalse();
        assertThat(trusted.server()).isEqualTo(new PinnedServer(ID_A, PIN_1, "Mi Servidor", T0));
    }

    @Test
    void confiarDevuelveUnAlmacenNuevoSinTocarElOriginal() {
        var vacio = PinStore.empty();
        var conPin = vacio.trust(DIR_TCP, ID_A, PIN_1, "Mi Servidor", T0);
        assertThat(vacio.verify(DIR_TCP, ID_A, PIN_1)).isInstanceOf(Verdict.FirstContact.class);
        assertThat(conPin.verify(DIR_TCP, ID_A, PIN_1)).isInstanceOf(Verdict.Trusted.class);
        assertThat(vacio.isPinned(DIR_TCP)).isFalse();
        assertThat(conPin.isPinned(DIR_TCP)).isTrue();
    }

    // ===== Mismo servidor por otra dirección (RF-WS-05) =====

    @Test
    void elMismoServidorPorOtraDireccionEsDeConfianzaPeroAvisaQueLaDireccionEsNueva() {
        var store = PinStore.empty().trust(DIR_TCP, ID_A, PIN_1, "Mi Servidor", T0);
        var veredicto = (Verdict.Trusted) store.verify(DIR_WS, ID_A, PIN_1);
        assertThat(veredicto.newAddress()).isTrue();
        assertThat(store.isPinned(DIR_WS)).isFalse();
    }

    @Test
    void registrarLaDireccionNuevaLaAsociaAlMismoServidor() {
        var store = PinStore.empty().trust(DIR_TCP, ID_A, PIN_1, "Mi Servidor", T0).addAddress(DIR_WS, ID_A);
        assertThat(((Verdict.Trusted) store.verify(DIR_WS, ID_A, PIN_1)).newAddress()).isFalse();
        assertThat(store.isPinned(DIR_WS)).isTrue();
    }

    @Test
    void noSePuedeRedirigirEnSilencioUnaDireccionDeUnServidorAOtro() {
        // Si no, addAddress sería una puerta trasera para el secuestro que SAM-C001 bloquea
        var store = PinStore.empty()
            .trust(DIR_TCP, ID_A, PIN_1, "Servidor A", T0)
            .trust(DIR_OTRA, ID_B, PIN_2, "Servidor B", T0);
        assertThatThrownBy(() -> store.addAddress(DIR_TCP, ID_B))
            .isInstanceOf(IllegalStateException.class)
            .hasMessageContaining(DIR_TCP);
    }

    @Test
    void agregarUnaDireccionQueYaEsDelMismoServidorNoCambiaNada() {
        var store = PinStore.empty().trust(DIR_TCP, ID_A, PIN_1, "Servidor A", T0).addAddress(DIR_TCP, ID_A);
        assertThat(((Verdict.Trusted) store.verify(DIR_TCP, ID_A, PIN_1)).newAddress()).isFalse();
    }

    @Test
    void unServidorFijadoNoAdmiteCamposNulos() {
        assertThatThrownBy(() -> new PinnedServer(null, PIN_1, "S", T0)).isInstanceOf(NullPointerException.class);
        assertThatThrownBy(() -> new PinnedServer(ID_A, null, "S", T0)).isInstanceOf(NullPointerException.class);
        assertThatThrownBy(() -> new PinnedServer(ID_A, PIN_1, null, T0)).isInstanceOf(NullPointerException.class);
        assertThatThrownBy(() -> new PinnedServer(ID_A, PIN_1, "S", null)).isInstanceOf(NullPointerException.class);
    }

    @Test
    void noSePuedeAgregarUnaDireccionAUnServidorDesconocido() {
        assertThatThrownBy(() -> PinStore.empty().addAddress(DIR_WS, ID_A))
            .isInstanceOf(IllegalArgumentException.class);
    }

    // ===== SAM-C002: cambio de clave =====

    @Test
    void elMismoServerIdConOtraClaveEsCambioDeClave() {
        var store = PinStore.empty().trust(DIR_TCP, ID_A, PIN_1, "Mi Servidor", T0);
        var veredicto = store.verify(DIR_TCP, ID_A, PIN_2);
        assertThat(veredicto).isEqualTo(new Verdict.KeyChanged(new PinnedServer(ID_A, PIN_1, "Mi Servidor", T0), PIN_2));
        assertThat(((Verdict.KeyChanged) veredicto).code()).isEqualTo("SAM-C002");
    }

    @Test
    void unServerIdConocidoReclamadoDesdeOtraDireccionConOtraClaveSeBloquea() {
        // Un servidor falso que copia el server_id de uno conocido (RN-09 / AMENAZAS 7.1)
        var store = PinStore.empty().trust(DIR_TCP, ID_A, PIN_1, "Mi Servidor", T0);
        assertThat(store.verify(DIR_OTRA, ID_A, PIN_2)).isInstanceOf(Verdict.KeyChanged.class);
    }

    // ===== SAM-C001: la dirección presenta otra identidad =====

    @Test
    void unaDireccionFijadaQuePresentaOtroServerIdEsIdentidadDistinta() {
        var store = PinStore.empty().trust(DIR_TCP, ID_A, PIN_1, "Mi Servidor", T0);
        var veredicto = store.verify(DIR_TCP, ID_B, PIN_2);
        assertThat(veredicto).isEqualTo(new Verdict.IdentityMismatch(ID_A, ID_B));
        assertThat(((Verdict.IdentityMismatch) veredicto).code()).isEqualTo("SAM-C001");
    }

    @Test
    void identidadDistintaAunqueElOtroServidorTambienSeaDeConfianza() {
        // Si la dirección de A ahora responde B (aunque B sea legítimo), alguien redirigió la dirección
        var store = PinStore.empty()
            .trust(DIR_TCP, ID_A, PIN_1, "Servidor A", T0)
            .trust(DIR_OTRA, ID_B, PIN_2, "Servidor B", T0);
        assertThat(store.verify(DIR_TCP, ID_B, PIN_2)).isEqualTo(new Verdict.IdentityMismatch(ID_A, ID_B));
    }

    // ===== Invariantes de trust =====

    @Test
    void confiarEnUnServerIdYaFijadoConOtraClaveExigeReemplazoExplicito() {
        var store = PinStore.empty().trust(DIR_TCP, ID_A, PIN_1, "Mi Servidor", T0);
        assertThatThrownBy(() -> store.trust(DIR_OTRA, ID_A, PIN_2, "Mi Servidor", T1))
            .isInstanceOf(IllegalStateException.class)
            .hasMessageContaining("replacePin");
    }

    @Test
    void confiarEnUnaDireccionFijadaAOtroServidorSeRechaza() {
        var store = PinStore.empty().trust(DIR_TCP, ID_A, PIN_1, "Mi Servidor", T0);
        assertThatThrownBy(() -> store.trust(DIR_TCP, ID_B, PIN_2, "Otro", T1))
            .isInstanceOf(IllegalStateException.class);
    }

    @Test
    void volverAConfiarEnLoMismoNoCambiaNada() {
        var store = PinStore.empty().trust(DIR_TCP, ID_A, PIN_1, "Mi Servidor", T0);
        var otraVez = store.trust(DIR_TCP, ID_A, PIN_1, "Nombre nuevo", T1);
        assertThat(otraVez.server(ID_A)).contains(new PinnedServer(ID_A, PIN_1, "Mi Servidor", T0));
    }

    // ===== Reemplazo manual de clave (RS-NET-08) =====

    @Test
    void reemplazarElPinAceptaLaClaveNuevaYRechazaLaVieja() {
        var store = PinStore.empty().trust(DIR_TCP, ID_A, PIN_1, "Mi Servidor", T0).replacePin(ID_A, PIN_2);
        assertThat(store.verify(DIR_TCP, ID_A, PIN_2)).isInstanceOf(Verdict.Trusted.class);
        assertThat(store.verify(DIR_TCP, ID_A, PIN_1)).isInstanceOf(Verdict.KeyChanged.class);
        assertThat(store.server(ID_A)).contains(new PinnedServer(ID_A, PIN_2, "Mi Servidor", T0));
    }

    @Test
    void noSePuedeReemplazarElPinDeUnServidorDesconocido() {
        assertThatThrownBy(() -> PinStore.empty().replacePin(ID_A, PIN_2))
            .isInstanceOf(IllegalArgumentException.class);
    }

    // ===== Olvidar un servidor (RS-NET-10: borrar el pin a mano) =====

    @Test
    void olvidarUnServidorBorraSuPinYTodasSusDirecciones() {
        var store = PinStore.empty()
            .trust(DIR_TCP, ID_A, PIN_1, "Servidor A", T0)
            .addAddress(DIR_WS, ID_A)
            .trust(DIR_OTRA, ID_B, PIN_2, "Servidor B", T0)
            .forget(ID_A);
        assertThat(store.verify(DIR_TCP, ID_A, PIN_1)).isInstanceOf(Verdict.FirstContact.class);
        assertThat(store.isPinned(DIR_TCP)).isFalse();
        assertThat(store.isPinned(DIR_WS)).isFalse();
        assertThat(store.server(ID_A)).isEmpty();
        assertThat(store.verify(DIR_OTRA, ID_B, PIN_2)).isInstanceOf(Verdict.Trusted.class);
    }

    @Test
    void olvidarUnServidorDesconocidoNoCambiaNada() {
        var store = PinStore.empty().trust(DIR_TCP, ID_A, PIN_1, "Servidor A", T0);
        assertThat(store.forget(ID_B).verify(DIR_TCP, ID_A, PIN_1)).isInstanceOf(Verdict.Trusted.class);
    }

    // ===== Propiedades =====

    @Property
    void despuesDeConfiarSoloElMismoParIdClaveEsDeConfianza(
            @ForAll @Size(16) byte[] id, @ForAll @Size(32) byte[] clave,
            @ForAll @Size(16) byte[] otroId, @ForAll @Size(32) byte[] otraClave) {
        var serverId = ServerId.of(id);
        var pin = Pin.of(clave);
        var store = PinStore.empty().trust(DIR_TCP, serverId, pin, "S", T0);

        assertThat(store.verify(DIR_TCP, serverId, pin)).isInstanceOf(Verdict.Trusted.class);
        if (!Pin.of(otraClave).equals(pin)) {
            assertThat(store.verify(DIR_TCP, serverId, Pin.of(otraClave))).isInstanceOf(Verdict.KeyChanged.class);
        }
        if (!ServerId.of(otroId).equals(serverId)) {
            assertThat(store.verify(DIR_TCP, ServerId.of(otroId), Pin.of(otraClave)))
                .isInstanceOf(Verdict.IdentityMismatch.class);
        }
    }

    private static Pin pin(int ultimo) {
        var bytes = new byte[32];
        bytes[31] = (byte) ultimo;
        return Pin.of(bytes);
    }
}
