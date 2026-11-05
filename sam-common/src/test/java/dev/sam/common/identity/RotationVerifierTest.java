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

import dev.sam.common.identity.RotationVerifier.Reason;
import dev.sam.common.identity.RotationVerifier.Result;

/**
 * PROTOCOLO.md 3.7: rotación de la clave del servidor firmada por la clave anterior.
 *
 * <p>Las firmas esperadas se calcularon con la librería 'cryptography' de Python (OpenSSL),
 * independiente. Ed25519 es determinista: la implementación Java debe reproducirlas exactas.
 */
class RotationVerifierTest {

    private static final ServerId SID_1 = ServerId.fromHex("00000000000000000000000000000001");
    private static final ServerId SID_2 = ServerId.fromHex("00000000000000000000000000000002");
    private static final PinnedServer FIJADO_K1 = new PinnedServer(SID_1, K1.publicKey(), "S", Instant.EPOCH);

    private static final String SIG_K1_K2 = "b31a237a3262c30491bb6c2abba4de49bb1c7db822814e9f466ed721d117ff3835f42d54ba1f5c580894acf933fa1ce254997125c59a00461e60ae9b9fa9fc0d";
    private static final String SIG_K2_K3 = "e0ac1e9456590e2058cb51810691ff163e2c340b45d5ce8e000e9394ef169432c3859c3d844b8464723892844fbee62ec958a7796d4a4d7d94a17aaea94a1900";
    private static final String MSG_K1_K2 = "53414d2d726f742d76310000000000000000000000000000000106e3fd8fda29bb60ab59557de61edb0aecdb231134be30e75b455f8e1b792fa9302a300506032b65700321003d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c000000006aeb3740";

    // ===== Formato de la declaración =====

    @Test
    void elMensajeFirmadoCoincideConLaReferencia() {
        var rot = RotationStatement.unsigned(SID_1, K1.publicKey().pin(), K2.publicKey(), 1793800000L);
        assertThat(HexFormat.of().formatHex(rot.signedMessage())).isEqualTo(MSG_K1_K2);
    }

    @Test
    void firmarEnJavaReproduceLaFirmaDeLaReferencia() {
        var mensaje = HexFormat.of().parseHex(MSG_K1_K2);
        assertThat(HexFormat.of().formatHex(K1.sign(mensaje))).isEqualTo(SIG_K1_K2);
    }

    @Test
    void laFirmaDeLaReferenciaEsValidaConLaClaveAnterior() {
        assertThat(k1ToK2().isSignedBy(K1.publicKey())).isTrue();
        assertThat(k1ToK2().isSignedBy(K2.publicKey())).isFalse();
    }

    @Test
    void unaDeclaracionQueNoCorrespondeALaClaveQueLaVerificaNoEsValida() {
        // Firma válida de K1, pero old_pin dice K3: la clave que verifica debe ser la del old_pin
        var rot = signed(SID_1, K1, K3.publicKey().pin(), K2.publicKey(), 1L);
        assertThat(rot.isSignedBy(K1.publicKey())).isFalse();
    }

    @Test
    void laFirmaDebeMedir64Bytes() {
        assertThatThrownBy(() -> new RotationStatement(SID_1, K1.publicKey().pin(), K2.publicKey(), 1L, new byte[63]))
            .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void igualdadPorValorIncluyendoLaFirma() {
        assertThat(k1ToK2()).isEqualTo(k1ToK2()).hasSameHashCodeAs(k1ToK2());
        var otraFirma = new RotationStatement(SID_1, K1.publicKey().pin(), K2.publicKey(), 1793800000L, new byte[64]);
        assertThat(otraFirma).isNotEqualTo(k1ToK2());
        assertThat(k1ToK2().signature()).isEqualTo(HexFormat.of().parseHex(SIG_K1_K2));
        assertThat(k1ToK2().toString()).contains("1793800000");
    }

    @Test
    void cambiarCualquierCampoCambiaLaIgualdadYElHash() {
        var base = k1ToK2();
        var firma = HexFormat.of().parseHex(SIG_K1_K2);
        var variantes = List.of(
            new RotationStatement(SID_2, K1.publicKey().pin(), K2.publicKey(), 1793800000L, firma),
            new RotationStatement(SID_1, K2.publicKey().pin(), K2.publicKey(), 1793800000L, firma),
            new RotationStatement(SID_1, K1.publicKey().pin(), K3.publicKey(), 1793800000L, firma),
            new RotationStatement(SID_1, K1.publicKey().pin(), K2.publicKey(), 1793800001L, firma));
        for (var variante : variantes) {
            assertThat(variante).isNotEqualTo(base);
            assertThat(variante.hashCode()).isNotEqualTo(base.hashCode());
        }
        assertThat((Object) base).isNotEqualTo("no es una rotación");
    }

    @Test
    void laFirmaDevueltaEsUnaCopia() {
        var rot = k1ToK2();
        rot.signature()[0] ^= 1;
        assertThat(rot.isSignedBy(K1.publicKey())).isTrue();
    }

    // ===== Resolución de cadenas =====

    @Test
    void unSaltoValidoRota() {
        assertThat(RotationVerifier.resolve(FIJADO_K1, K2.publicKey(), List.of(k1ToK2())))
            .isEqualTo(new Result.Rotated(K2.publicKey(), 1));
    }

    @Test
    void unaCadenaDeDosSaltosRota() {
        assertThat(RotationVerifier.resolve(FIJADO_K1, K3.publicKey(), List.of(k1ToK2(), k2ToK3())))
            .isEqualTo(new Result.Rotated(K3.publicKey(), 2));
    }

    @Test
    void elOrdenDeLasDeclaracionesNoImporta() {
        assertThat(RotationVerifier.resolve(FIJADO_K1, K3.publicKey(), List.of(k2ToK3(), k1ToK2())))
            .isEqualTo(new Result.Rotated(K3.publicKey(), 2));
    }

    @Test
    void sinDeclaracionesNoHayCamino() {
        assertThat(RotationVerifier.resolve(FIJADO_K1, K2.publicKey(), List.of()))
            .isEqualTo(new Result.Rejected(Reason.NO_PATH));
    }

    @Test
    void unaCadenaQueNoLlegaALaClavePresentadaNoRota() {
        assertThat(RotationVerifier.resolve(FIJADO_K1, K3.publicKey(), List.of(k1ToK2())))
            .isEqualTo(new Result.Rejected(Reason.NO_PATH));
    }

    @Test
    void unaCadenaQueNoEmpiezaEnLaClaveFijadaNoRota() {
        assertThat(RotationVerifier.resolve(FIJADO_K1, K3.publicKey(), List.of(k2ToK3())))
            .isEqualTo(new Result.Rejected(Reason.NO_PATH));
    }

    @Test
    void unaFirmaFalsificadaRechazaTodo() {
        // Un atacante con K3 firma "K1 → K3" haciéndose pasar por K1
        var falsa = signed(SID_1, K3, K1.publicKey().pin(), K3.publicKey(), 1L);
        assertThat(RotationVerifier.resolve(FIJADO_K1, K3.publicKey(), List.of(falsa)))
            .isEqualTo(new Result.Rejected(Reason.INVALID_SIGNATURE));
    }

    @Test
    void lasDeclaracionesDeOtroServerIdSeIgnoran() {
        var deOtro = signed(SID_2, K1, K1.publicKey().pin(), K2.publicKey(), 1L);
        assertThat(RotationVerifier.resolve(FIJADO_K1, K2.publicKey(), List.of(deOtro)))
            .isEqualTo(new Result.Rejected(Reason.NO_PATH));
    }

    @Test
    void unCicloNoSeRecorreParaSiempre() {
        var vuelta = signed(SID_1, K2, K2.publicKey().pin(), K1.publicKey(), 2L);
        assertThat(RotationVerifier.resolve(FIJADO_K1, K3.publicKey(), List.of(k1ToK2(), vuelta)))
            .isEqualTo(new Result.Rejected(Reason.NO_PATH));
    }

    @Test
    void masDeCuatroDeclaracionesSeRechazan() {
        var cinco = List.of(k1ToK2(), k1ToK2(), k1ToK2(), k1ToK2(), k1ToK2());
        assertThat(RotationVerifier.resolve(FIJADO_K1, K2.publicKey(), cinco))
            .isEqualTo(new Result.Rejected(Reason.TOO_MANY_STATEMENTS));
        var cuatro = List.of(k1ToK2(), k1ToK2(), k1ToK2(), k2ToK3());
        assertThat(RotationVerifier.resolve(FIJADO_K1, K3.publicKey(), cuatro)).isInstanceOf(Result.Rotated.class);
    }

    @Test
    void laClavePresentadaIgualALaFijadaNoEsUnaRotacion() {
        assertThatThrownBy(() -> RotationVerifier.resolve(FIJADO_K1, K1.publicKey(), List.of(k1ToK2())))
            .isInstanceOf(IllegalArgumentException.class);
    }

    // ===== Helpers =====

    private static RotationStatement k1ToK2() {
        return new RotationStatement(SID_1, K1.publicKey().pin(), K2.publicKey(), 1793800000L,
            HexFormat.of().parseHex(SIG_K1_K2));
    }

    private static RotationStatement k2ToK3() {
        return new RotationStatement(SID_1, K2.publicKey().pin(), K3.publicKey(), 1793900000L,
            HexFormat.of().parseHex(SIG_K2_K3));
    }

    private static RotationStatement signed(ServerId id, TestKeys.TestKey firmante, Pin oldPin, ServerPublicKey nueva, long issuedAt) {
        var sinFirma = RotationStatement.unsigned(id, oldPin, nueva, issuedAt);
        return new RotationStatement(id, oldPin, nueva, issuedAt, firmante.sign(sinFirma.signedMessage()));
    }
}
