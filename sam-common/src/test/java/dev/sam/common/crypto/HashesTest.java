package dev.sam.common.crypto;

import static org.assertj.core.api.Assertions.assertThat;

import java.nio.charset.StandardCharsets;
import java.util.HexFormat;

import org.junit.jupiter.api.Test;

class HashesTest {

    @Test
    void sha256DeLaCadenaVaciaEsElValorConocido() {
        assertThat(HexFormat.of().formatHex(Hashes.sha256()))
            .isEqualTo("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    }

    @Test
    void sha256DeAbcEsElVectorDeFips180() {
        assertThat(HexFormat.of().formatHex(Hashes.sha256("abc".getBytes(StandardCharsets.US_ASCII))))
            .isEqualTo("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    }

    @Test
    void lasPartesSeConcatenanEnOrden() {
        var junto = Hashes.sha256("abc".getBytes(StandardCharsets.US_ASCII));
        var partes = Hashes.sha256("a".getBytes(StandardCharsets.US_ASCII), "bc".getBytes(StandardCharsets.US_ASCII));
        var alReves = Hashes.sha256("bc".getBytes(StandardCharsets.US_ASCII), "a".getBytes(StandardCharsets.US_ASCII));
        assertThat(partes).isEqualTo(junto);
        assertThat(alReves).isNotEqualTo(junto);
    }
}
