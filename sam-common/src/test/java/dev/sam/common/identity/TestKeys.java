package dev.sam.common.identity;

import java.util.HexFormat;

import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters;
import org.bouncycastle.crypto.signers.Ed25519Signer;

/** Claves Ed25519 deterministas para tests. K1, K2 y K3 son las de la RFC 8032 §7.1. */
final class TestKeys {

    static final byte[] SPKI_PREFIX = HexFormat.of().parseHex("302a300506032b6570032100");

    static final TestKey K1 = fromSeed("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");
    static final TestKey K2 = fromSeed("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb");
    static final TestKey K3 = fromSeed("c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7");

    private TestKeys() {
    }

    static TestKey fromSeed(String hexSeed) {
        return fromSeed(HexFormat.of().parseHex(hexSeed));
    }

    static TestKey fromSeed(byte[] seed) {
        var priv = new Ed25519PrivateKeyParameters(seed, 0);
        var raw = priv.generatePublicKey().getEncoded();
        var spki = new byte[SPKI_PREFIX.length + raw.length];
        System.arraycopy(SPKI_PREFIX, 0, spki, 0, SPKI_PREFIX.length);
        System.arraycopy(raw, 0, spki, SPKI_PREFIX.length, raw.length);
        return new TestKey(priv, spki);
    }

    record TestKey(Ed25519PrivateKeyParameters priv, byte[] spki) {

        ServerPublicKey publicKey() {
            return ServerPublicKey.fromSpki(spki);
        }

        byte[] sign(byte[] message) {
            var signer = new Ed25519Signer();
            signer.init(true, priv);
            signer.update(message, 0, message.length);
            return signer.generateSignature();
        }
    }
}
