package dev.sam.common.proto.auth;

/** Estado del nick en el servidor (PROTOCOLO.md 5.1); revelarlo es inherente al flujo (R-ACC-02). */
public enum AccountState {
    NEW, REGISTERED, RESERVED
}
