package dev.sam.common.proto.auth;

/** Métodos de login (REQUERIMIENTOS.md 8.3, PROTOCOLO.md 5.3). */
public enum AuthMethod {
    PASSWORD, TOTP, PASSWORD_TOTP, GOOGLE, DISCORD
}
