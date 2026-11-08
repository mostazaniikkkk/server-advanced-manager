# Hardening de SAM: brechas frente a ISO 27001 y SOC 2

Análisis del 2026-11-08 del código de SAM (0.3.0) y del servidor operado (QA Server SAM) frente a:

- **ISO/IEC 27001:2022**, Anexo A;
- **SOC 2**, Trust Services Criteria: Security (CC), Availability (A) y Confidentiality (C).

SAM es un producto y no una organización, así que aquí solo entran los controles técnicos que el mod y su operación pueden cumplir. Los controles organizacionales (RR. HH., proveedores, gestión del SGSI) quedan fuera.

Cada brecha tiene un id `H-xx`, una prioridad y el control que cubre:

- **P1**: explotable hoy o requisito ya escrito que no está implementado. Va primero.
- **P2**: endurece algo que ya funciona.
- **P3**: proceso y documentación.

Las brechas marcadas **[operador]** tocan el equipo o el servidor del operador. Se aplican solo con su decisión.

## 1. Lo que ya cumple

| Control | Evidencia |
|---|---|
| A.8.5 autenticación segura / CC6.1 | Argon2id en cliente (64 MiB, t=3) y servidor (19 MiB, t=2), comparación en tiempo constante, TOTP RFC 6238 con anti-replay, códigos de respaldo hasheados |
| A.8.24 criptografía / CC6.7 | TLS 1.3 solo AEAD, ALPN `sam/1`, identidad Ed25519 con pinning y rotación firmada; TOTP sellado con AES-256-GCM |
| A.5.33 / C1.1 secretos | `SAM_DATA_KEY` y `SAM_IDENTITY_PASSPHRASE` solo desde el entorno del proceso (el arranque falla si están en el `.env`); `.env` y `accounts.json` solo para el dueño, escritura atómica |
| A.8.20-8.22 red / CC6.6 | Límites de conexiones sin clasificar (8 por IP, 256 en total), topes de tamaño por paquete, IP real solo desde proxies de confianza |
| A.8.26-8.28 desarrollo seguro / CC8.1 | Sandbox Lua por lista blanca con batería de scripts maliciosos; capacidades por manifest exigidas en `ScriptHost`; scripts firmados con confirmación por consola |
| A.8.8 / CC7.1 cadena de suministro (parcial) | Versiones fijas, `verification-metadata.xml` con SHA-256, wrapper con `distributionSha256Sum` |
| A.8.29 pruebas | JaCoCo al 90 % y PIT al 100 % en sam-common y sam-signer, propiedades con jqwik |

## 2. Brechas

### Control de acceso y privilegios (A.5.15, A.5.18, A.8.2, A.8.5 / CC6.1-6.3)

| Id | P | Brecha |
|---|---|---|
| H-01 | ✅ | **Cerrada 2026-11-08** (mixin sobre `getProfilePermissions`, RF-ADM-04): el nivel de OP solo vale con el 2FA completado en la sesión; si no, nivel 0. Verificado en un clon: un OP sin 2FA no puede usar `/gamemode`, uno con 2FA sí
| H-02 | ✅ | **Cerrada 2026-11-08** (RF-ADM-03a): un admin (ops ≥ `SAM_ADMIN_OP_LEVEL` o `sam.admin`) sin TOTP recibe `NEED_ENROLL` y la pantalla "Activar 2FA" en el login; el primer código válido lo activa y entra con la sesión verificada. Verificado en un clon (enrolamiento, login verificado y `/gamemode`)
| H-03 | ✅ | **Cerrada 2026-11-08** (`LoginThrottle`, RF-AUTH-06a): bloqueo exponencial por (cuenta, IP) que sobrevive a la reconexión, global de cuenta más suave, logins pendientes por IP y globales, cola de Argon2 de 64 (`SAM-K005`). Verificado en un clon: la segunda conexión se rechaza antes de Argon2. Pendiente: los fallos de contraseña en "Opciones de cuenta" (en juego) todavía usan su propio contador
| H-04 | ✅ | **Cerrada 2026-11-08** (RF-ADM-05a, `SessionClock`): la sesión verificada de un admin vence a las `SAM_POLICY_ADMIN_SESSION_TTL` (12 h) y apaga sus poderes con aviso; cualquier sesión dura como mucho `SAM_POLICY_DEFAULT_SESSION_TTL` (7 d). Verificado en un clon con 30 s y 60 s |
| H-05 | ✅ | **Cerrada 2026-11-08**: todo `/sam scripts` exige el criterio de comando sensible (consola o admin verificado). Verificado en un clon |
| H-06 | ✅ | **Cerrada 2026-11-08** (RN-45): mínimo 8 por defecto (NIST SP 800-63B), el cliente rechaza las ~96.000 contraseñas más usadas (lista del NCSC vía SecLists) y las que contienen el nick, con el motivo a la vista. Verificado en pantalla
| H-07 | ✅ | **Cerrada 2026-11-08** (PERMISOS.md): un admin en el juego no puede cambiar permisos que le aplican a él (su entrada, sus grupos, los heredados o `default`); se rechaza y se audita. Verificado en un clon |

### Registro y monitoreo (A.8.15, A.8.16 / CC7.2-7.3)

| Id | P | Brecha |
|---|---|---|
| H-08 | ✅ | **Cerrada 2026-11-08** (`AuditLog` + `SamAudit`, RF-AUTH-08a): `config/sam/audit.jsonl` encadenado por SHA-256 y solo del dueño, `/sam audit verify|last|export` como comandos sensibles, cabeza de la cadena en el log al arrancar. Verificado en un clon y con un verificador independiente en Python
| H-09 | ✅ | **Cerrada 2026-11-08** (RF-ADM-06a): intentos fallidos y logins con IP y motivo; cada cambio de `/sam perms` con el JSON de antes y después; los comandos de `SAM_AUDIT_COMMANDS` (también dentro de `execute ... run`) de jugadores, consola y RCON. Verificado en un clon
| H-10 | ✅ | **Cerrada 2026-11-08** (van a `config/sam/secretos-sugeridos.txt`, solo del dueño). Antes: **secretos en el log**: los valores sugeridos de `SAM_IDENTITY_PASSPHRASE` y `SAM_DATA_KEY` se escriben en `latest.log` y en sus archivos rotados |
| H-11 | P2 | `SAM_AUDIT_IP_RETENTION` está documentada pero no se usa: no hay retención |

### Protección de datos (A.8.10-8.12, A.8.24, A.5.34 / C1.1-1.2)

| Id | P | Brecha |
|---|---|---|
| H-12 | ✅ | **Cerrada 2026-11-08** (`SecureFiles`, RF-CFG-10). Antes: **permisos de archivos**: `identity.p12`, `permissions.json`, los `.dat` de scripts y el trust store se escriben sin restringirlos al dueño. En el cliente, `pins.json` y los consentimientos tampoco |
| H-13 | ✅ | **Cerrada 2026-11-08** (RF-CFG-12, `FieldCipher`): correo y `sub` de Google cifrados con AES-256-GCM y AAD por campo y cuenta; los valores viejos en claro se migran al guardar; sin la clave el archivo no abre. Verificado en un clon |
| H-14 | ✅ | **Cerrada 2026-11-08** (RF-CFG-12, `KeyRing`): id de clave en los valores, `SAM_DATA_KEY_PREVIOUS` para leer durante la rotación y `sam datakey rotate` (solo consola) para volver a cifrar 2FA, correos y Google con la nueva. Verificado en un clon: rotación completa y login con 2FA con solo la clave nueva |
| H-15 | ✅ | **Cerrada 2026-11-08** (RF-AUTH-07e): "Exportar datos" y "Borrar cuenta" en Opciones de cuenta, con contraseña y 2FA; el export trae la cuenta, los permisos y su auditoría; el borrado (y `sam auth reset`) quita la cuenta, sus permisos y avisa a los scripts con `erase` (SAM Basics borra homes y conversaciones). Los fallos de contraseña en Opciones de cuenta usan el mismo bloqueo que el login. Verificado en un clon |

### Continuidad y respaldo (A.8.13, A.5.30 / A1.2-1.3)

| Id | P | Brecha |
|---|---|---|
| H-16 | ✅ | **Cerrada 2026-11-08** (RF-CFG-11): `backup.ps1` arma el respaldo en una carpeta temporal solo del dueño y lo cifra con `sam-signer backup-seal` (AES-256-GCM por bloques, `SAM_BACKUP_KEY`), con `.sha256` al lado; `restore.ps1` verifica, descifra y extrae en una carpeta nueva. Restauración probada en un clon (archivos idénticos; con otra clave no abre). Los 2 zips viejos en claro se cifraron (verificados) y se borraron; el operador define `SAM_BACKUP_KEY` en su entorno
| H-17 | P2 [operador] | El respaldo vive en el mismo disco que el servidor; no hay copia fuera del equipo |

### Desarrollo seguro y cadena de suministro (A.8.8, A.8.25-8.29, A.8.32 / CC7.1, CC8.1)

| Id | P | Brecha |
|---|---|---|
| H-18 | P2 | Sin escaneo de vulnerabilidades de dependencias ni SBOM (RN-38) |
| H-19 | P2 | Sin CI: PIT y las pruebas de QA no son una barrera obligatoria, y sam-server y sam-client no tienen pruebas unitarias ni `-Werror` |
| H-20 | P2 | Sin análisis estático (SpotBugs o Error Prone) |
| H-21 | P2 | Releases sin checksums ni firma, y jars no reproducibles (RNF-06, RN-39) |
| H-22 | P3 | Los ganchos `sam.dev.*` viajan en el jar de release (protegidos por `isDevelopmentEnvironment`). Conviene quitarlos al compilar |

### Operación del servidor (A.8.9, A.8.31 / CC6.6, CC7.1) [operador]

| Id | P | Brecha |
|---|---|---|
| H-23 | ✅ [operador] | **Cerrada 2026-11-08** con la decisión del operador: la passphrase y `identity.p12` de QA Server SAM quedaron solo para su usuario (`icacls`, sin herencia). Los archivos nuevos ya nacen así (H-12)
| H-24 | P2 [operador] | RCON está activo, con la contraseña en claro en `server.properties`. Hoy escucha solo en 127.0.0.1 |
| H-25 | P2 [operador] | Con WebSocket detrás de Cloudflare, `SAM_TCP_ENABLED=true` deja una entrada directa que se salta el CDN |
| H-26 | P3 [operador] | QA y producción son el mismo servidor y el mismo directorio |

### Políticas e incidentes (A.5.24-5.28, A.5.37 / CC7.3-7.5, CC2.3)

| Id | P | Brecha |
|---|---|---|
| H-27 | P3 | Sin `SECURITY.md` (divulgación de vulnerabilidades), runbook de incidentes ni CHANGELOG |
| H-28 | P3 | Los procedimientos (rotación de claves, restauración, alta de admins) están dispersos o no existen |

## 3. Plan

En el orden de las prioridades, un ciclo TDD por brecha de código, con PIT al 100 %:

1. **P1 de código**: H-10, H-12, H-03, H-01 y H-02, H-08 y H-09, H-16 (el script de respaldo).
2. **P1 del operador**: H-23, con la decisión del operador.
3. **P2** de código, y después **P3**.

El estado de cada brecha se actualiza en este documento al cerrarla.

## 4. Decisiones del operador (2026-11-08)

| Tema | Decisión |
|---|---|
| H-01, H-02 | **Sin 2FA no es OP**: el nivel de OP solo vale después de completar el 2FA en esa sesión; antes, el admin juega como jugador normal. Los admins deben activar 2FA al entrar |
| H-16 | **Respaldo cifrado con clave propia**: AES-256-GCM con una clave de respaldo que llega como variable de entorno, hash de integridad y un comando de restauración probado |
| H-18 a H-21 | **GitHub Actions**: build, pruebas, PIT, escaneo de dependencias, SBOM y checksums de release |
| [operador] | Se pregunta una por una antes de cada cambio en el equipo o el servidor |
| H-18 a H-21 (push) | Se sube a GitHub al terminar el hardening completo y se verifica que el workflow pase |
| H-17 | **Riesgo aceptado por el operador**: los respaldos cifrados quedan en el mismo equipo |
| H-24 | RCON se mantiene solo en 127.0.0.1, con una contraseña nueva larga y `server.properties` solo para el usuario del servidor |
| H-25, H-26 | **Fuera del alcance**: cómo se usa y se expone el servidor lo decide el operador |
