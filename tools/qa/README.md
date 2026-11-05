# Herramientas de QA (Windows / PowerShell 5.1)

- `qa-run.ps1`: QA de punta a punta. Instala `sam-server` en el servidor QA local, lo arranca, espera
  `Done (` (con corte ante crash o log trabado), corre `gradlew :sam-server:qaTest` y lo detiene por RCON.
  Uso: `powershell -File tools\qa\qa-run.ps1 [-ServerDir <ruta>] [-SkipInstall]`. Deja los logs en `build\qa`.
- `gradle-watch.ps1`: corre `gradlew` vigilando el log; si deja de avanzar, toma un volcado de hilos
  (`jstack`) del daemon para diagnosticar dónde se trabó.
- `rcon.ps1`: cliente RCON mínimo; lee puerto y contraseña del `server.properties` del servidor.

Requisitos: JDK 25 (Gradle con Loom 1.19 lo exige; el código se compila para Java 21) y un servidor QA con
`enable-rcon=true`. Las rutas por defecto (JDK, servidor) se pueden cambiar por parámetro.
Los scripts se guardan en UTF-8 **con BOM**: sin BOM, Windows PowerShell 5.1 los lee como ANSI.