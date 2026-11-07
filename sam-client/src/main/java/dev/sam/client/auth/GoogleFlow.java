package dev.sam.client.auth;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.nio.charset.StandardCharsets;
import java.util.Optional;

import dev.sam.client.SamClient;
import dev.sam.common.oauth.LoopbackRedirect;
import dev.sam.common.proto.account.OAuthCode;
import dev.sam.common.proto.account.OAuthProvider;
import dev.sam.common.proto.account.OAuthStart;
import net.minecraft.Util;
import net.minecraft.client.Minecraft;

/**
 * "Entrar con Google" o vincularlo, del lado del cliente (REQUERIMIENTOS 5.5, pasos 3 y 4): abre un
 * servidor HTTP efímero en 127.0.0.1, pide la URL al servidor, abre el navegador del sistema y reenvía
 * el {@code code} que llega con el {@code state} correcto. Acepta un solo request y se cierra
 * (RS-OAUTH-03). Solo abre URLs de Google: un servidor no puede usar esto para abrir otra página.
 */
public final class GoogleFlow {

    /** Prefijo exacto de las URLs que el cliente acepta abrir. */
    static final String GOOGLE_PREFIX = "https://accounts.google.com/";
    private static final int WAIT_MS = 300_000;
    private static final int REQUEST_MS = 5_000;
    private static final int MAX_REQUEST_LINE = 8 * 1024;

    /** Cómo habla con el servidor (en configuration o en play) y cómo avisa a la pantalla. */
    public interface Callbacks {
        void sendStart(OAuthStart start);

        void sendCode(OAuthCode code);

        void failed(String reason);
    }

    private static GoogleFlow current;

    private final ServerSocket socket;
    private final Callbacks callbacks;

    private GoogleFlow(ServerSocket socket, Callbacks callbacks) {
        this.socket = socket;
        this.callbacks = callbacks;
    }

    /** Abre el loopback y pide la URL; el resto sigue cuando llega {@code sam:oauth_url}. */
    public static synchronized void begin(Callbacks callbacks) {
        cancel();
        try {
            var socket = new ServerSocket(0, 1, InetAddress.getLoopbackAddress());
            current = new GoogleFlow(socket, callbacks);
            callbacks.sendStart(new OAuthStart(OAuthProvider.GOOGLE, socket.getLocalPort()));
        } catch (IOException e) {
            callbacks.failed("No se pudo preparar el inicio de sesión con Google: " + e.getMessage());
        }
    }

    /** Llegó la URL de autorización: se abre el navegador y se espera el redirect. */
    public static synchronized void onUrl(String url) {
        var flow = current;
        if (flow == null) {
            return;
        }
        var state = LoopbackRedirect.stateOf(url);
        if (!url.startsWith(GOOGLE_PREFIX) || state.isEmpty()) {
            SamClient.LOGGER.warn("[SAM] El servidor mandó una URL de OAuth que no es de Google: no se abre");
            cancel();
            flow.callbacks.failed("El servidor mandó una dirección que no es de Google.");
            return;
        }
        var thread = new Thread(() -> flow.await(state.get()), "SAM OAuth loopback");
        thread.setDaemon(true);
        thread.start();
        Util.getPlatform().openUri(url);
    }

    public static synchronized void cancel() {
        if (current != null) {
            current.close();
            current = null;
        }
    }

    private void await(String state) {
        try {
            socket.setSoTimeout(WAIT_MS);
            // Algunos navegadores abren conexiones especulativas sin request: se ignoran. Si no llega
            // nada en WAIT_MS, accept lanza SocketTimeoutException y el flujo termina.
            while (true) {
                try (var client = socket.accept()) {
                    client.setSoTimeout(REQUEST_MS);
                    var target = requestTarget(client.getInputStream());
                    if (target.isEmpty()) {
                        continue;
                    }
                    var code = LoopbackRedirect.code(target.get(), state);
                    respond(client, code.isPresent());
                    var minecraft = Minecraft.getInstance();
                    if (code.isPresent()) {
                        minecraft.execute(() -> callbacks.sendCode(new OAuthCode(code.get(), state)));
                    } else {
                        minecraft.execute(() -> callbacks.failed("Google no confirmó el inicio de sesión."));
                    }
                    return;
                }
            }
        } catch (IOException e) {
            if (!socket.isClosed()) {
                Minecraft.getInstance().execute(() -> callbacks.failed("Se acabó el tiempo para iniciar sesión con Google."));
            }
        } finally {
            close();
        }
    }

    /** {@code GET <target> HTTP/1.1}: solo la primera línea; vacío si no llegó una. */
    private static Optional<String> requestTarget(InputStream in) throws IOException {
        var line = new StringBuilder();
        int b;
        try {
            while ((b = in.read()) != -1 && b != '\n') {
                if (line.length() >= MAX_REQUEST_LINE) {
                    return Optional.empty();
                }
                line.append((char) b);
            }
        } catch (SocketTimeoutException silent) {
            return Optional.empty();
        }
        var parts = line.toString().strip().split(" ");
        return parts.length == 3 && parts[0].equals("GET") ? Optional.of(parts[1]) : Optional.empty();
    }

    private static void respond(Socket client, boolean ok) throws IOException {
        var body = "<!doctype html><meta charset=utf-8><title>SAM</title><body style=\"font-family:sans-serif;text-align:center;"
            + "margin-top:15vh;background:#16161a;color:#eee\"><h2>" + (ok ? "Listo" : "No se pudo completar") + "</h2><p>"
            + (ok ? "Ya puedes cerrar esta pestaña y volver a Minecraft." : "Vuelve a Minecraft e inténtalo de nuevo.")
            + "</p></body>";
        var bytes = body.getBytes(StandardCharsets.UTF_8);
        OutputStream out = client.getOutputStream();
        out.write(("HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: " + bytes.length
            + "\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n").getBytes(StandardCharsets.US_ASCII));
        out.write(bytes);
        out.flush();
    }

    private void close() {
        try {
            socket.close();
        } catch (IOException ignored) {
            // ya estaba cerrado
        }
    }
}
