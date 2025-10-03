import com.sun.net.httpserver.*;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.util.*;
import javax.naming.InitialContext; // usato indirettamente da log4j JNDI
import org.apache.logging.log4j.*;
import org.apache.logging.log4j.core.config.Configurator;

public class VulnApp {
    private static final Logger logger = LogManager.getLogger(VulnApp.class);

    public static void main(String[] args) throws Exception {
        // Log4j pattern che include il messaggio (dove arriva l’iniezione)
        System.setProperty("log4j2.formatMsgNoLookups", "false"); // abilita lookup su 2.14.1
        Configurator.initialize(null, (String) null);

        HttpServer server = HttpServer.create(new InetSocketAddress(8888), 0);
        server.createContext("/", new RootHandler());
        server.setExecutor(null);
        System.out.println("VulnApp up on :8080");
        server.start();
    }

    static class RootHandler implements HttpHandler {
        public void handle(HttpExchange ex) throws IOException {
            // Logga Header sensibili e query → se contengono ${jndi:ldap://...} scatta il lookup
            Headers h = ex.getRequestHeaders();
            String ua = first(h, "User-Agent");
            String xapi = first(h, "X-Api");
            String query = ex.getRequestURI().getQuery();

            logger.error("RootHandler UA: {}", ua);
            logger.error("RootHandler X-Api: {}", xapi);
            logger.error("RootHandler query: {}", query);

            // Logga anche tutti gli header (utile a Infection Monkey che mette il payload altrove)
            for (Map.Entry<String, List<String>> e : h.entrySet()) {
                logger.error("Hdr {}: {}", e.getKey(), e.getValue());
            }

            byte[] resp = "OK\n".getBytes();
            ex.sendResponseHeaders(200, resp.length);
            try (OutputStream os = ex.getResponseBody()) {
                os.write(resp);
            }
        }

        private String first(Headers h, String key) {
            List<String> v = h.get(key);
            return (v == null || v.isEmpty()) ? null : v.get(0);
        }
    }
}

