package com.reconhub.analysis;

import com.reconhub.model.ClientFlow;
import com.reconhub.model.Endpoint;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Pure helpers for Client Flows (0.59.0): the Lead type + hint (IDOR / no-auth), the Seen matcher against
 * captured endpoints, and the Repeater request template. No Montoya -- headless-tested.
 */
public final class ClientFlowLeads {

    public static final String TYPE = "Client Flow";
    public static final String TYPE_IDOR = "Client Flow: IDOR candidate";
    public static final String TYPE_NO_AUTH = "Client Flow: no auth in call";

    private static final Pattern PLACEHOLDER = Pattern.compile("\\{([^}/]{1,60})}");
    private static final Pattern NUMERIC_SEGMENT = Pattern.compile("/\\d{1,19}(?=/|$)");
    /** camelCase / snake_case object-id suffixes the whole-name IDOR class misses (memberNo, board_seq). */
    private static final Pattern ID_SUFFIX = Pattern.compile("(?:[a-z0-9](?:Id|ID|No|Seq|Idx)|_(?:id|no|seq|idx))$");

    private ClientFlowLeads() {}

    /** The flow's Lead type: IDOR candidate first (object-id shaped parameter), then no-auth, else plain. */
    public static String type(ClientFlow f) {
        if (idorParam(f) != null) return TYPE_IDOR;
        if (f.getAuth() == null || f.getAuth().isEmpty()) return TYPE_NO_AUTH;
        return TYPE;
    }

    /** How-to-test hint for the flow (from {@code finding-hints.json} by type), naming the ID parameter. */
    public static String hint(ClientFlow f) {
        String type = type(f);
        String base = FindingHints.forType(type);
        String id = idorParam(f);
        if (TYPE_IDOR.equals(type) && id != null) {
            return "change " + id + " to another user's value -- " + base;
        }
        return base;
    }

    /** The first object-id shaped parameter (path placeholder, numeric segment, body or query key), or null. */
    public static String idorParam(ClientFlow f) {
        Matcher m = PLACEHOLDER.matcher(f.getPath());
        while (m.find()) {
            if (isIdName(m.group(1))) return "{" + m.group(1) + "}";
        }
        if (NUMERIC_SEGMENT.matcher(f.pathOnly()).find()) return "the numeric path segment";
        for (String k : f.getQueryKeys()) {
            if (isIdName(k)) return k;
        }
        for (String k : f.getBodyKeys()) {
            if (isIdName(k)) return k;
        }
        return null;
    }

    static boolean isIdName(String name) {
        if (name == null || name.isEmpty()) return false;
        return ParameterClassifier.classifyCached(name).contains("IDOR") || ID_SUFFIX.matcher(name).find();
    }

    // ---- Seen ---------------------------------------------------------------------------

    /** Captured endpoints that answered (status != 0), indexed by method for {@link #find}. */
    public static final class SeenIndex {
        private final Map<String, List<Object[]>> byMethod = new HashMap<>();   // method -> {path, endpoint}

        public Endpoint find(ClientFlow f) {
            List<Object[]> rows = byMethod.get(f.getMethod().toUpperCase(Locale.ROOT));
            if (rows == null) return null;
            Pattern p = f.pathPattern();
            for (Object[] r : rows) {
                if (p.matcher((String) r[0]).matches()) return (Endpoint) r[1];
            }
            return null;
        }
    }

    public static SeenIndex index(List<Endpoint> endpoints) {
        SeenIndex idx = new SeenIndex();
        for (Endpoint e : endpoints) {
            if (e.getLastStatusCode() == 0 || e.getMethod() == null) continue;
            idx.byMethod.computeIfAbsent(e.getMethod().toUpperCase(Locale.ROOT), k -> new ArrayList<>())
                    .add(new Object[]{JsAnalyzer.routePath(e.getPath()), e});
        }
        return idx;
    }

    // ---- Repeater template ---------------------------------------------------------------

    /** A request to place in Repeater (never sent by ReconHub): target + raw HTTP/1.1 text. */
    public record Template(String host, int port, boolean secure, String raw) {}

    public static Template template(ClientFlow f) {
        String host = f.getHost();
        boolean secure = f.isSecure();
        int port = -1;
        String path = f.getPath();
        if (path.startsWith("http://") || path.startsWith("https://")) {
            secure = path.startsWith("https://");
            int start = path.indexOf("://") + 3;
            int slash = path.indexOf('/', start);
            String authority = slash < 0 ? path.substring(start) : path.substring(start, slash);
            int colon = authority.lastIndexOf(':');
            if (colon > 0) {
                try {
                    port = Integer.parseInt(authority.substring(colon + 1));
                    authority = authority.substring(0, colon);
                } catch (NumberFormatException ignored) {
                    // keep the default port
                }
            }
            host = authority;
        }
        if (port < 0) port = secure ? 443 : 80;
        StringBuilder target = new StringBuilder(f.pathOnly());
        List<String> q = f.getQueryKeys();
        for (int i = 0; i < q.size(); i++) {
            target.append(i == 0 ? '?' : '&').append(q.get(i)).append('=');
        }
        StringBuilder raw = new StringBuilder();
        raw.append(f.getMethod()).append(' ').append(target).append(" HTTP/1.1\r\n");
        raw.append("Host: ").append(host).append("\r\n");
        raw.append("Accept: application/json, text/plain, */*\r\n");
        String auth = f.getAuth() == null ? "" : f.getAuth();
        String authHeader = auth.contains(" ") ? auth.substring(0, auth.indexOf(' ')) : auth;
        if (!authHeader.isEmpty() && !authHeader.startsWith("cookies")) {
            raw.append(authHeader).append(": ").append("<token>").append("\r\n");
        }
        List<String> body = f.getBodyKeys();
        boolean hasBody = !body.isEmpty() || f.getMethod().matches("POST|PUT|PATCH");
        String json = "";
        if (hasBody) {
            StringBuilder sb = new StringBuilder("{");
            for (int i = 0; i < body.size(); i++) {
                if (i > 0) sb.append(',');
                sb.append('"').append(body.get(i).replace("\"", "")).append("\":\"\"");
            }
            json = sb.append('}').toString();
            raw.append("Content-Type: application/json\r\n");
            raw.append("Content-Length: ").append(json.getBytes(java.nio.charset.StandardCharsets.UTF_8).length)
                    .append("\r\n");
        }
        raw.append("\r\n").append(json);
        return new Template(host, port, secure, raw.toString());
    }
}
