package com.reconhub.analysis;

import burp.api.montoya.http.message.HttpRequestResponse;
import com.google.gson.Gson;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.reconhub.core.DataStore;
import com.reconhub.model.Finding;
import com.reconhub.model.ParameterInfo;
import org.yaml.snakeyaml.LoaderOptions;
import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.constructor.SafeConstructor;

import java.net.URI;
import java.util.LinkedHashSet;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * Passive API-surface discovery from already-captured responses:
 *
 * <ul>
 *   <li><b>OpenAPI / Swagger</b> — parses {@code paths} into endpoints (source {@code "spec"}) and
 *       their query/header/cookie parameters, and records an INFO finding that a spec is exposed.
 *       Handles both JSON specs and <b>YAML specs</b> (e.g. {@code /openapi.yaml}) — a common format
 *       Burp/JSON-only tooling tends to miss entirely; YAML is parsed with a {@link SafeConstructor}
 *       (no arbitrary class instantiation) since the body comes from the target, then converted to a
 *       {@link JsonElement} tree so the same path/parameter walk handles both formats.
 *   <li><b>GraphQL</b> — flags a GraphQL endpoint, and raises a MEDIUM finding when a response exposes
 *       {@code __schema} (introspection enabled).
 * </ul>
 *
 * <p>Everything here reads content that was already captured; it never sends a request to a target.
 */
public final class ApiSpecAnalyzer {

    private static final int MAX_BODY = 5_000_000;   // don't parse absurdly large bodies
    private static final Set<String> HTTP_METHODS =
            Set.of("get", "put", "post", "delete", "options", "head", "patch", "trace");
    // No arbitrary class instantiation from untrusted (target-controlled) YAML.
    private static final Yaml SAFE_YAML = new Yaml(new SafeConstructor(new LoaderOptions()));
    // Matched against the first few characters only -- the two root keys every OpenAPI/Swagger YAML
    // starts with. Lowercasing (and regex-scanning) the WHOLE body just to read its first ~10 chars
    // allocated a full copy of every non-JSON response, including every JS bundle.
    private static final int SPEC_HEAD_CHARS = 32;
    private static final Pattern YAML_SPEC_HEAD = Pattern.compile("(?i)^(?:openapi|swagger)\\s{0,8}:");

    private final DataStore store;

    public ApiSpecAnalyzer(DataStore store) {
        this.store = store;
    }

    public void analyze(String url, String contentType, String body, HttpRequestResponse rr) {
        if (body == null || body.isEmpty() || body.length() > MAX_BODY) {
            return;
        }
        String ct = contentType == null ? "" : contentType.toLowerCase(Locale.ROOT);
        String trimmed = body.stripLeading();
        boolean jsonish = ct.contains("json") || trimmed.startsWith("{");
        // Only worth trying YAML when it isn't already JSON-shaped, and it looks like an OpenAPI/
        // Swagger root (starts with "openapi:"/"swagger:", the two top-level keys every such spec has).
        String head = trimmed.length() > SPEC_HEAD_CHARS ? trimmed.substring(0, SPEC_HEAD_CHARS) : trimmed;
        boolean yamlish = !jsonish && (ct.contains("yaml") || YAML_SPEC_HEAD.matcher(head).find());

        // --- OpenAPI / Swagger (JSON) -------------------------------------
        if (jsonish && body.contains("\"paths\"")
                && (body.contains("\"openapi\"") || body.contains("\"swagger\""))) {
            try {
                JsonElement rootEl = JsonParser.parseString(body);
                if (rootEl.isJsonObject()) {
                    parseOpenApi(rootEl.getAsJsonObject(), url, rr);
                }
            } catch (RuntimeException ignored) {
                // malformed / unexpected shape -> skip silently
            }
        } else if (yamlish && body.contains("paths:")
                && (body.contains("openapi:") || body.contains("swagger:"))) {
            // --- OpenAPI / Swagger (YAML) ---------------------------------
            try {
                Object yamlRoot = SAFE_YAML.load(body);
                JsonElement rootEl = new Gson().toJsonTree(yamlRoot);
                if (rootEl.isJsonObject()) {
                    parseOpenApi(rootEl.getAsJsonObject(), url, rr);
                }
            } catch (RuntimeException ignored) {
                // malformed YAML / unexpected shape -> skip silently
            }
        }

        // --- GraphQL ------------------------------------------------------
        if (url.toLowerCase(Locale.ROOT).contains("graphql")) {
            record(new Finding("GraphQL endpoint", Finding.Severity.INFO,
                    "graphql|" + hostKey(url), url, "graphql", false), rr);
        }
        if (jsonish && body.contains("\"__schema\"") && body.contains("\"types\"")) {
            record(new Finding("GraphQL introspection enabled", Finding.Severity.MEDIUM,
                    "gql-introspection|" + hostKey(url), url, "introspection on", false), rr);
        }
    }

    // ---- OpenAPI / Swagger ---------------------------------------------

    private void parseOpenApi(JsonObject root, String specUrl, HttpRequestResponse rr) {
        JsonObject paths = optObject(root, "paths");
        if (paths == null) {
            return;
        }

        String base = baseAuthority(specUrl);          // scheme://host[:port]
        String host = hostOnly(specUrl);
        String basePath = optString(root, "basePath");  // Swagger 2.0
        String kind = root.has("openapi") ? "OpenAPI " + optString(root, "openapi")
                : "Swagger " + optString(root, "swagger");

        int endpointCount = 0;
        for (Map.Entry<String, JsonElement> pe : paths.entrySet()) {
            if (!pe.getValue().isJsonObject()) {
                continue;
            }
            JsonObject item = pe.getValue().getAsJsonObject();
            String fullPath = joinPath(basePath, pe.getKey());
            String normalized = base + fullPath;

            // Path-level parameters apply to every operation on this path.
            Set<String> pathLevel = paramNames(item.get("parameters"));

            for (Map.Entry<String, JsonElement> oe : item.entrySet()) {
                String method = oe.getKey().toLowerCase(Locale.ROOT);
                if (!HTTP_METHODS.contains(method) || !oe.getValue().isJsonObject()) {
                    continue;
                }
                JsonObject op = oe.getValue().getAsJsonObject();

                Set<String> names = new LinkedHashSet<>(pathLevel);
                names.addAll(paramNames(op.get("parameters")));

                store.recordEndpoint(method.toUpperCase(Locale.ROOT), host, fullPath, normalized,
                        0, "", "spec", names, null, Set.of());
                recordParams(item.get("parameters"), normalized, fullPath);
                recordParams(op.get("parameters"), normalized, fullPath);
                endpointCount++;
            }
        }

        if (endpointCount > 0) {
            record(new Finding("API spec exposed", Finding.Severity.INFO, "spec|" + specUrl, specUrl,
                    kind.trim() + ", " + endpointCount + " ops", false), rr);
        }
    }

    private void recordParams(JsonElement paramsEl, String endpointKey, String endpointPath) {
        if (paramsEl == null || !paramsEl.isJsonArray()) {
            return;
        }
        for (JsonElement el : paramsEl.getAsJsonArray()) {
            if (!el.isJsonObject()) {
                continue;
            }
            JsonObject p = el.getAsJsonObject();
            String name = optString(p, "name");
            if (name.isEmpty()) {
                continue;   // $ref-only params can't be resolved here
            }
            ParameterInfo.Location loc = switch (optString(p, "in").toLowerCase(Locale.ROOT)) {
                case "query" -> ParameterInfo.Location.QUERY;
                case "header" -> ParameterInfo.Location.HEADER;
                case "cookie" -> ParameterInfo.Location.COOKIE;
                case "body", "formdata" -> ParameterInfo.Location.BODY;
                default -> null;   // e.g. "path" — no matching bucket, skip
            };
            if (loc != null) {
                store.recordParameter(loc, name, null, endpointKey, endpointPath, false, null);
            }
        }
    }

    private static Set<String> paramNames(JsonElement paramsEl) {
        Set<String> names = new LinkedHashSet<>();
        if (paramsEl != null && paramsEl.isJsonArray()) {
            for (JsonElement el : paramsEl.getAsJsonArray()) {
                if (el.isJsonObject()) {
                    String n = optString(el.getAsJsonObject(), "name");
                    if (!n.isEmpty()) {
                        names.add(n);
                    }
                }
            }
        }
        return names;
    }

    // ---- helpers --------------------------------------------------------

    private void record(Finding f, HttpRequestResponse rr) {
        f.setMessages(rr);
        store.recordFinding(f);
    }

    private static String joinPath(String basePath, String path) {
        String bp = basePath == null ? "" : basePath.trim();
        if (bp.equals("/")) {
            bp = "";
        }
        String p = path == null ? "" : path.trim();
        if (!p.startsWith("/") && !bp.endsWith("/")) {
            p = "/" + p;
        }
        String joined = bp + p;
        return joined.isEmpty() ? "/" : joined;
    }

    private static String baseAuthority(String url) {
        try {
            URI u = URI.create(url);
            if (u.getScheme() != null && u.getHost() != null) {
                String auth = u.getScheme() + "://" + u.getHost();
                int port = u.getPort();
                if (port > 0 && !isDefaultPort(u.getScheme(), port)) {
                    auth += ":" + port;
                }
                return auth;
            }
        } catch (RuntimeException ignored) {
            // fall through
        }
        return "";
    }

    private static String hostOnly(String url) {
        try {
            URI u = URI.create(url);
            return u.getHost() != null ? u.getHost() : "";
        } catch (RuntimeException e) {
            return "";
        }
    }

    private static String hostKey(String url) {
        String h = hostOnly(url);
        return h.isEmpty() ? url : h;
    }

    private static boolean isDefaultPort(String scheme, int port) {
        return ("http".equalsIgnoreCase(scheme) && port == 80)
                || ("https".equalsIgnoreCase(scheme) && port == 443);
    }

    private static JsonObject optObject(JsonObject o, String key) {
        JsonElement e = o.get(key);
        return e != null && e.isJsonObject() ? e.getAsJsonObject() : null;
    }

    private static String optString(JsonObject o, String key) {
        JsonElement e = o.get(key);
        return e != null && e.isJsonPrimitive() ? e.getAsString() : "";
    }
}
