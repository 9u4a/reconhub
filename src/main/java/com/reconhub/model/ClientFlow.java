package com.reconhub.model;

import burp.api.montoya.http.message.HttpRequestResponse;

import java.net.URI;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * A Client Flow (0.59.0): one API request the front-end code sends -- method, path template, body/query
 * keys, auth source -- plus where it comes from (enclosing function, triggering route/handler, JS file).
 * Deduped by {@link #key()} = method + path template, so the same call site in several bundles/chunks is
 * one row. Derived from JS only: never serialized (recomputed from stored JS on state import).
 */
public final class ClientFlow {

    private final String method;
    private final String path;          // path template, e.g. /api/users/{id} (or an absolute URL template)
    private final String host;          // target host: the template's own host, else the JS file's host
    private final Set<String> bodyKeys = Collections.synchronizedSet(new LinkedHashSet<>());
    private final Set<String> queryKeys = Collections.synchronizedSet(new LinkedHashSet<>());
    private final Set<String> jsUrls = Collections.synchronizedSet(new LinkedHashSet<>());
    private volatile String auth = "";
    private volatile String function = "";
    private volatile String trigger = "";
    private volatile String via = "";
    private volatile String callSite = "";
    private volatile String jsUrl = "";   // first JS file seen (for the code view)
    private volatile boolean secure = true;
    private volatile HttpRequestResponse messages;   // the JS file's exchange, for the code view
    private volatile Pattern pathPattern;            // lazily compiled Seen matcher

    public ClientFlow(String method, String path, String host) {
        this.method = method == null ? "GET" : method;
        this.path = path == null ? "" : path;
        this.host = host == null ? "" : host;
    }

    public String key() {
        return method + " " + path;
    }

    /** Merges one more sighting of the same call (another bundle / call site). First non-empty wins. */
    public void merge(List<String> body, List<String> query, String authSource, String fn, String trig,
                      String viaText, String site, String fromJsUrl, boolean secureJs, HttpRequestResponse msgs) {
        if (body != null) bodyKeys.addAll(body);
        if (query != null) queryKeys.addAll(query);
        if (fromJsUrl != null && !fromJsUrl.isEmpty()) jsUrls.add(fromJsUrl);
        if (auth.isEmpty() && authSource != null) auth = authSource;
        if (function.isEmpty() && fn != null) function = fn;
        if (trigger.isEmpty() && trig != null) trigger = trig;
        if (via.isEmpty() && viaText != null) via = viaText;
        if (callSite.isEmpty() && site != null) callSite = site;
        if (jsUrl.isEmpty() && fromJsUrl != null) {
            jsUrl = fromJsUrl;
            secure = secureJs;
        }
        if (messages == null) messages = msgs;
    }

    public String getMethod() { return method; }
    public String getPath() { return path; }
    public String getHost() { return host; }
    public List<String> getBodyKeys() { synchronized (bodyKeys) { return List.copyOf(bodyKeys); } }
    public List<String> getQueryKeys() { synchronized (queryKeys) { return List.copyOf(queryKeys); } }
    public List<String> getJsUrls() { synchronized (jsUrls) { return List.copyOf(jsUrls); } }
    public String getAuth() { return auth; }
    public String getFunction() { return function; }
    public String getTrigger() { return trigger; }
    public String getVia() { return via; }
    public String getCallSite() { return callSite; }
    public String getJsUrl() { return jsUrl; }
    public boolean isSecure() { return secure; }
    public HttpRequestResponse getMessages() { return messages; }

    /** The template's path part (scheme+host dropped, leading '/'). */
    public String pathOnly() {
        String p = path;
        int scheme = p.indexOf("://");
        if (scheme >= 0) {
            int slash = p.indexOf('/', scheme + 3);
            p = slash < 0 ? "/" : p.substring(slash);
        }
        if (!p.startsWith("/")) p = "/" + p;
        return p;
    }

    /** Regex for {@link #pathOnly()} with each {@code {x}} placeholder matching one path segment. */
    public Pattern pathPattern() {
        Pattern p = pathPattern;
        if (p == null) {
            StringBuilder sb = new StringBuilder("^");
            String t = pathOnly();
            while (t.length() > 1 && t.endsWith("/")) t = t.substring(0, t.length() - 1);
            int i = 0;
            while (i < t.length()) {
                int open = t.indexOf('{', i);
                if (open < 0) {
                    sb.append(Pattern.quote(t.substring(i)));
                    break;
                }
                int close = t.indexOf('}', open);
                if (close < 0) {
                    sb.append(Pattern.quote(t.substring(i)));
                    break;
                }
                if (open > i) sb.append(Pattern.quote(t.substring(i, open)));
                sb.append("[^/]+");
                i = close + 1;
            }
            sb.append("/?$");
            p = Pattern.compile(sb.toString());
            pathPattern = p;
        }
        return p;
    }

    /** Host of an absolute template, else null. */
    public static String hostOf(String template) {
        if (template == null || !(template.startsWith("http://") || template.startsWith("https://"))) {
            return null;
        }
        try {
            String clean = template.replaceAll("\\{[^}]{0,60}}", "x");
            return URI.create(clean).getHost();
        } catch (RuntimeException e) {
            return null;
        }
    }
}
