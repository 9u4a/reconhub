package com.reconhub.model;

import burp.api.montoya.http.message.HttpRequestResponse;

import java.util.Collections;
import java.util.Set;
import java.util.TreeSet;
import java.util.concurrent.ConcurrentHashMap;

/**
 * A deduplicated endpoint observed in traffic (or discovered inside JS).
 *
 * <p>Dedup key = HTTP method + normalized URL (scheme://host[:port]/path, query values
 * stripped but parameter names retained). See {@link #key(String, String)}.
 */
public final class Endpoint {

    private final String method;      // GET, POST, ... or "JS" for JS-discovered links
    private final String host;
    private final String path;        // path only, no query
    private final String normalizedUrl;

    // Mutable, aggregated across all observations of this endpoint.
    private volatile int lastStatusCode;
    private volatile String contentType = "";
    private final Set<String> paramNames = Collections.newSetFromMap(new ConcurrentHashMap<>());
    private final Set<String> sources = Collections.newSetFromMap(new ConcurrentHashMap<>()); // "proxy","sitemap","js"
    private final Set<String> origins = Collections.newSetFromMap(new ConcurrentHashMap<>()); // JS files a JS-link was found in
    private final long firstSeenEpochMs;
    private volatile int observations;
    private volatile boolean authObserved;    // seen at least once with Authorization/Cookie
    private volatile boolean anonObserved;    // seen at least once with no credentials
    private volatile HttpRequestResponse messages;   // representative request/response (latest, if any)

    public Endpoint(String method, String host, String path, String normalizedUrl) {
        this(method, host, path, normalizedUrl, System.currentTimeMillis());
    }

    /** Restore constructor: preserves the original first-seen timestamp on import. */
    public Endpoint(String method, String host, String path, String normalizedUrl,
                    long firstSeenEpochMs) {
        this.method = method;
        this.host = host;
        this.path = path;
        this.normalizedUrl = normalizedUrl;
        this.firstSeenEpochMs = firstSeenEpochMs;
    }

    /** Stable dedup key for a (method, normalizedUrl) pair. */
    public static String key(String method, String normalizedUrl) {
        return method + " " + normalizedUrl;
    }

    public String key() {
        return key(method, normalizedUrl);
    }

    public void recordObservation(int statusCode, String contentType, String source,
                                  HttpRequestResponse messages) {
        this.observations++;
        if (statusCode > 0) {
            this.lastStatusCode = statusCode;
        }
        if (contentType != null && !contentType.isBlank()) {
            this.contentType = contentType;
        }
        if (source != null) {
            this.sources.add(source);
        }
        if (messages != null) {
            this.messages = messages;
        }
    }

    /** Records whether a given observation of this endpoint carried credentials. */
    public void recordAuth(boolean authed) {
        if (authed) {
            this.authObserved = true;
        } else {
            this.anonObserved = true;
        }
    }

    public void addParamNames(Set<String> names) {
        if (names != null) {
            paramNames.addAll(names);
        }
    }

    public void addOrigins(Set<String> jsUrls) {
        if (jsUrls != null) {
            origins.addAll(jsUrls);
        }
    }

    // ---- Restore setters (used by state import) -------------------------

    public void addSources(Set<String> s) {
        if (s != null) {
            sources.addAll(s);
        }
    }

    public void setLastStatusCode(int code) { this.lastStatusCode = code; }
    public void setContentType(String ct) { this.contentType = ct == null ? "" : ct; }
    public void setObservations(int n) { this.observations = n; }
    public void setAuthObserved(boolean b) { this.authObserved = b; }
    public void setAnonObserved(boolean b) { this.anonObserved = b; }
    public void setMessages(HttpRequestResponse m) { this.messages = m; }

    public String getMethod() { return method; }
    public String getHost() { return host; }
    public String getPath() { return path; }
    public String getNormalizedUrl() { return normalizedUrl; }
    public int getLastStatusCode() { return lastStatusCode; }
    public String getContentType() { return contentType; }
    public int getParamCount() { return paramNames.size(); }
    public Set<String> getParamNames() { return new TreeSet<>(paramNames); }
    public Set<String> getSources() { return new TreeSet<>(sources); }
    public Set<String> getOrigins() { return new TreeSet<>(origins); }
    public long getFirstSeenEpochMs() { return firstSeenEpochMs; }
    public int getObservations() { return observations; }
    public boolean isAuthObserved() { return authObserved; }
    public boolean isAnonObserved() { return anonObserved; }

    /** Credential exposure of this endpoint's observations: auth / anon / both / (none seen). */
    public String authStatus() {
        if (authObserved && anonObserved) {
            return "both";
        }
        if (authObserved) {
            return "auth";
        }
        if (anonObserved) {
            return "anon";
        }
        return "";
    }

    public HttpRequestResponse getMessages() { return messages; }
}
