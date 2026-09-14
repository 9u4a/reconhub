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
    private volatile HttpRequestResponse messages;   // representative request/response (latest, if any)

    public Endpoint(String method, String host, String path, String normalizedUrl) {
        this.method = method;
        this.host = host;
        this.path = path;
        this.normalizedUrl = normalizedUrl;
        this.firstSeenEpochMs = System.currentTimeMillis();
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
    public HttpRequestResponse getMessages() { return messages; }
}
