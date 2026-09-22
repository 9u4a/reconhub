package com.reconhub.model;

import burp.api.montoya.http.message.HttpRequestResponse;

import java.net.URI;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * A deduplicated parameter observed on a specific endpoint.
 *
 * <p>Dedup key = endpoint + location + name, so the same {@code q} seen on {@code /search} and on
 * {@code /find} produces two rows (each tied to its own endpoint and representative message).
 */
public final class ParameterInfo {

    /** Where a parameter was found. */
    public enum Location { QUERY, BODY, JSON, COOKIE, HEADER }

    private final Location location;
    private final String name;
    private final String endpointKey;      // normalized URL of the owning endpoint
    private final String endpointPath;     // display-friendly path

    private volatile String exampleValue = "";
    private volatile boolean reflected;    // example value seen echoed back in a response
    // AtomicInteger, not `volatile int` -- see Endpoint.observations for why (bruteforce concurrency
    // races this against the ingest thread).
    private final AtomicInteger seen = new AtomicInteger();
    private volatile HttpRequestResponse messages;   // representative request/response
    private volatile String host;          // derived lazily from endpointKey

    public ParameterInfo(Location location, String name, String endpointKey, String endpointPath) {
        this.location = location;
        this.name = name;
        this.endpointKey = endpointKey;
        this.endpointPath = endpointPath;
    }

    public static String key(Location location, String name, String endpointKey) {
        return endpointKey + "|" + location + ":" + name;
    }

    public String key() {
        return key(location, name, endpointKey);
    }

    public void record(String value, boolean reflected, HttpRequestResponse messages) {
        this.seen.incrementAndGet();
        if (value != null && !value.isBlank() && this.exampleValue.isBlank()) {
            this.exampleValue = value.length() > 120 ? value.substring(0, 120) + "…" : value;
        }
        if (reflected) {
            this.reflected = true;
        }
        if (messages != null) {
            this.messages = messages;
        }
    }

    // ---- Restore setters (used by state import) -------------------------

    public void setExampleValue(String v) { this.exampleValue = v == null ? "" : v; }
    public void setReflected(boolean b) { this.reflected = b; }
    public void setSeen(int n) { this.seen.set(n); }
    public void setMessages(HttpRequestResponse m) { this.messages = m; }

    /** Host of the owning endpoint, parsed from {@code endpointKey} (empty if not derivable). */
    public String getHost() {
        String h = host;
        if (h == null) {
            h = deriveHost(endpointKey);
            host = h;
        }
        return h;
    }

    private static String deriveHost(String endpointKey) {
        if (endpointKey == null || endpointKey.isBlank()) {
            return "";
        }
        try {
            URI u = URI.create(endpointKey);
            if (u.getHost() != null) {
                return u.getHost();
            }
        } catch (RuntimeException ignored) {
            // non-URL key -> no host
        }
        return "";
    }

    public Location getLocation() { return location; }
    public String getName() { return name; }
    public String getEndpointKey() { return endpointKey; }
    public String getEndpointPath() { return endpointPath; }
    public String getExampleValue() { return exampleValue; }
    public boolean isReflected() { return reflected; }
    public int getSeen() { return seen.get(); }
    public HttpRequestResponse getMessages() { return messages; }
}
