package com.reconhub.model;

import burp.api.montoya.http.message.HttpRequestResponse;

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
    private volatile int seen;             // number of requests in which this parameter appeared
    private volatile HttpRequestResponse messages;   // representative request/response

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
        this.seen++;
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

    public Location getLocation() { return location; }
    public String getName() { return name; }
    public String getEndpointKey() { return endpointKey; }
    public String getEndpointPath() { return endpointPath; }
    public String getExampleValue() { return exampleValue; }
    public boolean isReflected() { return reflected; }
    public int getSeen() { return seen; }
    public HttpRequestResponse getMessages() { return messages; }
}
