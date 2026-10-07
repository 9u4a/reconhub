package com.reconhub.model;

import burp.api.montoya.http.message.HttpRequestResponse;

import java.net.URI;

/**
 * A JavaScript file collected from traffic. Deduplicated by SHA-256 of its body, so the same
 * bundle served from multiple URLs is stored once.
 */
public final class JsAsset {

    private final String url;
    private final String sha256;
    private final int sizeBytes;
    private volatile int extractedEndpoints;
    private volatile int extractedSecrets;
    private volatile String savedPath = "";   // absolute path on disk, once written
    private volatile String preview = "";     // short identifying hint (sample endpoints or a snippet)
    private volatile HttpRequestResponse messages;   // null for a manually-imported local file
    private volatile String host;      // derived lazily from url -- see getHost()

    public JsAsset(String url, String sha256, int sizeBytes) {
        this.url = url;
        this.sha256 = sha256;
        this.sizeBytes = sizeBytes;
    }

    public String key() {
        return sha256;
    }

    public String getUrl() { return url; }

    /** Host of {@link #url}, lazily derived and cached (0.43.9) -- same pattern as
     * {@code ParameterInfo.getHost()}/{@code Finding.getHost()}: {@code url} is immutable, so this
     * only ever needs computing once per instance. Empty string, never null, when {@code url} is
     * null/blank/unparseable. */
    public String getHost() {
        String h = host;
        if (h == null) {
            h = deriveHost(url);
            host = h;
        }
        return h;
    }

    private static String deriveHost(String url) {
        if (url == null || url.isBlank()) {
            return "";
        }
        try {
            String h = URI.create(url).getHost();
            return h == null ? "" : h;
        } catch (RuntimeException ignored) {
            return "";
        }
    }

    public String getSha256() { return sha256; }
    public int getSizeBytes() { return sizeBytes; }
    public int getExtractedEndpoints() { return extractedEndpoints; }
    public int getExtractedSecrets() { return extractedSecrets; }
    public String getSavedPath() { return savedPath; }
    public String getPreview() { return preview; }
    public HttpRequestResponse getMessages() { return messages; }

    public void setExtractedEndpoints(int n) { this.extractedEndpoints = n; }
    public void setExtractedSecrets(int n) { this.extractedSecrets = n; }
    public void setSavedPath(String p) { this.savedPath = p; }
    public void setPreview(String p) { this.preview = p == null ? "" : p; }
    public void setMessages(HttpRequestResponse m) { this.messages = m; }
}
