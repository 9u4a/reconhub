package com.reconhub.core;

import burp.api.montoya.http.message.HttpRequestResponse;
import com.reconhub.model.Endpoint;
import com.reconhub.model.Finding;
import com.reconhub.model.JsAsset;
import com.reconhub.model.ParameterInfo;
import com.reconhub.model.TechInfo;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Central, thread-safe in-memory model for everything ReconHub extracts.
 *
 * <p>Ingestion/analysis threads write here via the {@code record*} methods; the UI reads snapshots
 * via the {@code snapshot*} methods and subscribes to {@link ChangeListener} to refresh. Listener
 * callbacks are coalesced by the caller (UI schedules a repaint on the EDT).
 */
public final class DataStore {

    /** Notified (off the EDT) whenever the model changes. */
    public interface ChangeListener {
        void onDataChanged();
    }

    private final Map<String, Endpoint> endpoints = new ConcurrentHashMap<>();
    private final Map<String, ParameterInfo> parameters = new ConcurrentHashMap<>();
    private final Map<String, Finding> findings = new ConcurrentHashMap<>();
    private final Map<String, JsAsset> jsAssets = new ConcurrentHashMap<>();
    private final Map<String, TechInfo> techByHost = new ConcurrentHashMap<>();

    // Dashboard counters.
    private final AtomicInteger requestsProcessed = new AtomicInteger();
    private final Map<Integer, AtomicInteger> statusCodeCounts = new ConcurrentHashMap<>();
    private final Map<String, AtomicInteger> hostCounts = new ConcurrentHashMap<>();
    private final Map<String, AtomicInteger> contentTypeCounts = new ConcurrentHashMap<>();

    private final List<ChangeListener> listeners = new CopyOnWriteArrayList<>();

    public void addChangeListener(ChangeListener l) {
        listeners.add(l);
    }

    public void fireChanged() {
        for (ChangeListener l : listeners) {
            try {
                l.onDataChanged();
            } catch (RuntimeException ignored) {
                // A misbehaving listener must not break ingestion.
            }
        }
    }

    // ---- Endpoints -------------------------------------------------------

    public Endpoint recordEndpoint(String method, String host, String path,
                                   String normalizedUrl, int status, String contentType,
                                   String source, java.util.Set<String> paramNames,
                                   HttpRequestResponse messages, java.util.Set<String> origins) {
        Endpoint ep = endpoints.computeIfAbsent(
                Endpoint.key(method, normalizedUrl),
                k -> new Endpoint(method, host, path, normalizedUrl));
        ep.recordObservation(status, contentType, source, messages);
        ep.addParamNames(paramNames);
        ep.addOrigins(origins);
        return ep;
    }

    // ---- Parameters ------------------------------------------------------

    public void recordParameter(ParameterInfo.Location loc, String name, String value,
                                String endpointKey, String endpointPath, boolean reflected,
                                HttpRequestResponse messages) {
        parameters.computeIfAbsent(
                        ParameterInfo.key(loc, name, endpointKey),
                        k -> new ParameterInfo(loc, name, endpointKey, endpointPath))
                .record(value, reflected, messages);
    }

    // ---- Findings --------------------------------------------------------

    /** @return true if this was a new (previously unseen) finding. */
    public boolean recordFinding(Finding f) {
        Finding existing = findings.putIfAbsent(f.key(), f);
        if (existing != null) {
            existing.incrementSeen();
            return false;
        }
        return true;
    }

    // ---- JS assets -------------------------------------------------------

    /** @return the stored asset (existing if the hash was already seen, else the new one). */
    public JsAsset recordJsAsset(JsAsset asset) {
        JsAsset existing = jsAssets.putIfAbsent(asset.key(), asset);
        return existing != null ? existing : asset;
    }

    public boolean hasJsAsset(String sha256) {
        return jsAssets.containsKey(sha256);
    }

    // ---- Tech ------------------------------------------------------------

    public TechInfo techForHost(String host) {
        return techByHost.computeIfAbsent(host, TechInfo::new);
    }

    // ---- Dashboard counters ---------------------------------------------

    public void countRequest(String host, int status, String contentType) {
        requestsProcessed.incrementAndGet();
        if (host != null) {
            hostCounts.computeIfAbsent(host, k -> new AtomicInteger()).incrementAndGet();
        }
        if (status > 0) {
            statusCodeCounts.computeIfAbsent(status, k -> new AtomicInteger()).incrementAndGet();
        }
        if (contentType != null && !contentType.isBlank()) {
            String ct = contentType.split(";")[0].trim();
            contentTypeCounts.computeIfAbsent(ct, k -> new AtomicInteger()).incrementAndGet();
        }
    }

    // ---- Snapshots (for UI / export) ------------------------------------

    public List<Endpoint> snapshotEndpoints() {
        List<Endpoint> l = new ArrayList<>(endpoints.values());
        l.sort(Comparator.comparing(Endpoint::getHost).thenComparing(Endpoint::getPath));
        return l;
    }

    public List<ParameterInfo> snapshotParameters() {
        List<ParameterInfo> l = new ArrayList<>(parameters.values());
        l.sort(Comparator.comparing(ParameterInfo::getEndpointPath)
                .thenComparing(ParameterInfo::getName));
        return l;
    }

    public List<Finding> snapshotFindings() {
        List<Finding> l = new ArrayList<>(findings.values());
        l.sort(Comparator.comparingInt((Finding f) -> f.getSeverity().ordinal())
                .thenComparing(Finding::getType));
        return l;
    }

    public List<JsAsset> snapshotJsAssets() {
        List<JsAsset> l = new ArrayList<>(jsAssets.values());
        l.sort(Comparator.comparing(JsAsset::getUrl));
        return l;
    }

    public List<TechInfo> snapshotTech() {
        List<TechInfo> l = new ArrayList<>(techByHost.values());
        l.sort(Comparator.comparing(TechInfo::getHost));
        return l;
    }

    public int getRequestsProcessed() { return requestsProcessed.get(); }

    public Map<Integer, Integer> statusCodeCounts() {
        return flatten(statusCodeCounts);
    }

    public Map<String, Integer> hostCounts() {
        return flatten(hostCounts);
    }

    public Map<String, Integer> contentTypeCounts() {
        return flatten(contentTypeCounts);
    }

    private static <K> Map<K, Integer> flatten(Map<K, AtomicInteger> src) {
        Map<K, Integer> out = new java.util.LinkedHashMap<>();
        src.entrySet().stream()
                .sorted((a, b) -> Integer.compare(b.getValue().get(), a.getValue().get()))
                .forEach(e -> out.put(e.getKey(), e.getValue().get()));
        return out;
    }

    /** Clears every collection and counter (used by the "Clear" button). */
    public void clear() {
        endpoints.clear();
        parameters.clear();
        findings.clear();
        jsAssets.clear();
        techByHost.clear();
        requestsProcessed.set(0);
        statusCodeCounts.clear();
        hostCounts.clear();
        contentTypeCounts.clear();
        fireChanged();
    }
}
