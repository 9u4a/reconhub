package com.reconhub.core;

import burp.api.montoya.http.message.HttpRequestResponse;
import com.reconhub.model.Endpoint;
import com.reconhub.model.Finding;
import com.reconhub.model.JsAsset;
import com.reconhub.model.ParameterInfo;
import com.reconhub.model.TechInfo;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Predicate;

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

    // ---- Snapshot cache ---------------------------------------------------
    // Each snapshot*() below used to copy + sort its whole collection on every single call. The sort
    // keys (host/path/name/url/severity/type) are all immutable once a row is created, so a cached
    // sorted list stays correctly sorted no matter how a row's OTHER fields mutate afterwards -- only a
    // change to the KEY SET (a new/removed entry) can invalidate it. Mutating an existing entry (e.g.
    // Endpoint.recordObservation, TechInfo.addTechnology) must NOT bump the counter.

    /** A sorted snapshot plus the modification counter it was built from (one volatile read pairs the
     * two atomically). */
    private static final class Snap<T> {
        final int mod;
        final List<T> list;
        Snap(int mod, List<T> list) { this.mod = mod; this.list = list; }
    }

    private final AtomicInteger endpointsMod = new AtomicInteger();
    private final AtomicInteger parametersMod = new AtomicInteger();
    private final AtomicInteger findingsMod = new AtomicInteger();
    private final AtomicInteger jsAssetsMod = new AtomicInteger();
    private final AtomicInteger techMod = new AtomicInteger();

    private volatile Snap<Endpoint> endpointsSnap = new Snap<>(-1, List.of());
    private volatile Snap<ParameterInfo> parametersSnap = new Snap<>(-1, List.of());
    private volatile Snap<Finding> findingsSnap = new Snap<>(-1, List.of());
    private volatile Snap<JsAsset> jsAssetsSnap = new Snap<>(-1, List.of());
    private volatile Snap<TechInfo> techSnap = new Snap<>(-1, List.of());

    // Dashboard counters.
    private final AtomicInteger requestsProcessed = new AtomicInteger();
    private final Map<Integer, AtomicInteger> statusCodeCounts = new ConcurrentHashMap<>();
    private final Map<String, AtomicInteger> hostCounts = new ConcurrentHashMap<>();
    private final Map<String, AtomicInteger> contentTypeCounts = new ConcurrentHashMap<>();

    private final List<ChangeListener> listeners = new CopyOnWriteArrayList<>();

    public void addChangeListener(ChangeListener l) {
        listeners.add(l);
    }

    /** Detaches a listener previously added via {@link #addChangeListener} (0.43.8) -- added so
     * {@code MainTab} can unregister itself on extension unload; there was previously no way to, so
     * every reload accumulated one more permanently-registered listener on a {@code DataStore} that
     * also has no removal path of its own otherwise. */
    public void removeChangeListener(ChangeListener l) {
        listeners.remove(l);
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
                k -> { endpointsMod.incrementAndGet(); return new Endpoint(method, host, path, normalizedUrl); });
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
                        k -> { parametersMod.incrementAndGet();
                               return new ParameterInfo(loc, name, endpointKey, endpointPath); })
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
        findingsMod.incrementAndGet();
        return true;
    }

    // ---- JS assets -------------------------------------------------------

    /** @return the stored asset (existing if the hash was already seen, else the new one). */
    public JsAsset recordJsAsset(JsAsset asset) {
        JsAsset existing = jsAssets.putIfAbsent(asset.key(), asset);
        if (existing != null) {
            return existing;
        }
        jsAssetsMod.incrementAndGet();
        return asset;
    }

    public boolean hasJsAsset(String sha256) {
        return jsAssets.containsKey(sha256);
    }

    // ---- Tech ------------------------------------------------------------

    public TechInfo techForHost(String host) {
        return techByHost.computeIfAbsent(host, h -> { techMod.incrementAndGet(); return new TechInfo(h); });
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

    // ---- Restore (state import) -----------------------------------------

    public void restoreEndpoint(Endpoint e) { endpoints.put(e.key(), e); endpointsMod.incrementAndGet(); }
    public void restoreParameter(ParameterInfo p) { parameters.put(p.key(), p); parametersMod.incrementAndGet(); }
    public void restoreFinding(Finding f) { findings.put(f.key(), f); findingsMod.incrementAndGet(); }
    public void restoreJsAsset(JsAsset a) { jsAssets.put(a.key(), a); jsAssetsMod.incrementAndGet(); }
    public void restoreTech(TechInfo t) { techByHost.put(t.key(), t); techMod.incrementAndGet(); }

    public void restoreCounters(int requests, Map<Integer, Integer> status,
                                Map<String, Integer> hosts, Map<String, Integer> ctypes) {
        requestsProcessed.set(requests);
        putCounts(statusCodeCounts, status);
        putCounts(hostCounts, hosts);
        putCounts(contentTypeCounts, ctypes);
    }

    private static <K> void putCounts(Map<K, AtomicInteger> target, Map<K, Integer> src) {
        if (src == null) {
            return;
        }
        for (Map.Entry<K, Integer> e : src.entrySet()) {
            target.computeIfAbsent(e.getKey(), k -> new AtomicInteger()).set(e.getValue());
        }
    }

    // ---- Snapshots (for UI / export) ------------------------------------

    // 0.43.8: every snapshotX() used to `return new ArrayList<>(snap.list)` -- a fresh, independently-
    // mutable copy per call, on top of the cache rebuild this already avoids when nothing changed.
    // Traced all ~30 call sites across ui/export/active: none mutate the returned list (all either
    // iterate it, stream it, or copy it again themselves). Collections.unmodifiableList is free (no
    // copy) and keeps the original intent -- a caller can't corrupt the shared cached list -- while
    // actually strengthening it: a future caller that DID try to mutate it would now get an immediate
    // UnsupportedOperationException instead of silently corrupting the cache other callers share.

    public List<Endpoint> snapshotEndpoints() {
        // mod read BEFORE building: a concurrent insert during the build just means the NEXT call sees
        // snap.mod != mod and rebuilds -- this can never serve a snapshot older than what was live when
        // the call started.
        int mod = endpointsMod.get();
        Snap<Endpoint> snap = endpointsSnap;
        if (snap.mod != mod) {
            List<Endpoint> l = new ArrayList<>(endpoints.values());
            l.sort(Comparator.comparing(Endpoint::getHost).thenComparing(Endpoint::getPath));
            snap = new Snap<>(mod, l);
            endpointsSnap = snap;
        }
        return Collections.unmodifiableList(snap.list);
    }

    public List<ParameterInfo> snapshotParameters() {
        int mod = parametersMod.get();
        Snap<ParameterInfo> snap = parametersSnap;
        if (snap.mod != mod) {
            List<ParameterInfo> l = new ArrayList<>(parameters.values());
            l.sort(Comparator.comparing(ParameterInfo::getHost)
                    .thenComparing(ParameterInfo::getEndpointPath)
                    .thenComparing(ParameterInfo::getName));
            snap = new Snap<>(mod, l);
            parametersSnap = snap;
        }
        return Collections.unmodifiableList(snap.list);
    }

    public List<Finding> snapshotFindings() {
        int mod = findingsMod.get();
        Snap<Finding> snap = findingsSnap;
        if (snap.mod != mod) {
            List<Finding> l = new ArrayList<>(findings.values());
            l.sort(Comparator.comparingInt((Finding f) -> f.getSeverity().ordinal())
                    .thenComparing(Finding::getType));
            snap = new Snap<>(mod, l);
            findingsSnap = snap;
        }
        return Collections.unmodifiableList(snap.list);
    }

    public List<JsAsset> snapshotJsAssets() {
        int mod = jsAssetsMod.get();
        Snap<JsAsset> snap = jsAssetsSnap;
        if (snap.mod != mod) {
            List<JsAsset> l = new ArrayList<>(jsAssets.values());
            l.sort(Comparator.comparing(JsAsset::getUrl));
            snap = new Snap<>(mod, l);
            jsAssetsSnap = snap;
        }
        return Collections.unmodifiableList(snap.list);
    }

    public List<TechInfo> snapshotTech() {
        int mod = techMod.get();
        Snap<TechInfo> snap = techSnap;
        if (snap.mod != mod) {
            List<TechInfo> l = new ArrayList<>(techByHost.values());
            l.sort(Comparator.comparing(TechInfo::getHost));
            snap = new Snap<>(mod, l);
            techSnap = snap;
        }
        return Collections.unmodifiableList(snap.list);
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

    // ---- Per-host delete --------------------------------------------------

    /** Counts of what {@link #deleteHost} actually removed, for a confirmation/summary message. */
    public record HostDeleteResult(int endpoints, int parameters, int findings, int jsAssets, boolean tech) {}

    /**
     * Removes every {@link Endpoint}/{@link ParameterInfo}/{@link Finding}/{@link JsAsset}/{@link
     * TechInfo} attributed to {@code host}, plus its {@link #hostCounts} entry. Only ReconHub's own
     * model is touched -- Burp's Proxy History/Site Map is never affected.
     *
     * <p><b>Deliberately does not touch {@code Bookmarks}</b> -- same reasoning as {@link #clear()} not
     * touching it (user-authored data, kept in a separate class specifically so bulk-delete operations
     * here can't reach it). A bookmark on a now-removed row becomes an orphan (its key simply never
     * matches a row again) -- harmless, but not cleaned up automatically.
     *
     * <p>{@code requestsProcessed}/{@code statusCodeCounts}/{@code contentTypeCounts} are also left
     * alone -- there's no way to accurately subtract one host's contribution back out of those running
     * totals after the fact.
     */
    public HostDeleteResult deleteHost(String host) {
        if (host == null || host.isBlank()) {
            return new HostDeleteResult(0, 0, 0, 0, false);
        }
        return deleteHosts(Set.of(host));
    }

    /**
     * Bulk version of {@link #deleteHost} -- removes every row attributed to any host in {@code hosts}.
     * Scans each of the 5 collections exactly once regardless of how many hosts are given, instead of
     * once per host (0.41.0: the previous "call {@link #deleteHost} in a loop" pattern used by {@code
     * SettingsPanel.doRemoveOutOfScope} was O(hosts &times; rows) -- a real cost once a whole site map
     * has been ingested and both host count and row count are large). Mod-counter and {@code
     * Bookmarks}-preservation semantics are identical to {@link #deleteHost}.
     */
    public HostDeleteResult deleteHosts(Set<String> hosts) {
        if (hosts == null || hosts.isEmpty()) {
            return new HostDeleteResult(0, 0, 0, 0, false);
        }
        int ep = removeIf(endpoints, e -> hosts.contains(e.getHost()));
        int pm = removeIf(parameters, p -> hosts.contains(p.getHost()));
        int fd = removeIf(findings, f -> hosts.contains(Hosts.of(f.getLocationUrl())));
        int js = removeIf(jsAssets, a -> hosts.contains(Hosts.of(a.getUrl())));
        boolean tech = false;
        for (String host : hosts) {
            if (techByHost.remove(host) != null) {
                tech = true;
            }
        }
        // Mod counters bump only when the key set actually changed for that collection -- same
        // invariant as every record*/restore* method above (0.35.0's snapshot-cache design).
        if (ep > 0) {
            endpointsMod.incrementAndGet();
        }
        if (pm > 0) {
            parametersMod.incrementAndGet();
        }
        if (fd > 0) {
            findingsMod.incrementAndGet();
        }
        if (js > 0) {
            jsAssetsMod.incrementAndGet();
        }
        if (tech) {
            techMod.incrementAndGet();
        }
        hostCounts.keySet().removeAll(hosts);
        fireChanged();
        return new HostDeleteResult(ep, pm, fd, js, tech);
    }

    private static <T> int removeIf(Map<String, T> map, Predicate<T> pred) {
        int[] n = {0};
        // ConcurrentHashMap's values() view supports removeIf as a weakly-consistent bulk operation --
        // safe alongside concurrent record*() calls on the ingest thread.
        map.values().removeIf(v -> {
            if (pred.test(v)) {
                n[0]++;
                return true;
            }
            return false;
        });
        return n[0];
    }

    /** Clears every collection and counter (used by the "Clear" button). */
    public void clear() {
        endpoints.clear();
        parameters.clear();
        findings.clear();
        jsAssets.clear();
        techByHost.clear();
        endpointsMod.incrementAndGet();
        parametersMod.incrementAndGet();
        findingsMod.incrementAndGet();
        jsAssetsMod.incrementAndGet();
        techMod.incrementAndGet();
        requestsProcessed.set(0);
        statusCodeCounts.clear();
        hostCounts.clear();
        contentTypeCounts.clear();
        fireChanged();
    }
}
