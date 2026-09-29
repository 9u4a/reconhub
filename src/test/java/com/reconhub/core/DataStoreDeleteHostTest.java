package com.reconhub.core;

import com.reconhub.model.Finding;
import com.reconhub.model.JsAsset;
import com.reconhub.model.ParameterInfo;
import org.junit.jupiter.api.Test;

import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** {@code DataStore.deleteHost} -- per-host bulk delete across all five collections. */
class DataStoreDeleteHostTest {

    private static DataStore populated() {
        DataStore store = new DataStore();
        // h.example: 2 endpoints, 1 parameter, 1 finding, 1 JS asset, 1 tech entry.
        store.recordEndpoint("GET", "h.example", "/a", "http://h.example/a", 200, "text/html",
                "sitemap", Set.of(), null, Set.of());
        store.recordEndpoint("GET", "h.example", "/b", "http://h.example/b", 200, "text/html",
                "sitemap", Set.of(), null, Set.of());
        store.recordParameter(ParameterInfo.Location.QUERY, "id", "1",
                "http://h.example/a", "/a", false, null);
        store.recordFinding(new Finding("Missing security headers", Finding.Severity.LOW,
                "missing-headers|h.example", "https://h.example", "X-Frame-Options", false));
        store.recordJsAsset(new JsAsset("http://h.example/app.js", "sha-h1", 100));
        store.techForHost("h.example");

        // other.example: 1 endpoint, 1 parameter, 1 finding, 1 JS asset, 1 tech entry -- must survive.
        store.recordEndpoint("GET", "other.example", "/x", "http://other.example/x", 200, "text/html",
                "sitemap", Set.of(), null, Set.of());
        store.recordParameter(ParameterInfo.Location.QUERY, "q", "1",
                "http://other.example/x", "/x", false, null);
        store.recordFinding(new Finding("Missing security headers", Finding.Severity.LOW,
                "missing-headers|other.example", "https://other.example", "X-Frame-Options", false));
        store.recordJsAsset(new JsAsset("http://other.example/app.js", "sha-o1", 100));
        store.techForHost("other.example");

        return store;
    }

    @Test
    void removesEveryCollectionForTheTargetHost() {
        DataStore store = populated();
        DataStore.HostDeleteResult r = store.deleteHost("h.example");

        assertEquals(2, r.endpoints());
        assertEquals(1, r.parameters());
        assertEquals(1, r.findings());
        assertEquals(1, r.jsAssets());
        assertTrue(r.tech());
    }

    @Test
    void otherHostsSurviveUntouched() {
        DataStore store = populated();
        store.deleteHost("h.example");

        assertTrue(store.snapshotEndpoints().stream().anyMatch(e -> "other.example".equals(e.getHost())));
        assertTrue(store.snapshotParameters().stream().anyMatch(p -> "other.example".equals(p.getHost())));
        assertTrue(store.snapshotFindings().stream()
                .anyMatch(f -> f.getLocationUrl() != null && f.getLocationUrl().contains("other.example")));
        assertTrue(store.snapshotJsAssets().stream().anyMatch(a -> a.getUrl().contains("other.example")));
        assertTrue(store.snapshotTech().stream().anyMatch(t -> "other.example".equals(t.getHost())));
    }

    @Test
    void deletedHostIsFullyGoneAfterward() {
        DataStore store = populated();
        store.deleteHost("h.example");

        assertFalse(store.snapshotEndpoints().stream().anyMatch(e -> "h.example".equals(e.getHost())));
        assertFalse(store.snapshotParameters().stream().anyMatch(p -> "h.example".equals(p.getHost())));
        assertFalse(store.snapshotFindings().stream()
                .anyMatch(f -> f.getLocationUrl() != null && f.getLocationUrl().contains("h.example")));
        assertFalse(store.snapshotJsAssets().stream().anyMatch(a -> a.getUrl().contains("h.example")));
        assertFalse(store.snapshotTech().stream().anyMatch(t -> "h.example".equals(t.getHost())));
        assertFalse(store.hostCounts().containsKey("h.example"));
    }

    @Test
    void snapshotCacheInvalidatesAfterDelete() {
        // Regression guard for the 0.35.0 mod-counter snapshot cache: deleteHost MUST bump the mod
        // counter for every collection it actually changed, or snapshot*() would keep serving a stale
        // cached list that still includes the deleted rows.
        DataStore store = populated();
        assertEquals(3, store.snapshotEndpoints().size());   // 2 h.example + 1 other.example
        store.deleteHost("h.example");
        assertEquals(1, store.snapshotEndpoints().size());
    }

    @Test
    void deletingAHostWithNoDataReturnsAllZeros() {
        DataStore store = populated();
        DataStore.HostDeleteResult r = store.deleteHost("never-seen.example");
        assertEquals(0, r.endpoints());
        assertEquals(0, r.parameters());
        assertEquals(0, r.findings());
        assertEquals(0, r.jsAssets());
        assertFalse(r.tech());
        // and nothing else was disturbed
        assertEquals(3, store.snapshotEndpoints().size());
    }

    @Test
    void nullOrBlankHostIsANoOp() {
        DataStore store = populated();
        int before = store.snapshotEndpoints().size();

        DataStore.HostDeleteResult nullResult = store.deleteHost(null);
        DataStore.HostDeleteResult blankResult = store.deleteHost("   ");

        assertEquals(0, nullResult.endpoints());
        assertEquals(0, blankResult.endpoints());
        assertEquals(before, store.snapshotEndpoints().size());
    }

    @Test
    void hostCountsEntryIsRemoved() {
        DataStore store = new DataStore();
        store.countRequest("h.example", 200, "text/html");
        assertTrue(store.hostCounts().containsKey("h.example"));

        store.deleteHost("h.example");
        assertFalse(store.hostCounts().containsKey("h.example"));
    }

    @Test
    void fireChangedIsCalledAfterDelete() {
        DataStore store = populated();
        boolean[] fired = {false};
        store.addChangeListener(() -> fired[0] = true);
        store.deleteHost("h.example");
        assertTrue(fired[0]);
    }

    // ---- deleteHosts (0.41.0 bulk version, backing deleteHost above) --------------------------------

    @Test
    void deleteHostsWithEmptySetIsANoOp() {
        DataStore store = populated();
        int before = store.snapshotEndpoints().size();

        DataStore.HostDeleteResult r = store.deleteHosts(Set.of());

        assertEquals(0, r.endpoints());
        assertFalse(r.tech());
        assertEquals(before, store.snapshotEndpoints().size());
    }

    @Test
    void deleteHostsWithNullSetIsANoOp() {
        DataStore store = populated();
        int before = store.snapshotEndpoints().size();
        DataStore.HostDeleteResult r = store.deleteHosts(null);
        assertEquals(0, r.endpoints());
        assertEquals(before, store.snapshotEndpoints().size());
    }

    @Test
    void deletingMultipleHostsAtOnceRemovesAllOfThem() {
        DataStore store = populated();
        DataStore.HostDeleteResult r = store.deleteHosts(Set.of("h.example", "other.example"));

        assertEquals(3, r.endpoints());    // 2 + 1
        assertEquals(2, r.parameters());
        assertEquals(2, r.findings());
        assertEquals(2, r.jsAssets());
        assertTrue(r.tech());
        assertTrue(store.snapshotEndpoints().isEmpty());
        assertTrue(store.snapshotTech().isEmpty());
    }

    @Test
    void deleteHostsIgnoresUnknownHostsMixedIntoTheSet() {
        DataStore store = populated();
        DataStore.HostDeleteResult r = store.deleteHosts(Set.of("h.example", "never-seen.example"));

        assertEquals(2, r.endpoints());   // only h.example's rows
        assertTrue(store.snapshotEndpoints().stream().anyMatch(e -> "other.example".equals(e.getHost())));
    }

    @Test
    void bulkDeleteMatchesSumOfSequentialSingleDeletes() {
        DataStore bulk = populated();
        DataStore sequential = populated();

        DataStore.HostDeleteResult bulkResult = bulk.deleteHosts(Set.of("h.example", "other.example"));
        DataStore.HostDeleteResult r1 = sequential.deleteHost("h.example");
        DataStore.HostDeleteResult r2 = sequential.deleteHost("other.example");

        assertEquals(r1.endpoints() + r2.endpoints(), bulkResult.endpoints());
        assertEquals(r1.parameters() + r2.parameters(), bulkResult.parameters());
        assertEquals(r1.findings() + r2.findings(), bulkResult.findings());
        assertEquals(r1.jsAssets() + r2.jsAssets(), bulkResult.jsAssets());
        assertEquals(r1.tech() || r2.tech(), bulkResult.tech());
    }
}
