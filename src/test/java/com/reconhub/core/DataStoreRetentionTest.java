package com.reconhub.core;

import com.reconhub.model.Finding;
import org.junit.jupiter.api.Test;

import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * {@code DataStore} optional retention cap (0.44.0) -- evicts the oldest rows past the cap, in
 * insertion order, bumping the snapshot mod counter so the next {@code snapshot*()} rebuilds. Pure
 * logic (models construct without a live Burp runtime; {@code messages} is passed null), so headless.
 */
class DataStoreRetentionTest {

    private static DataStore withEndpoints(int n) {
        DataStore store = new DataStore();
        for (int i = 0; i < n; i++) {
            store.recordEndpoint("GET", "h.example", "/p" + i, "http://h.example/p" + i, 200,
                    "text/html", "sitemap", Set.of(), null, Set.of());
        }
        return store;
    }

    @Test
    void capOfZeroMeansUnlimited() {
        DataStore store = new DataStore();   // default cap 0
        for (int i = 0; i < 50; i++) {
            store.recordEndpoint("GET", "h.example", "/p" + i, "http://h.example/p" + i, 200,
                    "text/html", "sitemap", Set.of(), null, Set.of());
        }
        assertEquals(50, store.snapshotEndpoints().size());
    }

    @Test
    void evictsOldestOverTheCap() {
        DataStore store = new DataStore();
        store.setMaxRetained(10);
        for (int i = 0; i < 25; i++) {
            store.recordEndpoint("GET", "h.example", "/p" + i, "http://h.example/p" + i, 200,
                    "text/html", "sitemap", Set.of(), null, Set.of());
        }
        var snap = store.snapshotEndpoints();
        assertEquals(10, snap.size());
        // The 10 survivors must be the newest (p15..p24); the oldest (p0..p14) are gone.
        boolean hasOldest = snap.stream().anyMatch(e -> e.getPath().equals("/p0"));
        boolean hasNewest = snap.stream().anyMatch(e -> e.getPath().equals("/p24"));
        assertFalse(hasOldest, "oldest row should have been evicted");
        assertTrue(hasNewest, "newest row must survive");
    }

    @Test
    void capIsPerCollectionNotShared() {
        DataStore store = new DataStore();
        store.setMaxRetained(5);
        for (int i = 0; i < 8; i++) {
            store.recordEndpoint("GET", "h.example", "/p" + i, "http://h.example/p" + i, 200,
                    "text/html", "sitemap", Set.of(), null, Set.of());
            store.recordFinding(new Finding("T", Finding.Severity.LOW, "m" + i,
                    "https://h.example/p" + i, "e", false));
        }
        assertEquals(5, store.snapshotEndpoints().size());
        assertEquals(5, store.snapshotFindings().size());
    }

    @Test
    void evictionBumpsModCounterSoSnapshotRebuilds() {
        DataStore store = new DataStore();
        store.setMaxRetained(3);
        for (int i = 0; i < 3; i++) {
            store.recordEndpoint("GET", "h.example", "/p" + i, "http://h.example/p" + i, 200,
                    "text/html", "sitemap", Set.of(), null, Set.of());
        }
        assertEquals(3, store.snapshotEndpoints().size());   // caches a snapshot at this mod
        // One more insert pushes over the cap -> an eviction happens in the same call.
        store.recordEndpoint("GET", "h.example", "/p9", "http://h.example/p9", 200,
                "text/html", "sitemap", Set.of(), null, Set.of());
        var snap = store.snapshotEndpoints();
        assertEquals(3, snap.size());
        assertTrue(snap.stream().anyMatch(e -> e.getPath().equals("/p9")), "newest must be present");
        assertFalse(snap.stream().anyMatch(e -> e.getPath().equals("/p0")), "oldest must be gone");
    }

    @Test
    void staleKeysFromDeleteHostAreSkippedNotCounted() {
        // Insert 6 rows across two hosts under a cap of 4, then deleteHost one host (leaving stale keys
        // in the order queue), then insert more -- eviction must drain the stale keys harmlessly and
        // still land the live collection exactly at the cap, never throwing or under/over-removing.
        DataStore store = new DataStore();
        store.setMaxRetained(4);
        for (int i = 0; i < 3; i++) {
            store.recordEndpoint("GET", "a.example", "/p" + i, "http://a.example/p" + i, 200,
                    "text/html", "sitemap", Set.of(), null, Set.of());
        }
        store.deleteHost("a.example");   // removes rows from the map, leaves their keys in the queue
        assertEquals(0, store.snapshotEndpoints().size());
        for (int i = 0; i < 10; i++) {
            store.recordEndpoint("GET", "b.example", "/q" + i, "http://b.example/q" + i, 200,
                    "text/html", "sitemap", Set.of(), null, Set.of());
        }
        var snap = store.snapshotEndpoints();
        assertEquals(4, snap.size());
        assertTrue(snap.stream().allMatch(e -> e.getHost().equals("b.example")));
        assertTrue(snap.stream().anyMatch(e -> e.getPath().equals("/q9")), "newest must survive");
    }

    @Test
    void loweringCapLaterEvictsOnNextInsert() {
        DataStore store = withEndpoints(20);   // cap off -> 20 kept
        assertEquals(20, store.snapshotEndpoints().size());
        store.setMaxRetained(5);
        // The cap applies to subsequently-recorded rows; one more insert enforces it down to the cap.
        store.recordEndpoint("GET", "h.example", "/pNew", "http://h.example/pNew", 200,
                "text/html", "sitemap", Set.of(), null, Set.of());
        assertEquals(5, store.snapshotEndpoints().size());
    }
}
