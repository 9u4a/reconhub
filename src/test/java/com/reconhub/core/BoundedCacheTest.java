package com.reconhub.core;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** {@code BoundedCache} -- the fix for 0.43.2's "search gets laggy once data accumulates" bug (see its
 * class javadoc: a char-count-bounded cache that used to clear itself entirely on every overflow,
 * forcing a full re-decode of every row on the very next search once enough data had built up). Pure
 * logic (plain Strings weighed by length), headless. */
class BoundedCacheTest {

    private static BoundedCache<String, String> cache(int maxWeight) {
        return new BoundedCache<>(maxWeight, String::length);
    }

    @Test
    void getOnAMissingKeyIsNull() {
        BoundedCache<String, String> c = cache(100);
        assertNull(c.get("nope"));
    }

    @Test
    void putThenGetReturnsTheValue() {
        BoundedCache<String, String> c = cache(100);
        c.put("a", "hello");
        assertEquals("hello", c.get("a"));
        assertEquals(1, c.size());
    }

    @Test
    void staysUnderBudgetWithoutEvictingAnythingWhenThereIsRoom() {
        BoundedCache<String, String> c = cache(100);
        c.put("a", "12345");
        c.put("b", "67890");
        assertEquals(2, c.size());
        assertEquals("12345", c.get("a"));
        assertEquals("67890", c.get("b"));
    }

    @Test
    void evictsOnlyAsManyLeastRecentlyUsedEntriesAsNeeded_notEverything() {
        // Budget 25: "aaaaaaaaaa"(10) + "bbbbbbbbbb"(10) = 20, fits. Adding "cccccccccc"(10) -> 30,
        // over budget by 5 -- must evict the single LRU entry ("a", never re-accessed) to get back to
        // 20, NOT clear the whole cache (which is what the old AbstractTablePanel bodyCache did).
        BoundedCache<String, String> c = cache(25);
        c.put("a", "aaaaaaaaaa");
        c.put("b", "bbbbbbbbbb");
        c.put("c", "cccccccccc");

        assertNull(c.get("a"), "least-recently-used entry should have been evicted");
        assertEquals("bbbbbbbbbb", c.get("b"), "more-recently-used entry must survive");
        assertEquals("cccccccccc", c.get("c"), "just-inserted entry must survive");
    }

    @Test
    void getMarksAnEntryAsRecentlyUsedSoItSurvivesOverAColderOne() {
        BoundedCache<String, String> c = cache(25);
        c.put("a", "aaaaaaaaaa");   // 10
        c.put("b", "bbbbbbbbbb");   // 20
        c.get("a");                 // touch "a" -- now "b" is the LRU one, not "a"
        c.put("c", "cccccccccc");   // 30, over by 5 -> evict LRU

        assertEquals("aaaaaaaaaa", c.get("a"), "recently-touched entry should survive");
        assertNull(c.get("b"), "the untouched, now-coldest entry should have been evicted instead");
    }

    @Test
    void aSingleOversizedValueIsKeptAloneEvenOverBudget() {
        // Evicting the only remaining entry (itself) to "fix" the overflow would defeat the point of
        // caching it at all -- always leave at least one entry.
        BoundedCache<String, String> c = cache(5);
        c.put("huge", "x".repeat(1000));
        assertEquals(1000, c.get("huge").length());
        assertEquals(1, c.size());
    }

    @Test
    void retainKeysDropsEverythingNotInTheGivenCollection() {
        BoundedCache<String, String> c = cache(1000);
        c.put("a", "1");
        c.put("b", "2");
        c.put("c", "3");

        c.retainKeys(List.of("a", "c"));

        assertEquals("1", c.get("a"));
        assertNull(c.get("b"));
        assertEquals("3", c.get("c"));
        assertEquals(2, c.size());
    }

    @Test
    void retainKeysThenPutStillEvictsCorrectlyAfterward() {
        // Regression guard: retainKeys must recompute the internal weight total, not just drop entries
        // -- otherwise a stale (too-high or too-low) weight would make later eviction decisions wrong.
        BoundedCache<String, String> c = cache(15);
        c.put("a", "aaaaaaaaaa");   // 10
        c.put("b", "bb");           // 12
        c.retainKeys(List.of("a", "b"));   // no-op drop, but exercises weight recompute: still 12

        c.put("c", "cc");   // 14, still under 15 -- must NOT evict anything if weight was recomputed
                            // correctly; a stale (too-high) weight would wrongly evict here
        assertEquals("aaaaaaaaaa", c.get("a"));
        assertEquals("bb", c.get("b"));
        assertEquals("cc", c.get("c"));
    }

    @Test
    void retainKeysWithAKeyThatWasNeverCachedIsIgnored() {
        BoundedCache<String, String> c = cache(1000);
        c.put("a", "1");
        c.retainKeys(List.of("a", "never-cached"));
        assertEquals("1", c.get("a"));
        assertEquals(1, c.size());
    }

    @Test
    void identityKeyedCacheTreatsEqualButDistinctObjectsAsDifferentEntries() {
        // Mirrors how model row classes (deliberately no equals()/hashCode() override -- see the 0.32.1
        // CLAUDE.md note) are keyed: BoundedCache itself is equals()-based (plain LinkedHashMap), so
        // this just confirms it doesn't do anything surprising with a key type that DOES override
        // equals (String) -- two equal Strings share one cache slot, as any normal Map would.
        BoundedCache<String, String> c = cache(1000);
        c.put(new String("key"), "first");
        c.put(new String("key"), "second");
        assertEquals("second", c.get("key"));
        assertEquals(1, c.size());
    }
}
