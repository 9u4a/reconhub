package com.reconhub.core;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** {@code KeyedDiff.compute} -- the added/removed diff behind {@code ui.SnapshotDiffPanel} (0.43.0).
 * Pure logic (plain Strings as the "row" type, keyed by identity), headless. */
class KeyedDiffTest {

    @Test
    void identicalListsHaveNoAddedOrRemoved() {
        var diff = KeyedDiff.compute(List.of("a", "b"), List.of("a", "b"), s -> s);
        assertTrue(diff.added().isEmpty());
        assertTrue(diff.removed().isEmpty());
    }

    @Test
    void newRowIsAdded() {
        var diff = KeyedDiff.compute(List.of("a"), List.of("a", "b"), s -> s);
        assertEquals(List.of("b"), diff.added());
        assertTrue(diff.removed().isEmpty());
    }

    @Test
    void missingRowIsRemoved() {
        var diff = KeyedDiff.compute(List.of("a", "b"), List.of("a"), s -> s);
        assertTrue(diff.added().isEmpty());
        assertEquals(List.of("b"), diff.removed());
    }

    @Test
    void disjointListsAreAllAddedAndAllRemoved() {
        var diff = KeyedDiff.compute(List.of("a"), List.of("b"), s -> s);
        assertEquals(List.of("b"), diff.added());
        assertEquals(List.of("a"), diff.removed());
    }

    @Test
    void bothEmptyIsEmptyDiff() {
        var diff = KeyedDiff.compute(List.<String>of(), List.<String>of(), s -> s);
        assertTrue(diff.added().isEmpty());
        assertTrue(diff.removed().isEmpty());
    }

    @Test
    void duplicateKeysInOneListCollapseToOne() {
        // Shouldn't happen for real model rows (key() is meant to be unique), but the diff must not
        // double-count if it ever does.
        var diff = KeyedDiff.compute(List.of("a", "a"), List.of("a", "b"), s -> s);
        assertEquals(List.of("b"), diff.added());
        assertTrue(diff.removed().isEmpty());
    }

    @Test
    void preservesInputOrderInResults() {
        var diff = KeyedDiff.compute(List.<String>of(), List.of("z", "a", "m"), s -> s);
        assertEquals(List.of("z", "a", "m"), diff.added());
    }

    @Test
    void rowsWithANullKeyAreIgnored() {
        var diff = KeyedDiff.compute(List.of("a"), List.of("a", "b"), s -> s.equals("b") ? null : s);
        assertTrue(diff.added().isEmpty());   // "b"'s null key means it's never indexed
    }

    // ---- Diff3 (added/removed/changed, 0.45.0) ---------------------------
    // Rows are String[]{key, signature} so key and content can differ independently.

    private static String key(String[] r) { return r[0]; }
    private static String sig(String[] r) { return r[1]; }

    @Test
    void sameKeyDifferentSignatureIsChanged() {
        var oldRows = List.<String[]>of(new String[]{"a", "200"});
        var newRows = List.<String[]>of(new String[]{"a", "500"});
        var diff = KeyedDiff.compute(oldRows, newRows, KeyedDiffTest::key, KeyedDiffTest::sig);
        assertTrue(diff.added().isEmpty());
        assertTrue(diff.removed().isEmpty());
        assertEquals(1, diff.changed().size());
        assertEquals("500", diff.changed().get(0)[1], "changed must return the NEW-side row");
    }

    @Test
    void sameKeySameSignatureIsNotChanged() {
        var oldRows = List.<String[]>of(new String[]{"a", "200"});
        var newRows = List.<String[]>of(new String[]{"a", "200"});
        var diff = KeyedDiff.compute(oldRows, newRows, KeyedDiffTest::key, KeyedDiffTest::sig);
        assertTrue(diff.added().isEmpty());
        assertTrue(diff.removed().isEmpty());
        assertTrue(diff.changed().isEmpty());
    }

    @Test
    void addedAndRemovedAreNotAlsoChanged() {
        var oldRows = List.of(new String[]{"a", "x"}, new String[]{"gone", "x"});
        var newRows = List.of(new String[]{"a", "x"}, new String[]{"new", "y"});
        var diff = KeyedDiff.compute(oldRows, newRows, KeyedDiffTest::key, KeyedDiffTest::sig);
        assertEquals(1, diff.added().size());
        assertEquals("new", diff.added().get(0)[0]);
        assertEquals(1, diff.removed().size());
        assertEquals("gone", diff.removed().get(0)[0]);
        assertTrue(diff.changed().isEmpty());   // "a" is unchanged; the +/- keys aren't "changed"
    }

    @Test
    void signatureEqualToKeyMakesChangedImpossible() {
        // Mirrors the JsAsset sha256 case: signature == key, so a different content is a different key.
        var oldRows = List.<String[]>of(new String[]{"sha1", "ignored"});
        var newRows = List.<String[]>of(new String[]{"sha2", "ignored"});
        var diff = KeyedDiff.compute(oldRows, newRows, KeyedDiffTest::key, KeyedDiffTest::key);
        assertEquals(1, diff.added().size());
        assertEquals(1, diff.removed().size());
        assertTrue(diff.changed().isEmpty());
    }

    @Test
    void diff3PreservesNewListOrderInChanged() {
        var oldRows = List.of(new String[]{"z", "1"}, new String[]{"a", "1"});
        var newRows = List.of(new String[]{"z", "2"}, new String[]{"a", "2"});
        var diff = KeyedDiff.compute(oldRows, newRows, KeyedDiffTest::key, KeyedDiffTest::sig);
        assertEquals(List.of("z", "a"),
                diff.changed().stream().map(KeyedDiffTest::key).toList());
    }
}
