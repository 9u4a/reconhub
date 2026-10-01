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
}
