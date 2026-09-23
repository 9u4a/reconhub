package com.reconhub.core;

import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** {@code core.Bookmarks} -- the standalone bookmark/note store introduced in 0.37.0 (deliberately not
 * part of {@code DataStore}, see the class javadoc: user-authored data must survive {@code
 * DataStore.clear()}). */
class BookmarksTest {

    @Test
    void defaultsForUnknownOrNullKeys() {
        Bookmarks b = new Bookmarks();
        assertFalse(b.isBookmarked("nope"));
        assertFalse(b.isBookmarked(null));
        assertEquals("", b.noteFor("nope"));
        assertEquals("", b.noteFor(null));
    }

    @Test
    void setBookmarkedAndNoteIndependently() {
        Bookmarks b = new Bookmarks();
        b.setBookmarked("k1", true);
        assertTrue(b.isBookmarked("k1"));
        assertEquals("", b.noteFor("k1"));

        b.setNote("k1", "worth a second look");
        assertTrue(b.isBookmarked("k1"), "note edit must not clear the bookmark flag");
        assertEquals("worth a second look", b.noteFor("k1"));

        b.setBookmarked("k1", false);
        assertFalse(b.isBookmarked("k1"), "un-bookmarking must not clear the note");
        assertEquals("worth a second look", b.noteFor("k1"));
    }

    @Test
    void emptyEntryIsNotRetained() {
        Bookmarks b = new Bookmarks();
        b.setBookmarked("k1", true);
        b.setNote("k1", "note");
        b.setBookmarked("k1", false);
        b.setNote("k1", "");
        assertTrue(b.snapshotAll().isEmpty(), "an entry with no bookmark and no note should not linger");
    }

    @Test
    void nullKeyOperationsAreNoOps() {
        Bookmarks b = new Bookmarks();
        b.setBookmarked(null, true);
        b.setNote(null, "x");
        assertTrue(b.snapshotAll().isEmpty());
    }

    @Test
    void snapshotAllIsAnIndependentCopy() {
        Bookmarks b = new Bookmarks();
        b.setBookmarked("k1", true);
        Map<String, Bookmarks.Entry> snap = b.snapshotAll();
        b.setBookmarked("k2", true);
        assertEquals(1, snap.size(), "snapshot must not see later mutations");
        assertEquals(2, b.snapshotAll().size());
    }

    @Test
    void restoreOnlyKeepsNonEmptyEntries() {
        Bookmarks b = new Bookmarks();
        b.restore("k1", new Bookmarks.Entry(true, ""));
        b.restore("k2", new Bookmarks.Entry(false, "a note"));
        b.restore("k3", new Bookmarks.Entry(false, ""));   // empty -- should not be kept
        b.restore("k4", null);
        b.restore(null, new Bookmarks.Entry(true, "x"));

        assertTrue(b.isBookmarked("k1"));
        assertEquals("a note", b.noteFor("k2"));
        assertFalse(b.snapshotAll().containsKey("k3"));
        assertEquals(2, b.snapshotAll().size());
    }

    @Test
    void saveLoadRoundTripsEveryField() {
        ApiStub stub = new ApiStub();
        Bookmarks b = new Bookmarks();
        b.setBookmarked("GET https://h.example/admin", true);
        b.setNote("GET https://h.example/admin", "check auth bypass");
        b.setNote("Missing security headers|h2.example", "low priority, ignore");   // note only, no star

        b.save(stub.api);
        assertTrue(stub.errorLog.isEmpty());
        assertFalse(stub.prefStrings.isEmpty());

        Bookmarks loaded = Bookmarks.load(stub.api);
        assertTrue(stub.errorLog.isEmpty());
        assertTrue(loaded.isBookmarked("GET https://h.example/admin"));
        assertEquals("check auth bypass", loaded.noteFor("GET https://h.example/admin"));
        assertFalse(loaded.isBookmarked("Missing security headers|h2.example"));
        assertEquals("low priority, ignore", loaded.noteFor("Missing security headers|h2.example"));
        assertEquals(2, loaded.snapshotAll().size());
    }

    @Test
    void loadWithNothingSavedYetReturnsEmpty() {
        ApiStub stub = new ApiStub();
        Bookmarks loaded = Bookmarks.load(stub.api);
        assertTrue(loaded.snapshotAll().isEmpty());
        assertTrue(stub.errorLog.isEmpty());
    }

    @Test
    void loadWithCorruptedJsonFallsBackToEmptyAndLogs() {
        ApiStub stub = new ApiStub();
        stub.prefStrings.put("reconhub.bookmarks.v1", "{not valid json!!");
        Bookmarks loaded = Bookmarks.load(stub.api);
        assertTrue(loaded.snapshotAll().isEmpty());
        assertFalse(stub.errorLog.isEmpty());
    }
}
