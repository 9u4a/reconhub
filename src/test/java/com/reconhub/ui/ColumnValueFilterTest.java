package com.reconhub.ui;

import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * {@code ColumnValueFilter} -- the Burp-History-filter-style checklist quick filter (0.40.0). The
 * button/popup itself is a real Swing component (constructing one is fine headless; only showing/
 * painting it needs a display), but its filtering logic (the tests here) is pure state, exercised via
 * {@code setValueShown} -- package-private, added specifically so tests don't need to drive the actual
 * popup UI (same "package-private for headless testing" convention used elsewhere in this codebase).
 * Same-package test since the class is itself package-private by design.
 */
class ColumnValueFilterTest {

    @Test
    void withNothingExcludedEverythingPasses() {
        ColumnValueFilter<String> f = new ColumnValueFilter<>("Method", s -> s);
        assertTrue(f.test("GET"));
        assertTrue(f.test("POST"));
    }

    @Test
    void nullValueAlwaysPasses() {
        // A row whose value-extractor returns null (e.g. an Endpoint with no observed status yet)
        // must never be silently hidden by a filter it doesn't have a value for.
        ColumnValueFilter<String> f = new ColumnValueFilter<>("Status", s -> null);
        f.refreshAvailableValues(List.of("200"));
        f.setValueShown("200", false);
        assertTrue(f.test("anything"));
    }

    @Test
    void hidingAValueExcludesOnlyMatchingRows() {
        ColumnValueFilter<String> f = new ColumnValueFilter<>("Method", s -> s);
        f.refreshAvailableValues(List.of("GET", "POST", "PUT"));
        f.setValueShown("POST", false);

        assertTrue(f.test("GET"));
        assertFalse(f.test("POST"));
        assertTrue(f.test("PUT"));
    }

    @Test
    void reShowingAHiddenValueRestoresIt() {
        ColumnValueFilter<String> f = new ColumnValueFilter<>("Method", s -> s);
        f.refreshAvailableValues(List.of("GET", "POST"));
        f.setValueShown("POST", false);
        assertFalse(f.test("POST"));
        f.setValueShown("POST", true);
        assertTrue(f.test("POST"));
    }

    @Test
    void hidingEveryKnownValueStillShowsAnUnknownOne() {
        // A value not present in `available` at all (e.g. brand new data since the last refresh) must
        // never be caught by a filter built from an older snapshot.
        ColumnValueFilter<String> f = new ColumnValueFilter<>("Method", s -> s);
        f.refreshAvailableValues(List.of("GET"));
        f.setValueShown("GET", false);
        assertTrue(f.test("POST"));
    }

    @Test
    void refreshAvailableValuesDropsExclusionForValuesNoLongerPresent() {
        ColumnValueFilter<String> f = new ColumnValueFilter<>("Method", s -> s);
        f.refreshAvailableValues(List.of("GET", "POST"));
        f.setValueShown("POST", false);
        assertFalse(f.test("POST"));

        // POST no longer appears in the data -- its exclusion must not persist forever.
        f.refreshAvailableValues(List.of("GET", "PUT"));
        assertTrue(f.test("POST"));
    }

    @Test
    void emptyAndBlankValuesAreNeverOfferedAsFilterableValues() {
        ColumnValueFilter<String> f = new ColumnValueFilter<>("Type", s -> s);
        f.refreshAvailableValues(Arrays.asList("json", "", null, "xml"));
        // Indirect check: the button label's count denominator is available.size(), which must
        // exclude "" and null -- verified via the label after excluding one real value.
        f.setValueShown("json", false);
        assertEquals("Type (1/2) ▾", f.component().getText());
    }

    @Test
    void onChangeIsNotCalledByRefreshAvailableValuesAlone() {
        // refreshAvailableValues runs on every data refresh (e.g. every 300ms tick); it must NOT fire
        // onChange on its own, or every refresh would trigger a redundant reapplyFilter() loop.
        ColumnValueFilter<String> f = new ColumnValueFilter<>("Method", s -> s);
        AtomicInteger calls = new AtomicInteger();
        f.setOnChange(calls::incrementAndGet);
        f.refreshAvailableValues(List.of("GET", "POST"));
        f.refreshAvailableValues(List.of("GET"));
        assertEquals(0, calls.get());
    }

    @Test
    void onChangeFiresExactlyOncePerSetValueShownCall() {
        ColumnValueFilter<String> f = new ColumnValueFilter<>("Method", s -> s);
        AtomicInteger calls = new AtomicInteger();
        f.refreshAvailableValues(List.of("GET", "POST"));
        f.setOnChange(calls::incrementAndGet);
        f.setValueShown("POST", false);
        f.setValueShown("POST", true);
        assertEquals(2, calls.get());
    }

    @Test
    void buttonLabelShowsNoCountWhenNothingIsExcluded() {
        ColumnValueFilter<String> f = new ColumnValueFilter<>("Method", s -> s);
        f.refreshAvailableValues(List.of("GET", "POST"));
        assertEquals("Method ▾", f.component().getText());
        assertFalse(f.component().getText().contains("("));
    }

    @Test
    void buttonLabelShowsShownOverTotalWhenSomethingIsExcluded() {
        ColumnValueFilter<String> f = new ColumnValueFilter<>("Method", s -> s);
        f.refreshAvailableValues(List.of("GET", "POST", "PUT"));
        f.setValueShown("POST", false);
        assertEquals("Method (2/3) ▾", f.component().getText());
    }
}
