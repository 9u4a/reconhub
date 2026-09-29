package com.reconhub.export;

import com.reconhub.core.Bookmarks;
import com.reconhub.model.Finding;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** {@code ReportOptions} -- triage filters (pre-existing) plus the 0.41.0 {@code bookmarkedOnly} filter,
 * which (unlike the triage ones) applies to any row type via {@link #includesKey}, not just Finding. */
class ReportOptionsTest {

    private static Finding finding(Finding.Triage triage) {
        Finding f = new Finding("Secret", Finding.Severity.HIGH, "raw-" + triage,
                "https://h.example/a", "evidence");
        f.setTriage(triage);
        return f;
    }

    // ---- all() / baseline --------------------------------------------------------------------------

    @Test
    void allIncludesEveryTriageState() {
        ReportOptions opts = ReportOptions.all();
        for (Finding.Triage t : Finding.Triage.values()) {
            assertTrue(opts.includes(finding(t)));
        }
    }

    @Test
    void allIncludesAnyKeyRegardlessOfBookmarks() {
        assertTrue(ReportOptions.all().includesKey("anything"));
        assertTrue(ReportOptions.all().includesKey(null));
    }

    @Test
    void includesIsFalseForNullFinding() {
        assertFalse(ReportOptions.all().includes(null));
    }

    // ---- triage filters (pre-existing) --------------------------------------------------------------

    @Test
    void confirmedOnlyExcludesEverythingElse() {
        ReportOptions opts = new ReportOptions(true, false, false, null);
        assertTrue(opts.includes(finding(Finding.Triage.CONFIRMED)));
        assertFalse(opts.includes(finding(Finding.Triage.NEW)));
        assertFalse(opts.includes(finding(Finding.Triage.FALSE_POSITIVE)));
    }

    @Test
    void excludeFalsePositiveDropsOnlyThatState() {
        ReportOptions opts = new ReportOptions(false, true, false, null);
        assertFalse(opts.includes(finding(Finding.Triage.FALSE_POSITIVE)));
        assertTrue(opts.includes(finding(Finding.Triage.NEW)));
        assertTrue(opts.includes(finding(Finding.Triage.CONFIRMED)));
    }

    // ---- bookmarkedOnly (0.41.0) ---------------------------------------------------------------------

    @Test
    void bookmarkedOnlyIncludesOnlyBookmarkedKeys() {
        Bookmarks marks = new Bookmarks();
        marks.setBookmarked("keep", true);
        ReportOptions opts = new ReportOptions(false, false, true, marks);

        assertTrue(opts.includesKey("keep"));
        assertFalse(opts.includesKey("drop"));
    }

    @Test
    void bookmarkedOnlyWithNoBookmarksInstanceExcludesEverything() {
        // A caller bug (turning the option on without passing a Bookmarks), not "no filtering" -- must
        // fail closed, not open.
        ReportOptions opts = new ReportOptions(false, false, true, null);
        assertFalse(opts.includesKey("anything"));
    }

    @Test
    void bookmarkedOnlyWithNullKeyIsExcluded() {
        Bookmarks marks = new Bookmarks();
        ReportOptions opts = new ReportOptions(false, false, true, marks);
        assertFalse(opts.includesKey(null));
    }

    @Test
    void bookmarkedOnlyCombinesWithTriageFiltersAsAnd() {
        Bookmarks marks = new Bookmarks();
        Finding confirmed = finding(Finding.Triage.CONFIRMED);
        Finding notConfirmed = finding(Finding.Triage.NEW);
        marks.setBookmarked(confirmed.key(), true);
        marks.setBookmarked(notConfirmed.key(), true);   // bookmarked but wrong triage

        ReportOptions opts = new ReportOptions(true, false, true, marks);

        assertTrue(opts.includes(confirmed));     // confirmed AND bookmarked
        assertFalse(opts.includes(notConfirmed)); // bookmarked but not confirmed -> still excluded
    }

    @Test
    void bookmarkedOnlyExcludesAConfirmedFindingThatIsNotBookmarked() {
        Bookmarks marks = new Bookmarks();   // nothing bookmarked
        ReportOptions opts = new ReportOptions(true, false, true, marks);
        assertFalse(opts.includes(finding(Finding.Triage.CONFIRMED)));
    }
}
