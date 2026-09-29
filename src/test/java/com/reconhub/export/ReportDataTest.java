package com.reconhub.export;

import com.reconhub.core.Bookmarks;
import com.reconhub.core.DataStore;
import com.reconhub.model.Endpoint;
import com.reconhub.model.Finding;
import com.reconhub.model.JsAsset;
import com.reconhub.model.ParameterInfo;
import com.reconhub.model.TechInfo;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** {@code ReportData.of} -- one snapshot-and-filter pass shared by every report section (package-
 * private, same package as the exporters). Same package as {@link ReportOptions}/{@link ReportData}. */
class ReportDataTest {

    /** One row of each of the 5 exported types; the endpoint/finding/jsAsset/tech rows are bookmarked,
     * the parameter row is not -- exercises {@code bookmarkedOnly} spanning every row type. */
    private static DataStore populated(Bookmarks marks) {
        DataStore store = new DataStore();
        Endpoint ep = store.recordEndpoint("GET", "h.example", "/a", "http://h.example/a", 200,
                "text/html", "sitemap", Set.of(), null, Set.of());
        store.recordParameter(ParameterInfo.Location.QUERY, "id", "1",
                "http://h.example/a", "/a", false, null);
        Finding f = new Finding("Secret", Finding.Severity.HIGH, "raw", "http://h.example/a", "ev");
        store.recordFinding(f);
        JsAsset asset = new JsAsset("http://h.example/app.js", "sha-1", 100);
        store.recordJsAsset(asset);
        TechInfo tech = store.techForHost("h.example");

        if (marks != null) {
            marks.setBookmarked(ep.key(), true);
            marks.setBookmarked(f.key(), true);
            marks.setBookmarked(asset.key(), true);
            marks.setBookmarked(tech.key(), true);
            // parameter row deliberately left unbookmarked
        }
        return store;
    }

    @Test
    void withNoFilteringEveryRowPassesThrough() {
        DataStore store = populated(null);
        ReportData data = ReportData.of(store, ReportOptions.all());

        assertEquals(1, data.endpoints().size());
        assertEquals(1, data.parameters().size());
        assertEquals(1, data.findings().size());
        assertEquals(1, data.jsAssets().size());
        assertEquals(1, data.tech().size());
    }

    @Test
    void withNoFilteringContentMatchesTheRawSnapshotExactly() {
        // ReportData.filter skips its stream-filter pass when the option is off -- store.snapshotX()
        // always returns a fresh defensive copy regardless (see DataStore.Snap), so this can only be
        // checked by content, not by reference identity.
        DataStore store = populated(null);
        List<Endpoint> snap = store.snapshotEndpoints();
        ReportData data = ReportData.of(store, ReportOptions.all());
        assertEquals(snap, data.endpoints());
    }

    @Test
    void bookmarkedOnlySpansAllFiveRowTypes() {
        Bookmarks marks = new Bookmarks();
        DataStore store = populated(marks);
        ReportOptions opts = new ReportOptions(false, false, true, marks);
        ReportData data = ReportData.of(store, opts);

        assertEquals(1, data.endpoints().size());
        assertEquals(1, data.findings().size());
        assertEquals(1, data.jsAssets().size());
        assertEquals(1, data.tech().size());
        // the one row deliberately never bookmarked
        assertTrue(data.parameters().isEmpty());
    }

    @Test
    void bookmarkedOnlyWithNothingBookmarkedYieldsEmptyEverySection() {
        DataStore store = populated(null);   // populated with no bookmarks set at all
        Bookmarks marks = new Bookmarks();   // a separate, genuinely empty Bookmarks
        ReportOptions opts = new ReportOptions(false, false, true, marks);
        ReportData data = ReportData.of(store, opts);

        assertTrue(data.endpoints().isEmpty());
        assertTrue(data.parameters().isEmpty());
        assertTrue(data.findings().isEmpty());
        assertTrue(data.jsAssets().isEmpty());
        assertTrue(data.tech().isEmpty());
    }

    @Test
    void findingsGoThroughIncludesNotJustTheBookmarkFilter() {
        // Findings additionally honor confirmedOnly/excludeFalsePositive -- ReportData.filterFindings
        // must call ReportOptions.includes, not just the bookmark check.
        Bookmarks marks = new Bookmarks();
        DataStore store = new DataStore();
        Finding notConfirmed = new Finding("Secret", Finding.Severity.HIGH, "raw", "http://h.example/a", "ev");
        store.recordFinding(notConfirmed);
        marks.setBookmarked(notConfirmed.key(), true);   // bookmarked, but never confirmed

        ReportOptions opts = new ReportOptions(true, false, true, marks);
        ReportData data = ReportData.of(store, opts);

        assertTrue(data.findings().isEmpty());
    }
}
