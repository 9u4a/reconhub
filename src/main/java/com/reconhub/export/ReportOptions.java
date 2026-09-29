package com.reconhub.export;

import com.reconhub.core.Bookmarks;
import com.reconhub.model.Finding;

/**
 * Filtering options shared by the HTML/Markdown/JSON/SARIF reporters.
 *
 * <p>{@code confirmedOnly}/{@code excludeFalsePositive} filter on analyst triage state, which only
 * {@link Finding} has, so {@link #includes(Finding)} is the one to call for the Findings section.
 * {@code bookmarkedOnly} (0.41.0) is row-type-agnostic -- {@code core.Bookmarks} keys any of the five
 * exported row types (Endpoint/ParameterInfo/Finding/JsAsset/TechInfo) by its own {@code key()} string,
 * so {@link #includesKey(String)} applies it uniformly to every section via {@link ReportData}, not
 * just Findings.
 */
public record ReportOptions(boolean confirmedOnly, boolean excludeFalsePositive,
                            boolean bookmarkedOnly, Bookmarks bookmarks) {

    /** No filtering — include every row. */
    public static ReportOptions all() {
        return new ReportOptions(false, false, false, null);
    }

    /** Whether {@code key} (a row's own {@code key()}) passes the bookmark filter. When {@code
     * bookmarkedOnly} is off this is always true; when it's on with no {@code Bookmarks} instance
     * available, every row is excluded (a caller bug, not "no filtering" -- callers always have a
     * {@code Bookmarks} to pass when this option can be turned on in the first place). */
    public boolean includesKey(String key) {
        return !bookmarkedOnly || (bookmarks != null && key != null && bookmarks.isBookmarked(key));
    }

    /** Whether a finding passes this option set: triage filters, plus the bookmark filter. */
    public boolean includes(Finding f) {
        if (f == null) {
            return false;
        }
        if (confirmedOnly && f.getTriage() != Finding.Triage.CONFIRMED) {
            return false;
        }
        if (excludeFalsePositive && f.getTriage() == Finding.Triage.FALSE_POSITIVE) {
            return false;
        }
        return includesKey(f.key());
    }
}
