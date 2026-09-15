package com.reconhub.export;

import com.reconhub.model.Finding;

/**
 * Filtering options shared by the HTML and Markdown reporters. Controls which findings are included
 * based on their analyst triage state.
 */
public record ReportOptions(boolean confirmedOnly, boolean excludeFalsePositive) {

    /** No filtering — include every finding. */
    public static ReportOptions all() {
        return new ReportOptions(false, false);
    }

    /** Whether a finding passes this option set. */
    public boolean includes(Finding f) {
        if (f == null) {
            return false;
        }
        if (confirmedOnly && f.getTriage() != Finding.Triage.CONFIRMED) {
            return false;
        }
        return !(excludeFalsePositive && f.getTriage() == Finding.Triage.FALSE_POSITIVE);
    }
}
