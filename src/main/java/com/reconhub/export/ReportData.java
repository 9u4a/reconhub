package com.reconhub.export;

import com.reconhub.core.DataStore;
import com.reconhub.model.Endpoint;
import com.reconhub.model.Finding;
import com.reconhub.model.JsAsset;
import com.reconhub.model.ParameterInfo;
import com.reconhub.model.TechInfo;

import java.util.List;
import java.util.function.Function;

/**
 * One snapshot-and-filter pass over {@link DataStore}, shared by every section of a report.
 *
 * <p>Before 0.41.0, each exporter took its own {@code store.snapshotX()} per section -- {@code
 * HtmlReporter} called {@code snapshotFindings()} four separate times in one export -- and {@link
 * ReportOptions} filtering was wired into the Findings section only, so a "bookmarked only" option
 * could never have reached the Endpoints/Parameters/JS/Tech sections without being wired into each one
 * individually. Building this once up front fixes both: one snapshot per collection, and the same
 * {@link ReportOptions#includesKey} bookmark check applied uniformly across all five row types via each
 * model's own {@code key()}.
 */
record ReportData(List<Endpoint> endpoints, List<ParameterInfo> parameters, List<Finding> findings,
                  List<JsAsset> jsAssets, List<TechInfo> tech) {

    static ReportData of(DataStore store, ReportOptions opts) {
        return new ReportData(
                filter(store.snapshotEndpoints(), opts, Endpoint::key),
                filter(store.snapshotParameters(), opts, ParameterInfo::key),
                filterFindings(store.snapshotFindings(), opts),
                filter(store.snapshotJsAssets(), opts, JsAsset::key),
                filter(store.snapshotTech(), opts, TechInfo::key));
    }

    private static <T> List<T> filter(List<T> rows, ReportOptions opts, Function<T, String> keyOf) {
        // Filter off (the common case) -> return the snapshot as-is, no extra copy.
        return opts.bookmarkedOnly() ? rows.stream().filter(r -> opts.includesKey(keyOf.apply(r))).toList()
                : rows;
    }

    /** Findings go through {@link ReportOptions#includes(Finding)} instead of {@link #filter} -- it
     * also applies the triage filters ({@code confirmedOnly}/{@code excludeFalsePositive}), which only
     * Findings have. */
    private static List<Finding> filterFindings(List<Finding> findings, ReportOptions opts) {
        return findings.stream().filter(opts::includes).toList();
    }
}
