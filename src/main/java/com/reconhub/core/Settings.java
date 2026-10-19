package com.reconhub.core;

import burp.api.montoya.MontoyaApi;
import com.google.gson.Gson;
import com.reconhub.analysis.FindingTaxonomy;
import com.reconhub.model.Finding;

import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Collections;
import java.util.EnumSet;
import java.util.Set;

/**
 * Mutable, shared runtime configuration edited from the Settings panel. All scalar fields are
 * volatile so the ingestion threads see UI changes immediately; {@link #mutedCategories} is a
 * collection, so it's wrapped with {@link Collections#synchronizedSet} instead (a plain
 * {@code EnumSet} is not thread-safe for concurrent reads during ingestion while the EDT mutates it).
 */
public final class Settings {

    /** How ingestion decides which traffic to process. */
    public enum ScopeMode { BURP_SCOPE, ALL }

    private volatile ScopeMode scopeMode = ScopeMode.BURP_SCOPE;
    private volatile boolean saveJsToDisk = true;
    private volatile Path jsSaveDirectory =
            Paths.get(System.getProperty("user.home"), "reconhub", "js");
    private volatile boolean scanResponsesForSecrets = true;
    private volatile boolean liveCaptureEnabled = true;
    private volatile boolean runPassiveChecks = true;     // interesting responses, misconfig, comments
    private volatile boolean ignoreStaticAssets = true;   // skip img/css/font/media (never JS)
    private volatile boolean autoIngestOnLoad = true;     // sweep site map when the extension loads
    private volatile String scopeIncludeRegex = "";       // extra include filter (empty = off)
    private volatile String scopeExcludeRegex = "";       // extra exclude filter (empty = off)
    // Findings display noise control (view-only filter; does not drop collected data).
    private volatile Finding.Severity minFindingSeverity = Finding.Severity.INFO;   // INFO = show all
    private final Set<FindingTaxonomy.Category> mutedCategories =
            Collections.synchronizedSet(EnumSet.noneOf(FindingTaxonomy.Category.class));

    // --- Match & Replace bulk send -- ReconHub's only ACTIVE (traffic-generating) feature (0.46.0
    // removed the known-path bruteforce). Follows the workspace target-load-safety policy's default:
    // a settings flag OFF by default + throttle (delay/concurrency) + ACTIVE labeling, plus a per-run
    // confirmation dialog (ui.MatchReplaceDialog) on top of the flag.
    private volatile boolean matchReplaceEnabled = false;
    private volatile int matchReplaceDelayMs = 500;
    private volatile int matchReplaceConcurrency = 1;

    // --- Memory: optional per-table retention cap (0.44.0). 0 = unlimited (default, unchanged behavior).
    // When > 0, each of DataStore's four message-bearing collections keeps at most this many rows,
    // evicting the oldest past the cap. Off-heap message storage (DataStore via TrafficIngestor's
    // copyToTempFile) is always on and independent of this; the cap additionally bounds the row COUNT
    // for very long engagements.
    private volatile int maxRetainedItems = 0;

    public ScopeMode getScopeMode() { return scopeMode; }
    public void setScopeMode(ScopeMode m) { this.scopeMode = m; }

    public boolean isSaveJsToDisk() { return saveJsToDisk; }
    public void setSaveJsToDisk(boolean b) { this.saveJsToDisk = b; }

    public Path getJsSaveDirectory() { return jsSaveDirectory; }
    public void setJsSaveDirectory(Path p) { this.jsSaveDirectory = p; }

    public boolean isScanResponsesForSecrets() { return scanResponsesForSecrets; }
    public void setScanResponsesForSecrets(boolean b) { this.scanResponsesForSecrets = b; }

    public boolean isLiveCaptureEnabled() { return liveCaptureEnabled; }
    public void setLiveCaptureEnabled(boolean b) { this.liveCaptureEnabled = b; }

    public boolean isRunPassiveChecks() { return runPassiveChecks; }
    public void setRunPassiveChecks(boolean b) { this.runPassiveChecks = b; }

    public boolean isIgnoreStaticAssets() { return ignoreStaticAssets; }
    public void setIgnoreStaticAssets(boolean b) { this.ignoreStaticAssets = b; }

    public boolean isAutoIngestOnLoad() { return autoIngestOnLoad; }
    public void setAutoIngestOnLoad(boolean b) { this.autoIngestOnLoad = b; }

    public String getScopeIncludeRegex() { return scopeIncludeRegex; }
    public void setScopeIncludeRegex(String s) { this.scopeIncludeRegex = s == null ? "" : s; }

    public String getScopeExcludeRegex() { return scopeExcludeRegex; }
    public void setScopeExcludeRegex(String s) { this.scopeExcludeRegex = s == null ? "" : s; }

    public Finding.Severity getMinFindingSeverity() { return minFindingSeverity; }
    public void setMinFindingSeverity(Finding.Severity s) {
        this.minFindingSeverity = s == null ? Finding.Severity.INFO : s;
    }

    public boolean isCategoryMuted(FindingTaxonomy.Category c) { return mutedCategories.contains(c); }
    public void setCategoryMuted(FindingTaxonomy.Category c, boolean muted) {
        if (muted) {
            mutedCategories.add(c);
        } else {
            mutedCategories.remove(c);
        }
    }

    /** True when a finding passes the display noise filter (severity threshold + category mute). */
    public boolean findingVisible(Finding.Severity sev, FindingTaxonomy.Category cat) {
        return sev.ordinal() <= minFindingSeverity.ordinal() && !mutedCategories.contains(cat);
    }

    public boolean isMatchReplaceEnabled() { return matchReplaceEnabled; }
    public void setMatchReplaceEnabled(boolean b) { this.matchReplaceEnabled = b; }

    public int getMatchReplaceDelayMs() { return matchReplaceDelayMs; }
    public void setMatchReplaceDelayMs(int ms) { this.matchReplaceDelayMs = Math.max(0, Math.min(ms, 60_000)); }

    public int getMatchReplaceConcurrency() { return matchReplaceConcurrency; }
    public void setMatchReplaceConcurrency(int n) { this.matchReplaceConcurrency = Math.max(1, Math.min(n, 10)); }

    public int getMaxRetainedItems() { return maxRetainedItems; }
    // 0 = unlimited; any positive value is floored to a sane minimum so a tiny cap can't thrash the
    // model, and ceilinged generously (a cap is a memory guard, not a hard product limit).
    public void setMaxRetainedItems(int n) {
        this.maxRetainedItems = n <= 0 ? 0 : Math.max(1000, Math.min(n, 1_000_000));
    }

    // ---- Persistence (Montoya extension preferences) ---------------------
    // Same "whole object as one Gson JSON blob under one preference key" pattern as
    // analysis.UserRuleStore. jsSaveDirectory (a Path) needs a String round-trip since Gson can't
    // serialize Path directly; mutedCategories (a Set<Category>) Gson handles natively as an array
    // of enum names.

    private static final String PREF_KEY = "reconhub.settings.v1";

    /** Plain-data mirror of every persisted field; also the on-disk JSON shape. */
    private static final class Dto {
        String scopeMode;
        boolean saveJsToDisk;
        String jsSaveDirectory;
        boolean scanResponsesForSecrets;
        boolean liveCaptureEnabled;
        boolean runPassiveChecks;
        boolean ignoreStaticAssets;
        boolean autoIngestOnLoad;
        String scopeIncludeRegex;
        String scopeExcludeRegex;
        String minFindingSeverity;
        Set<FindingTaxonomy.Category> mutedCategories;
        boolean matchReplaceEnabled;
        int matchReplaceDelayMs;
        int matchReplaceConcurrency;
        int maxRetainedItems;
    }

    private Dto toDto() {
        Dto d = new Dto();
        d.scopeMode = scopeMode.name();
        d.saveJsToDisk = saveJsToDisk;
        d.jsSaveDirectory = jsSaveDirectory == null ? null : jsSaveDirectory.toString();
        d.scanResponsesForSecrets = scanResponsesForSecrets;
        d.liveCaptureEnabled = liveCaptureEnabled;
        d.runPassiveChecks = runPassiveChecks;
        d.ignoreStaticAssets = ignoreStaticAssets;
        d.autoIngestOnLoad = autoIngestOnLoad;
        d.scopeIncludeRegex = scopeIncludeRegex;
        d.scopeExcludeRegex = scopeExcludeRegex;
        d.minFindingSeverity = minFindingSeverity.name();
        // Snapshot into a plain HashSet -- Gson serializes java.util.Collections$SynchronizedSet fine
        // in practice, but a plain copy avoids relying on that and matches every other set field here.
        d.mutedCategories = new java.util.HashSet<>(mutedCategories);
        d.matchReplaceEnabled = matchReplaceEnabled;
        d.matchReplaceDelayMs = matchReplaceDelayMs;
        d.matchReplaceConcurrency = matchReplaceConcurrency;
        d.maxRetainedItems = maxRetainedItems;
        return d;
    }

    /** Rebuilds a {@link Settings} from a loaded {@link Dto}; unrecognized/missing fields fall back
     * to the same defaults the no-arg constructor uses. */
    private static Settings fromDto(Dto d) {
        Settings s = new Settings();
        if (d == null) {
            return s;
        }
        if (d.scopeMode != null) {
            try {
                s.scopeMode = ScopeMode.valueOf(d.scopeMode);
            } catch (IllegalArgumentException ignored) { /* keep default */ }
        }
        s.saveJsToDisk = d.saveJsToDisk;
        if (d.jsSaveDirectory != null && !d.jsSaveDirectory.isBlank()) {
            s.jsSaveDirectory = Paths.get(d.jsSaveDirectory);
        }
        s.scanResponsesForSecrets = d.scanResponsesForSecrets;
        s.liveCaptureEnabled = d.liveCaptureEnabled;
        s.runPassiveChecks = d.runPassiveChecks;
        s.ignoreStaticAssets = d.ignoreStaticAssets;
        s.autoIngestOnLoad = d.autoIngestOnLoad;
        s.scopeIncludeRegex = d.scopeIncludeRegex == null ? "" : d.scopeIncludeRegex;
        s.scopeExcludeRegex = d.scopeExcludeRegex == null ? "" : d.scopeExcludeRegex;
        if (d.minFindingSeverity != null) {
            try {
                s.minFindingSeverity = Finding.Severity.valueOf(d.minFindingSeverity);
            } catch (IllegalArgumentException ignored) { /* keep default */ }
        }
        if (d.mutedCategories != null) {
            s.mutedCategories.addAll(d.mutedCategories);
        }
        s.matchReplaceEnabled = d.matchReplaceEnabled;   // absent/false on old saves -- correct default
        s.matchReplaceDelayMs = d.matchReplaceDelayMs == 0 ? 500 : d.matchReplaceDelayMs;
        s.matchReplaceConcurrency = d.matchReplaceConcurrency == 0 ? 1 : d.matchReplaceConcurrency;
        s.maxRetainedItems = d.maxRetainedItems;   // 0 (unlimited) on old saves -- correct default
        return s;
    }

    /** Persists every field to Montoya extension preferences (survives a Burp restart). */
    public void save(MontoyaApi api) {
        try {
            Dto d = toDto();
            api.persistence().preferences().setString(PREF_KEY, new Gson().toJson(d));
        } catch (RuntimeException e) {
            api.logging().logToError("ReconHub: failed to save settings: " + e);
        }
    }

    /** Loads previously-saved settings, or a fresh default {@link Settings} if none exist yet /
     * loading fails. */
    public static Settings load(MontoyaApi api) {
        try {
            String json = api.persistence().preferences().getString(PREF_KEY);
            if (json == null || json.isBlank()) {
                return new Settings();
            }
            return fromDto(new Gson().fromJson(json, Dto.class));
        } catch (RuntimeException e) {
            api.logging().logToError("ReconHub: failed to load settings, using defaults: " + e);
            return new Settings();
        }
    }
}
