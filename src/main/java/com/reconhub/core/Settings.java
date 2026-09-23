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

    // --- Known-path bruteforce (ACTIVE — sends its own traffic). No master on/off switch: the user
    // explicitly types/edits the target and clicks OK on a confirmation dialog every single run (see
    // RunBruteforceAction) -- a deliberate, discussed exception to the workspace target-load safety
    // policy's default-OFF-flag requirement (2026-09-17), since that per-run confirmation already is
    // explicit informed consent. The other two policy requirements still apply in full: every send
    // goes through active.Throttler paced by delayMs and capped by bruteforceMaxRequestsPerHost
    // (user-adjustable, see BruteforcePanel), and the UI clearly labels the feature ACTIVE (banner +
    // "(active)" menu suffix).
    private volatile int bruteforceDelayMs = 200;
    private volatile int bruteforceConcurrency = 1;
    private volatile int bruteforceMaxRequestsPerHost = 3000;

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

    public int getBruteforceDelayMs() { return bruteforceDelayMs; }
    // Upper bound matches the BruteforcePanel spinner's own max (60s/request) -- this setter is the
    // real contract (public, reachable from any future call site, not just the spinner), and was
    // previously one-sided: an absurd delay would park the Throttler's pace lock indefinitely with no
    // way to tell why, on the one feature CLAUDE.md documents as safety-critical.
    public void setBruteforceDelayMs(int ms) { this.bruteforceDelayMs = Math.max(0, Math.min(ms, 60_000)); }

    public int getBruteforceConcurrency() { return bruteforceConcurrency; }
    public void setBruteforceConcurrency(int n) { this.bruteforceConcurrency = Math.max(1, Math.min(n, 10)); }

    public int getBruteforceMaxRequestsPerHost() { return bruteforceMaxRequestsPerHost; }
    // Upper bound matches the BruteforcePanel spinner's own max -- same rationale as setBruteforceDelayMs
    // above: an unbounded budget defeats the per-host request cap that CLAUDE.md names as one of the
    // three mandatory target-load-safety requirements.
    public void setBruteforceMaxRequestsPerHost(int n) {
        this.bruteforceMaxRequestsPerHost = Math.max(1, Math.min(n, 20_000));
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
        int bruteforceDelayMs;
        int bruteforceConcurrency;
        int bruteforceMaxRequestsPerHost;
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
        d.bruteforceDelayMs = bruteforceDelayMs;
        d.bruteforceConcurrency = bruteforceConcurrency;
        d.bruteforceMaxRequestsPerHost = bruteforceMaxRequestsPerHost;
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
        s.bruteforceDelayMs = d.bruteforceDelayMs;   // already clamped when originally set/saved
        s.bruteforceConcurrency = d.bruteforceConcurrency == 0 ? 1 : d.bruteforceConcurrency;
        s.bruteforceMaxRequestsPerHost = d.bruteforceMaxRequestsPerHost == 0 ? 3000 : d.bruteforceMaxRequestsPerHost;
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
