package com.reconhub.core;

import com.reconhub.analysis.FindingTaxonomy;
import com.reconhub.model.Finding;

import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.EnumSet;
import java.util.Set;

/**
 * Mutable, shared runtime configuration edited from the Settings panel. All fields are volatile so
 * the ingestion threads see UI changes immediately.
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
            EnumSet.noneOf(FindingTaxonomy.Category.class);

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
}
