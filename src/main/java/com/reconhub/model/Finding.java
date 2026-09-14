package com.reconhub.model;

/**
 * A secret / sensitive-information hit produced by {@code SecretScanner} or {@code JsAnalyzer}.
 *
 * <p>Dedup key = type + raw match, so the same leaked key found on many pages collapses to one row
 * (the location list is kept as a count via {@link #incrementSeen()}).
 */
public final class Finding {

    public enum Severity { HIGH, MEDIUM, LOW, INFO }

    private final String type;         // e.g. "AWS Access Key", "JWT", "Email"
    private final Severity severity;
    private final String rawMatch;     // the exact matched text (used for dedup, not shown raw)
    private final String masked;       // display-safe, partially masked value
    private final String locationUrl;  // where first seen
    private final String evidence;     // short surrounding snippet
    private volatile int timesSeen;

    public Finding(String type, Severity severity, String rawMatch,
                   String locationUrl, String evidence) {
        this.type = type;
        this.severity = severity;
        this.rawMatch = rawMatch;
        this.masked = mask(rawMatch);
        this.locationUrl = locationUrl;
        this.evidence = evidence;
        this.timesSeen = 1;
    }

    public static String key(String type, String rawMatch) {
        return type + "|" + rawMatch;
    }

    public String key() {
        return key(type, rawMatch);
    }

    public void incrementSeen() {
        this.timesSeen++;
    }

    /** Restore setter (used by state import). */
    public void setTimesSeen(int n) {
        this.timesSeen = n;
    }

    private static String mask(String s) {
        if (s == null) {
            return "";
        }
        if (s.length() <= 8) {
            return s.charAt(0) + "***";
        }
        int keep = 4;
        return s.substring(0, keep) + "…" + s.substring(s.length() - keep);
    }

    public String getType() { return type; }
    public Severity getSeverity() { return severity; }
    public String getMasked() { return masked; }
    public String getRawMatch() { return rawMatch; }
    public String getLocationUrl() { return locationUrl; }
    public String getEvidence() { return evidence; }
    public int getTimesSeen() { return timesSeen; }
}
