package com.reconhub.model;

import burp.api.montoya.http.message.HttpRequestResponse;

import java.net.URI;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * A secret / sensitive-information hit produced by {@code SecretScanner} or {@code JsAnalyzer}.
 *
 * <p>Dedup key = type + raw match, so the same leaked key found on many pages collapses to one row
 * (the location list is kept as a count via {@link #incrementSeen()}).
 */
public final class Finding {

    public enum Severity { HIGH, MEDIUM, LOW, INFO }

    /** Analyst triage state (workflow aid; persisted in state backups). */
    public enum Triage { NEW, REVIEWED, CONFIRMED, FALSE_POSITIVE }

    private final String type;         // e.g. "AWS Access Key", "JWT", "Email"
    private final Severity severity;
    private final String rawMatch;     // the exact matched text (used for dedup, not shown raw)
    private final String masked;       // display-safe, partially masked value
    private final String locationUrl;  // where first seen
    private final String evidence;     // short surrounding snippet
    private final boolean sensitive;   // whether the value is masked for display
    // AtomicInteger, not `volatile int` -- see Endpoint.observations for why (bruteforce concurrency
    // races this against the ingest thread).
    private final AtomicInteger timesSeen = new AtomicInteger(1);
    private volatile Triage triage = Triage.NEW;      // analyst triage state
    private volatile HttpRequestResponse messages;   // request/response the finding came from
    private volatile String host;      // derived lazily from locationUrl -- see getHost()

    /** Sensitive finding (e.g. a secret): the value is masked for display. */
    public Finding(String type, Severity severity, String rawMatch,
                   String locationUrl, String evidence) {
        this(type, severity, rawMatch, locationUrl, evidence, true);
    }

    /**
     * @param sensitive when false the value is not shown (the detail lives in {@code evidence}); use
     *                  for non-secret findings like misconfigurations, signatures and comments where
     *                  {@code rawMatch} is only a dedup key.
     */
    public Finding(String type, Severity severity, String rawMatch,
                   String locationUrl, String evidence, boolean sensitive) {
        this.type = type;
        this.severity = severity;
        this.rawMatch = rawMatch;
        this.sensitive = sensitive;
        this.masked = sensitive ? mask(rawMatch) : "";
        this.locationUrl = locationUrl;
        this.evidence = evidence;
    }

    public static String key(String type, String rawMatch) {
        return type + "|" + rawMatch;
    }

    public String key() {
        return key(type, rawMatch);
    }

    public void incrementSeen() {
        this.timesSeen.incrementAndGet();
    }

    /** Restore setter (used by state import). */
    public void setTimesSeen(int n) {
        this.timesSeen.set(n);
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

    public void setMessages(HttpRequestResponse m) { this.messages = m; }
    public void setTriage(Triage t) { this.triage = t == null ? Triage.NEW : t; }
    public Triage getTriage() { return triage; }

    /** Host of {@link #locationUrl}, lazily derived and cached (0.43.9) -- same pattern as
     * {@code ParameterInfo.getHost()}: {@code locationUrl} is immutable, so this only ever needs
     * computing once per instance rather than re-parsing the URL (via {@code core.Hosts.of}, previously
     * called directly by every caller) on every call. Deliberately duplicates {@code ParameterInfo}'s
     * own inline URI parsing rather than depending on {@code core.Hosts} from this package. Empty
     * string, never null, when the URL is null/blank/unparseable. */
    public String getHost() {
        String h = host;
        if (h == null) {
            h = deriveHost(locationUrl);
            host = h;
        }
        return h;
    }

    private static String deriveHost(String url) {
        if (url == null || url.isBlank()) {
            return "";
        }
        try {
            String h = URI.create(url).getHost();
            return h == null ? "" : h;
        } catch (RuntimeException ignored) {
            return "";
        }
    }

    public String getType() { return type; }
    public Severity getSeverity() { return severity; }
    public String getMasked() { return masked; }
    public String getRawMatch() { return rawMatch; }
    public String getLocationUrl() { return locationUrl; }
    public String getEvidence() { return evidence; }
    public int getTimesSeen() { return timesSeen.get(); }
    public boolean isSensitive() { return sensitive; }
    public HttpRequestResponse getMessages() { return messages; }
}
