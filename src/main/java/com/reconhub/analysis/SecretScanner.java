package com.reconhub.analysis;

import com.reconhub.core.DataStore;
import com.reconhub.model.Finding;

import java.util.regex.Matcher;

/**
 * Scans a text body against the compiled secret patterns and records {@link Finding}s.
 * Shared by the response scanner and the JS analyzer.
 */
public final class SecretScanner {

    private static final int MAX_MATCHES_PER_RULE = 25;   // cap noise from one body
    private static final int EVIDENCE_RADIUS = 40;

    private final DataStore store;
    private final PatternRegistry patterns;

    public SecretScanner(DataStore store, PatternRegistry patterns) {
        this.store = store;
        this.patterns = patterns;
    }

    /**
     * @return number of newly discovered (previously unseen) findings in this body.
     */
    public int scan(String body, String locationUrl) {
        if (body == null || body.isEmpty()) {
            return 0;
        }
        int newCount = 0;
        for (PatternRegistry.SecretRule rule : patterns.secretRules()) {
            Matcher m = rule.pattern.matcher(body);
            int hits = 0;
            while (m.find() && hits < MAX_MATCHES_PER_RULE) {
                hits++;
                String match = m.group().trim();
                if (match.isEmpty()) {
                    continue;
                }
                Finding f = new Finding(rule.name, rule.severity, match, locationUrl,
                        evidence(body, m.start(), m.end()));
                if (store.recordFinding(f)) {
                    newCount++;
                }
            }
        }
        return newCount;
    }

    private static String evidence(String body, int start, int end) {
        int from = Math.max(0, start - EVIDENCE_RADIUS);
        int to = Math.min(body.length(), end + EVIDENCE_RADIUS);
        String snippet = body.substring(from, to).replaceAll("\\s+", " ").trim();
        return (from > 0 ? "…" : "") + snippet + (to < body.length() ? "…" : "");
    }
}
