package com.reconhub.analysis;

import com.reconhub.core.DataStore;
import com.reconhub.model.Finding;

import java.util.List;
import java.util.regex.Matcher;

/**
 * Scans a text body against a set of compiled rules and records {@link Finding}s. Reused for secret
 * patterns and for interesting-response signatures — the caller supplies the rule list.
 */
public final class SecretScanner {

    private static final int MAX_MATCHES_PER_RULE = 25;   // cap noise from one body
    private static final int EVIDENCE_RADIUS = 40;

    private final DataStore store;
    private final List<PatternRegistry.SecretRule> rules;
    private final boolean sensitive;

    /** @param sensitive true masks the matched value (secrets); false shows evidence (signatures). */
    public SecretScanner(DataStore store, List<PatternRegistry.SecretRule> rules, boolean sensitive) {
        this.store = store;
        this.rules = rules;
        this.sensitive = sensitive;
    }

    /**
     * @return number of newly discovered (previously unseen) findings in this body.
     */
    public int scan(String body, String locationUrl) {
        if (body == null || body.isEmpty()) {
            return 0;
        }
        int newCount = 0;
        for (PatternRegistry.SecretRule rule : rules) {
            Matcher m = rule.pattern.matcher(body);
            int hits = 0;
            while (m.find() && hits < MAX_MATCHES_PER_RULE) {
                hits++;
                String match = m.group().trim();
                if (match.isEmpty()) {
                    continue;
                }
                Finding f = new Finding(rule.name, rule.severity, match, locationUrl,
                        evidence(body, m.start(), m.end()), sensitive);
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
