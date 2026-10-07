package com.reconhub.analysis;

import burp.api.montoya.http.message.HttpRequestResponse;
import com.reconhub.core.DataStore;
import com.reconhub.model.Finding;

import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Scans a text body against a set of compiled rules and records {@link Finding}s. Reused for secret
 * patterns and for interesting-response signatures — the caller supplies the rule list.
 */
public final class SecretScanner {

    private static final int MAX_MATCHES_PER_RULE = 25;   // cap noise from one body
    private static final int EVIDENCE_RADIUS = 24;         // short surrounding context
    // 0.43.7: unlike ApiSpecAnalyzer (MAX_BODY) and SourceMapDetector (MAX_SNIFF), nothing capped the
    // size of body this scans -- and it's instantiated 4x (secrets/signatures/authz/user rules) and run
    // against the same response, so one huge body meant 4 x rules.size() full-body regex passes with no
    // ceiling. Matches ApiSpecAnalyzer/SourceMapDetector's "skip above this, don't truncate" precedent.
    private static final int MAX_SCAN_CHARS = 10_000_000;
    private static final Pattern WHITESPACE = Pattern.compile("\\s+");

    private final DataStore store;
    private final List<PatternRegistry.SecretRule> rules;
    private final boolean sensitive;

    /** @param sensitive true masks the matched value (secrets); false shows evidence (signatures). */
    public SecretScanner(DataStore store, List<PatternRegistry.SecretRule> rules, boolean sensitive) {
        this.store = store;
        this.rules = rules;
        this.sensitive = sensitive;
    }

    public int scan(String body, String locationUrl) {
        return scan(body, locationUrl, null);
    }

    /**
     * @return number of newly discovered (previously unseen) findings in this body.
     */
    public int scan(String body, String locationUrl, HttpRequestResponse messages) {
        if (body == null || body.isEmpty() || body.length() > MAX_SCAN_CHARS) {
            return 0;
        }
        int newCount = 0;
        for (PatternRegistry.SecretRule rule : rules) {
            Matcher m = rule.pattern.matcher(body);
            int hits = 0;
            while (hits < MAX_MATCHES_PER_RULE && m.find()) {
                hits++;
                String match = m.group().trim();
                if (match.isEmpty()) {
                    continue;
                }
                Finding f = new Finding(rule.name, rule.severity, match, locationUrl,
                        evidence(body, m.start(), m.end()), sensitive);
                f.setMessages(messages);
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
        String snippet = WHITESPACE.matcher(body.substring(from, to)).replaceAll(" ").trim();
        return (from > 0 ? "…" : "") + snippet + (to < body.length() ? "…" : "");
    }
}
