package com.reconhub.analysis;

import burp.api.montoya.http.message.HttpRequestResponse;
import com.reconhub.core.DataStore;
import com.reconhub.model.Finding;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.regex.Matcher;

/**
 * Turns a piece of JS logic (an <b>anchor</b>: a client-side authz check, a crypto call, ...) plus a
 * concrete <b>target</b> extracted nearby (the gated route, the embedded key, ...) into one actionable
 * finding (0.53.0). The sibling of {@link JsFlowAnalyzer} for non-DOM-XSS families: where the flat
 * locator rules (js-crypto/js-authz/...) say "there's an authz check here", this says "this check gates
 * route /admin/x -- go test it server-side".
 *
 * <p>Static/heuristic proximity (see {@code js-pairs.json}), not a taint/AST analysis -- a lead whose
 * {@code note} tells the analyst how to confirm by hand. Only fires when a target is actually found near
 * the anchor; the anchor alone is already covered (with its own hint) by the flat rules.
 */
public final class JsPairAnalyzer {

    static final int WINDOW = 600;
    private static final int MAX_PER_BODY = 40;

    private final DataStore store;
    private final PatternRegistry patterns;

    public JsPairAnalyzer(DataStore store, PatternRegistry patterns) {
        this.store = store;
        this.patterns = patterns;
    }

    public void analyze(String body, String url, HttpRequestResponse messages) {
        if (body == null || body.isEmpty()) {
            return;
        }
        for (PairHit h : findPairs(body, patterns.jsPairs())) {
            Finding f = new Finding(h.type(), h.severity(), h.rawMatch(), url, h.evidence(), false);
            f.setMessages(messages);
            store.recordFinding(f);
        }
    }

    /** One actionable pairing: {@code type} (e.g. "Client-side authorization gate → route"), the
     * extracted target as {@code rawMatch}, and an evidence line ending in the how-to-use hint. */
    public record PairHit(String type, Finding.Severity severity, String rawMatch, String evidence) {}

    /** Pure/static for headless testing. For each anchor match, extract the nearest target (group 1 if
     * the target pattern has one) within the window; dedup per (pair,target) per body. */
    public static List<PairHit> findPairs(String body, List<PatternRegistry.JsPair> pairs) {
        List<PairHit> out = new ArrayList<>();
        Set<String> seen = new HashSet<>();
        for (PatternRegistry.JsPair pair : pairs) {
            Matcher am = pair.anchor.matcher(body);
            int anchors = 0;
            while (am.find() && out.size() < MAX_PER_BODY && anchors < 200) {
                anchors++;
                String target = nearestTarget(body, am.start(), am.end(), pair.target);
                if (target == null) {
                    continue;   // anchor alone is already covered by the flat locator rules
                }
                if (!seen.add(pair.name + "|" + target)) {
                    continue;
                }
                String evidence = "target \"" + target + "\" near the matched logic  |  Try: " + pair.note;
                out.add(new PairHit(pair.name + ": " + target, pair.severity, target, evidence));
            }
        }
        return out;
    }

    private static String nearestTarget(String body, int anchorStart, int anchorEnd,
                                        java.util.regex.Pattern target) {
        int from = Math.max(0, anchorStart - WINDOW);
        int to = Math.min(body.length(), anchorEnd + WINDOW);
        Matcher tm = target.matcher(body.substring(from, to));
        if (tm.find()) {
            return (tm.groupCount() >= 1 && tm.group(1) != null ? tm.group(1) : tm.group()).trim();
        }
        return null;
    }
}
