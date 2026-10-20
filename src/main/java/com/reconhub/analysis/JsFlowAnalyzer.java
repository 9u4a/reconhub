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
 * Turns the flat sink/source regex hits (see {@code resources/patterns/js-flow.json}) into <b>actionable
 * flow findings</b> (0.52.0): a dangerous sink (innerHTML, document.write, eval, ...) is paired with an
 * attacker-controllable source (location.hash/search, postMessage, ...) when the two appear within a
 * proximity window in the same JS body, and reported as one finding that says <i>source → sink, try X</i>
 * instead of two noisy inventory hits. Sinks marked {@code always} (eval/Function/string-setTimeout) are
 * inherently dangerous and reported even with no nearby source.
 *
 * <p>This is deliberately a <b>static/heuristic</b> proximity check, not a real taint/AST analysis
 * (ReconHub stays passive and doesn't parse JS) -- the {@code test} hint tells the analyst how to confirm
 * the flow by hand. Proximity can both miss (source and sink far apart / in other functions) and
 * over-flag (co-located but unrelated); it's a lead, not proof.
 */
public final class JsFlowAnalyzer {

    /** How far on each side of a sink to look for a source (chars). Generous enough to span a small
     * handler, tight enough that unrelated code usually doesn't bleed in. */
    static final int WINDOW = 600;
    /** Cap distinct (sink,source) findings per body so one bundle can't flood the tab. */
    private static final int MAX_PER_BODY = 40;

    private final DataStore store;
    private final PatternRegistry patterns;

    public JsFlowAnalyzer(DataStore store, PatternRegistry patterns) {
        this.store = store;
        this.patterns = patterns;
    }

    public void analyze(String body, String url, HttpRequestResponse messages) {
        if (body == null || body.isEmpty()) {
            return;
        }
        for (FlowHit h : findFlows(body, patterns.jsSources(), patterns.jsSinks())) {
            Finding f = new Finding(h.type(), h.severity(), h.rawMatch(), url, h.evidence(), false);
            f.setMessages(messages);
            store.recordFinding(f);
        }
    }

    /** One actionable finding: {@code type} (e.g. "DOM XSS: URL fragment → innerHTML"), the sink's
     * matched text, and an evidence line ending in a how-to-test hint. */
    public record FlowHit(String type, Finding.Severity severity, String rawMatch, String evidence) {}

    /** Pure/static for headless testing (no Montoya, no DataStore). */
    public static List<FlowHit> findFlows(String body, List<PatternRegistry.JsSource> sources,
                                          List<PatternRegistry.JsSink> sinks) {
        List<FlowHit> out = new ArrayList<>();
        Set<String> seen = new HashSet<>();   // one finding per (sink,source) kind per body
        for (PatternRegistry.JsSink sink : sinks) {
            Matcher m = sink.pattern.matcher(body);
            int hits = 0;
            while (m.find() && out.size() < MAX_PER_BODY && hits < 200) {
                hits++;
                PatternRegistry.JsSource src = nearestSource(body, m.start(), sources);
                if (src == null && !sink.always) {
                    continue;   // a non-"always" sink with no attacker source nearby is just noise
                }
                String key = sink.name + "|" + (src == null ? "" : src.name);
                if (!seen.add(key)) {
                    continue;
                }
                String type;
                String evidence;
                if (src != null) {
                    type = "DOM XSS: " + src.name + " -> " + sink.name;
                    evidence = "source " + src.name + " reaches sink " + sink.name
                            + "  |  Try: inject via " + src.inject + "; " + sink.test;
                } else {
                    type = sink.name + " sink (XSS if input is attacker-controlled)";
                    evidence = "Try: " + sink.test;
                }
                out.add(new FlowHit(type, sink.severity, m.group().trim(), evidence));
            }
        }
        return out;
    }

    private static PatternRegistry.JsSource nearestSource(String body, int sinkAt,
                                                          List<PatternRegistry.JsSource> sources) {
        int from = Math.max(0, sinkAt - WINDOW);
        int to = Math.min(body.length(), sinkAt + WINDOW);
        String region = body.substring(from, to);
        for (PatternRegistry.JsSource s : sources) {
            if (s.pattern.matcher(region).find()) {
                return s;
            }
        }
        return null;
    }
}
