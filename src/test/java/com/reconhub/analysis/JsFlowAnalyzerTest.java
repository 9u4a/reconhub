package com.reconhub.analysis;

import com.reconhub.model.Finding;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.regex.Pattern;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * {@code JsFlowAnalyzer.findFlows} (0.52.0) -- the source→sink proximity pairing. Pure/static, headless;
 * uses hand-built sources/sinks so it doesn't depend on the shipped js-flow.json wording.
 */
class JsFlowAnalyzerTest {

    private static PatternRegistry.JsSource src(String name, String regex, String inject) {
        return new PatternRegistry.JsSource(name, Pattern.compile(regex), inject);
    }

    private static PatternRegistry.JsSink sink(String name, String regex, boolean always) {
        return new PatternRegistry.JsSink(name, Pattern.compile(regex), Finding.Severity.HIGH, "do X", always);
    }

    private static final List<PatternRegistry.JsSource> SOURCES =
            List.of(src("URL fragment", "location\\.hash", "the fragment"));
    private static final List<PatternRegistry.JsSink> SINKS = List.of(
            sink("innerHTML", "\\.innerHTML\\s*=", false),
            sink("eval()", "\\beval\\s*\\(", true));

    @Test
    void sourceNearSinkIsPairedAsFlow() {
        String body = "var x = location.hash; el.innerHTML = x;";
        List<JsFlowAnalyzer.FlowHit> hits = JsFlowAnalyzer.findFlows(body, SOURCES, SINKS);
        assertTrue(hits.stream().anyMatch(h -> h.type().equals("DOM XSS: URL fragment -> innerHTML")),
                hits.toString());
        // the flow evidence carries the how-to-test hint
        assertTrue(hits.stream().anyMatch(h -> h.evidence().contains("Try: inject via the fragment")),
                hits.toString());
    }

    @Test
    void nonAlwaysSinkWithNoNearbySourceIsDropped() {
        String body = "el.innerHTML = someLocalTemplate;";   // no source anywhere
        List<JsFlowAnalyzer.FlowHit> hits = JsFlowAnalyzer.findFlows(body, SOURCES, SINKS);
        assertFalse(hits.stream().anyMatch(h -> h.type().contains("innerHTML")),
                "innerHTML with no source nearby should be dropped as noise: " + hits);
    }

    @Test
    void alwaysSinkReportedEvenWithoutSource() {
        String body = "eval(decodeURIComponent(s));";
        List<JsFlowAnalyzer.FlowHit> hits = JsFlowAnalyzer.findFlows(body, SOURCES, SINKS);
        assertEquals(1, hits.size());
        assertTrue(hits.get(0).type().startsWith("eval() sink"), hits.toString());
        assertTrue(hits.get(0).evidence().startsWith("Try: do X"), hits.toString());
    }

    @Test
    void farApartSourceAndSinkAreNotPaired() {
        // source and sink separated by more than the proximity window -> not a flow.
        String body = "location.hash;" + "x".repeat(JsFlowAnalyzer.WINDOW + 50) + "el.innerHTML = y;";
        List<JsFlowAnalyzer.FlowHit> hits = JsFlowAnalyzer.findFlows(body, SOURCES, SINKS);
        assertFalse(hits.stream().anyMatch(h -> h.type().contains("innerHTML")), hits.toString());
    }

    @Test
    void oneFindingPerSinkSourceKindPerBody() {
        // many innerHTML+hash occurrences collapse to a single finding (noise cap).
        String one = "location.hash; el.innerHTML = x; ";
        String body = one.repeat(10);
        List<JsFlowAnalyzer.FlowHit> hits = JsFlowAnalyzer.findFlows(body, SOURCES, SINKS);
        assertEquals(1, hits.stream().filter(h -> h.type().contains("innerHTML")).count(), hits.toString());
    }
}
