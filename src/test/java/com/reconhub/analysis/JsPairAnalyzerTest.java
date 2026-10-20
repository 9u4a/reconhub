package com.reconhub.analysis;

import com.reconhub.model.Finding;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.regex.Pattern;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * {@code JsPairAnalyzer.findPairs} (0.53.0) -- anchor→target proximity extraction. Pure/static,
 * headless; uses hand-built pairs so it doesn't depend on the shipped js-pairs.json wording.
 */
class JsPairAnalyzerTest {

    private static PatternRegistry.JsPair pair(String name, String anchor, String target) {
        return new PatternRegistry.JsPair(name, Finding.Severity.MEDIUM,
                Pattern.compile(anchor), Pattern.compile(target), "do X");
    }

    private static final List<PatternRegistry.JsPair> PAIRS = List.of(
            pair("authz gate", "isAdmin|requireRole", "[\"'](/[A-Za-z0-9_/-]{1,40})[\"']"));

    @Test
    void extractsTargetNearAnchor() {
        String body = "const AdminRoute = requireRole('admin')(withPath('/admin/users'));";
        List<JsPairAnalyzer.PairHit> hits = JsPairAnalyzer.findPairs(body, PAIRS);
        assertEquals(1, hits.size());
        assertEquals("/admin/users", hits.get(0).rawMatch());
        assertTrue(hits.get(0).type().startsWith("authz gate: /admin/users"), hits.toString());
        assertTrue(hits.get(0).evidence().contains("Try: do X"), hits.toString());
    }

    @Test
    void noTargetNearAnchorIsNotReported() {
        String body = "if (isAdmin()) { renderMenu(); }";   // no quoted path nearby
        assertTrue(JsPairAnalyzer.findPairs(body, PAIRS).isEmpty());
    }

    @Test
    void targetFarFromAnchorIsNotPaired() {
        String body = "isAdmin();" + "x".repeat(JsPairAnalyzer.WINDOW + 50) + "'/admin/secret';";
        assertTrue(JsPairAnalyzer.findPairs(body, PAIRS).isEmpty());
    }

    @Test
    void dedupsSameTargetPerBody() {
        String unit = "requireRole('x')('/admin/a'); ";
        List<JsPairAnalyzer.PairHit> hits = JsPairAnalyzer.findPairs(unit.repeat(8), PAIRS);
        assertEquals(1, hits.stream().filter(h -> h.rawMatch().equals("/admin/a")).count(), hits.toString());
    }

    @Test
    void usesCapturingGroupOneAsTheTarget() {
        // target regex has a group -- the extracted value is the group, not the full quoted match.
        String body = "requireRole('r'); fetch('/api/admin/delete');";
        List<JsPairAnalyzer.PairHit> hits = JsPairAnalyzer.findPairs(body, PAIRS);
        assertFalse(hits.isEmpty());
        assertEquals("/api/admin/delete", hits.get(0).rawMatch());   // no surrounding quotes
    }
}
