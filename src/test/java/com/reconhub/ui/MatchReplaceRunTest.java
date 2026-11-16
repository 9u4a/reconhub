package com.reconhub.ui;

import com.reconhub.active.MatchReplaceEngine;
import com.reconhub.active.MatchReplaceJob;
import com.reconhub.active.MatchReplaceRule;
import com.reconhub.active.MatchReplaceTarget;
import com.reconhub.active.RunIdentity;
import com.reconhub.active.SessionProfiles;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** 0.61.0 multi-session run: identity assembly, line diff, estimate, run labels. Headless. */
class MatchReplaceRunTest {

    @Test
    void identitiesCombineSessionRulesWithExtraRules() {
        SessionProfiles s = new SessionProfiles();
        s.put(new SessionProfiles.Identity("bob", Map.of("Authorization", "Bearer B"), Map.of(), "t", 0));
        MatchReplaceRule extra = new MatchReplaceRule(MatchReplaceRule.Mode.HEADER, "X-Test", "", false, "1", true);
        List<RunIdentity> ids = MatchReplaceDialog.identities(List.of("Original", "No auth", "bob", "ghost"), s, List.of(extra));
        assertEquals(List.of("Original", "No auth", "bob"), ids.stream().map(RunIdentity::name).toList());
        assertEquals(List.of(extra), ids.get(0).rules(), "Original = only the extra rules");
        assertEquals(extra, ids.get(2).rules().get(ids.get(2).rules().size() - 1), "extra rules come last");
    }

    @Test
    void lineDiffMarksOnlyChangedLines() {
        List<LineDiff.Line> d = LineDiff.diff("GET / HTTP/1.1\nHost: a\nCookie: sid=A\nAccept: */*",
                "GET / HTTP/1.1\nHost: a\nAccept: */*\nCookie: sid=B");
        assertEquals(List.of(LineDiff.Op.SAME, LineDiff.Op.SAME, LineDiff.Op.REMOVED, LineDiff.Op.SAME, LineDiff.Op.ADDED),
                d.stream().map(LineDiff.Line::op).toList());
        assertEquals(2, LineDiff.changes(d));
        assertEquals(0, LineDiff.changes(LineDiff.diff("a\nb", "a\nb")));
    }

    @Test
    void lineDiffFallsBackPositionallyOnHugeInput() {
        String big = "x\n".repeat(LineDiff.MAX_LINES + 10);
        List<LineDiff.Line> d = LineDiff.diff(big, big + "y");
        assertTrue(LineDiff.changes(d) >= 1);
        assertTrue(d.size() >= LineDiff.MAX_LINES);
    }

    @Test
    void estimateIsPacedByDelayNotConcurrency() {
        assertEquals(0, MatchReplaceEngine.estimateSeconds(1, 500));
        assertEquals(18, MatchReplaceEngine.estimateSeconds(37, 500));
        assertEquals("2 min 5 s", MatchReplaceDialog.human(125));
    }

    @Test
    void jobLabelCountsTargetsAndSessions() {
        MatchReplaceTarget t = new MatchReplaceTarget("h", "/a", "GET", null);
        MatchReplaceJob job = new MatchReplaceJob(3, List.of(t, t), List.of(new RunIdentity("A", List.of()),
                new RunIdentity("B", List.of()), new RunIdentity("C", List.of())), 6);
        assertEquals("#3 · 2 targets × 3 sessions", job.label());
        assertEquals(6, job.getTotal());
        assertTrue(job.getIdentities().size() == 3);
    }
}
