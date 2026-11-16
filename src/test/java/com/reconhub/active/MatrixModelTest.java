package com.reconhub.active;

import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** {@link MatrixModel} (0.62.0): endpoint × session aggregation, outcomes, suspicious rows, counts. */
class MatrixModelTest {

    private static final String BODY = "{\"id\":42,\"email\":\"a@x.example\",\"items\":[1,2,3]}";

    private static MatchReplaceResult sent(String path, String identity, int status, String body, long t) {
        ResponseCompare.Result cmp = ResponseCompare.compare(200, BODY, BODY.length(), status, body,
                body == null ? 0 : body.length(), null);
        return new MatchReplaceResult("h", path, "GET", status, body == null ? 0 : body.length(), t, null, null, cmp, null)
                .tag(identity, 1);
    }

    private static MatchReplaceResult error(String path, String identity) {
        return MatchReplaceResult.failed("h", path, "GET", "out of scope").tag(identity, 1);
    }

    @Test
    void rowsColumnsAndLatestCellWin() {
        List<MatchReplaceResult> rs = List.of(
                sent("/a", "Original", 200, BODY, 1),
                sent("/a", "No auth", 401, "{}", 2),
                sent("/a", "bob", 200, BODY, 3),
                sent("/b", "bob", 403, "no", 4),
                sent("/a", "No auth", 200, BODY, 5));   // later result for the same cell wins
        MatrixModel m = MatrixModel.of(rs, List.of("Original", "No auth", "bob"));
        assertEquals(List.of("Original", "No auth", "bob"), m.columns());
        assertEquals(List.of("GET h/a", "GET h/b"), m.rows().stream().map(MatrixModel.Row::key).toList());
        MatrixModel.Row a = m.rows().get(0);
        assertEquals(MatrixModel.Outcome.SAME, MatrixModel.outcome(m.cell(a, "No auth")));
        assertNull(m.cell(m.rows().get(1), "Original"));
    }

    @Test
    void suspiciousIgnoresTheBaselineColumn() {
        MatrixModel m = MatrixModel.of(List.of(
                sent("/a", "Original", 200, BODY, 1),
                sent("/a", "No auth", 401, "{}", 2),
                sent("/b", "Original", 200, BODY, 3),
                sent("/b", "bob", 200, BODY, 4)), null);
        assertFalse(m.suspicious(m.rows().get(0)), "Original matching itself is expected");
        assertTrue(m.suspicious(m.rows().get(1)));
        assertTrue(m.has(m.rows().get(0), Set.of(MatrixModel.Outcome.BLOCKED)));
        assertTrue(m.has(m.rows().get(0), Set.of()), "empty filter = every row");
    }

    @Test
    void countsSkipBaselineVerdictsButKeepErrors() {
        MatrixModel m = MatrixModel.of(List.of(
                sent("/a", "Original", 200, BODY, 1),
                sent("/a", "bob", 200, BODY, 2),
                sent("/a", "No auth", 403, "x", 3),
                error("/b", "Original"),
                error("/b", "bob")), null);
        Map<MatrixModel.Outcome, Integer> c = m.counts();
        assertEquals(1, c.get(MatrixModel.Outcome.SAME));
        assertEquals(1, c.get(MatrixModel.Outcome.BLOCKED));
        assertEquals(2, c.get(MatrixModel.Outcome.ERROR));
    }

    @Test
    void cellTextShowsStatusAndVerdict() {
        assertEquals("200 ⚠ Same", MatrixModel.cellText(sent("/a", "bob", 200, BODY, 1), "bob"));
        assertEquals("200", MatrixModel.cellText(sent("/a", "Original", 200, BODY, 1), "Original"));
        assertEquals("Error", MatrixModel.cellText(error("/a", "bob"), "bob"));
        assertEquals("", MatrixModel.cellText(null, "bob"));
    }

    @Test
    void untaggedResultsGoToCustomColumn() {
        MatchReplaceResult legacy = new MatchReplaceResult("h", "/x", "GET", 200, 1, 1, null, null);
        MatrixModel m = MatrixModel.of(List.of(legacy), null);
        assertEquals(List.of("Custom"), m.columns());
    }
}
