package com.reconhub.active;

import java.util.ArrayList;
import java.util.EnumMap;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Endpoint × session matrix for Match &amp; Replace results (0.62.0): one row per target (method + host +
 * path), one column per session, each cell the latest result for that pair. Pure (no Swing / Montoya
 * calls on the results) so it is headless-tested.
 *
 * <p>Outcome per cell: SAME / BLOCKED / DIFFERENT (the verdict against the captured response), ERROR
 * (not sent), or NONE (no verdict). A row is <b>suspicious</b> when any non-baseline session got SAME --
 * another identity received what the captured user did.
 */
public final class MatrixModel {

    public enum Outcome { SAME, BLOCKED, DIFFERENT, ERROR, NONE }

    public record Row(String key, String method, String host, String path) {}

    private final List<Row> rows;
    private final List<String> columns;
    private final Map<String, MatchReplaceResult> cells;   // rowKey + "\n" + column

    private MatrixModel(List<Row> rows, List<String> columns, Map<String, MatchReplaceResult> cells) {
        this.rows = rows;
        this.columns = columns;
        this.cells = cells;
    }

    /** Builds the matrix; {@code columnOrder} (may be null) fixes column order, unknown sessions follow. */
    public static MatrixModel of(List<MatchReplaceResult> results, List<String> columnOrder) {
        Map<String, Row> rows = new LinkedHashMap<>();
        Set<String> cols = new LinkedHashSet<>();
        if (columnOrder != null) cols.addAll(columnOrder);
        Map<String, MatchReplaceResult> cells = new LinkedHashMap<>();
        for (MatchReplaceResult r : results) {
            String col = r.getIdentity() == null || r.getIdentity().isEmpty() ? "Custom" : r.getIdentity();
            cols.add(col);
            rows.putIfAbsent(r.targetKey(), new Row(r.targetKey(), r.getMethod(), r.getHost(), r.getPath()));
            String k = r.targetKey() + "\n" + col;
            MatchReplaceResult prev = cells.get(k);
            if (prev == null || r.getTimestamp() >= prev.getTimestamp()) cells.put(k, r);
        }
        return new MatrixModel(new ArrayList<>(rows.values()), new ArrayList<>(cols), cells);
    }

    public List<Row> rows() { return rows; }
    public List<String> columns() { return columns; }

    public MatchReplaceResult cell(Row row, String column) {
        return cells.get(row.key() + "\n" + column);
    }

    public static Outcome outcome(MatchReplaceResult r) {
        if (r == null) return Outcome.NONE;
        if (r.getError() != null) return Outcome.ERROR;
        if (r.getCompare() == null) return Outcome.NONE;
        return switch (r.getCompare().verdict()) {
            case SAME -> Outcome.SAME;
            case BLOCKED -> Outcome.BLOCKED;
            case DIFFERENT -> Outcome.DIFFERENT;
            default -> Outcome.NONE;
        };
    }

    /** The baseline column (the captured identity resent) is expected to match; it never makes a row suspicious. */
    public static boolean isBaseline(String column) {
        return SessionProfiles.ORIGINAL.equalsIgnoreCase(column);
    }

    /** True when any non-baseline session got the same response as the captured one. */
    public boolean suspicious(Row row) {
        return has(row, Set.of(Outcome.SAME));
    }

    /** True when any non-baseline cell of the row has one of {@code outcomes} (empty set = always true). */
    public boolean has(Row row, Set<Outcome> outcomes) {
        if (outcomes.isEmpty()) return true;
        for (String c : columns) {
            if (isBaseline(c)) continue;
            if (outcomes.contains(outcome(cell(row, c)))) return true;
        }
        return false;
    }

    /** Outcome counts over every non-baseline cell (errors counted in every column). */
    public Map<Outcome, Integer> counts() {
        Map<Outcome, Integer> m = new EnumMap<>(Outcome.class);
        for (Outcome o : Outcome.values()) m.put(o, 0);
        for (Map.Entry<String, MatchReplaceResult> e : cells.entrySet()) {
            String col = e.getKey().substring(e.getKey().indexOf('\n') + 1);
            Outcome o = outcome(e.getValue());
            if (isBaseline(col) && o != Outcome.ERROR) continue;
            m.merge(o, 1, Integer::sum);
        }
        return m;
    }

    /** Short cell text: "200 Same", "403 Blocked", "Error", "". */
    public static String cellText(MatchReplaceResult r, String column) {
        if (r == null) return "";
        Outcome o = outcome(r);
        if (o == Outcome.ERROR) return "Error";
        String status = r.getStatus() == 0 ? "" : String.valueOf(r.getStatus());
        if (isBaseline(column) || o == Outcome.NONE) return status;
        String label = switch (o) {
            case SAME -> "⚠ Same";
            case BLOCKED -> "Blocked";
            case DIFFERENT -> "Different";
            default -> "";
        };
        return (status + " " + label).trim();
    }
}
