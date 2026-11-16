package com.reconhub.ui;

import java.util.ArrayList;
import java.util.List;

/**
 * Line-level diff for the Match &amp; Replace preview (0.61.0): which lines of the request were removed,
 * added, or kept. Plain LCS -- requests are small; above {@link #MAX_LINES} lines per side it falls back
 * to a positional comparison so a huge body can't stall the dialog. Pure, headless-tested.
 */
final class LineDiff {

    static final int MAX_LINES = 800;

    enum Op { SAME, REMOVED, ADDED }

    record Line(Op op, String text) {}

    private LineDiff() {}

    static List<Line> diff(String before, String after) {
        String[] a = split(before);
        String[] b = split(after);
        if (a.length > MAX_LINES || b.length > MAX_LINES) {
            return positional(a, b);
        }
        int[][] lcs = new int[a.length + 1][b.length + 1];
        for (int i = a.length - 1; i >= 0; i--) {
            for (int j = b.length - 1; j >= 0; j--) {
                lcs[i][j] = a[i].equals(b[j]) ? lcs[i + 1][j + 1] + 1 : Math.max(lcs[i + 1][j], lcs[i][j + 1]);
            }
        }
        List<Line> out = new ArrayList<>();
        int i = 0;
        int j = 0;
        while (i < a.length && j < b.length) {
            if (a[i].equals(b[j])) {
                out.add(new Line(Op.SAME, a[i]));
                i++;
                j++;
            } else if (lcs[i + 1][j] >= lcs[i][j + 1]) {
                out.add(new Line(Op.REMOVED, a[i++]));
            } else {
                out.add(new Line(Op.ADDED, b[j++]));
            }
        }
        while (i < a.length) out.add(new Line(Op.REMOVED, a[i++]));
        while (j < b.length) out.add(new Line(Op.ADDED, b[j++]));
        return out;
    }

    /** Lines that changed (removed + added), for a one-line summary. */
    static int changes(List<Line> lines) {
        int n = 0;
        for (Line l : lines) if (l.op() != Op.SAME) n++;
        return n;
    }

    private static List<Line> positional(String[] a, String[] b) {
        List<Line> out = new ArrayList<>();
        int n = Math.max(a.length, b.length);
        for (int i = 0; i < n; i++) {
            String x = i < a.length ? a[i] : null;
            String y = i < b.length ? b[i] : null;
            if (x != null && x.equals(y)) {
                out.add(new Line(Op.SAME, x));
            } else {
                if (x != null) out.add(new Line(Op.REMOVED, x));
                if (y != null) out.add(new Line(Op.ADDED, y));
            }
        }
        return out;
    }

    private static String[] split(String s) {
        if (s == null || s.isEmpty()) return new String[0];
        return s.replace("\r\n", "\n").split("\n", -1);
    }
}
