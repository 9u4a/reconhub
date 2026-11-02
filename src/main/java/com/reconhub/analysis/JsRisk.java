package com.reconhub.analysis;

import com.reconhub.model.Finding;

import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Per-JS-file priority (0.55.0): which bundle to read first. A file's score is the severity-weighted sum
 * of the findings located at it, with a bonus for a source→sink DOM XSS flow (the most directly testable
 * JS lead). Pure/static, headless-tested ({@code JsRiskTest}).
 */
public final class JsRisk {

    private JsRisk() {}

    static final int FLOW_BONUS = 5;

    /** Findings count + risk score for one JS file. */
    public record Stat(int findings, int score) {
        static final Stat EMPTY = new Stat(0, 0);
    }

    public static int weight(Finding f) {
        int w = switch (f.getSeverity()) {
            case HIGH -> 10;
            case MEDIUM -> 4;
            case LOW -> 1;
            default -> 0;
        };
        String type = f.getType();
        if (type != null && type.startsWith("DOM XSS:")) {
            w += FLOW_BONUS;
        }
        return w;
    }

    /** {@code locationUrl → Stat} over {@code findings}. */
    public static Map<String, Stat> byLocation(List<Finding> findings) {
        Map<String, int[]> acc = new HashMap<>();
        for (Finding f : findings) {
            String loc = f.getLocationUrl();
            if (loc == null) {
                continue;
            }
            int[] a = acc.computeIfAbsent(loc, k -> new int[2]);
            a[0]++;
            a[1] += weight(f);
        }
        Map<String, Stat> out = new HashMap<>(acc.size() * 2);
        acc.forEach((k, a) -> out.put(k, new Stat(a[0], a[1])));
        return out;
    }

    public static Stat of(Map<String, Stat> byLocation, String url) {
        Stat s = url == null ? null : byLocation.get(url);
        return s == null ? Stat.EMPTY : s;
    }

    /**
     * Identity memo of {@link #byLocation}: {@code DataStore.snapshotFindings()} returns the same list
     * instance until the findings key set changes, so an unchanged refresh tick reuses the last map.
     * EDT-only (panel refresh/paint).
     */
    public static final class Memo {
        private List<Finding> lastSource;
        private Map<String, Stat> last = Collections.emptyMap();

        public Map<String, Stat> get(List<Finding> findings) {
            if (findings != lastSource) {
                last = byLocation(findings);
                lastSource = findings;
            }
            return last;
        }
    }
}
