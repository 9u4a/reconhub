package com.reconhub.active;

import java.util.HashSet;
import java.util.Locale;
import java.util.Set;

/**
 * Response-body similarity for the bruteforce soft-404 check. A raw length-tolerance comparison is
 * fooled the moment a "not found" page embeds anything path-dependent (the requested path echoed back,
 * a timestamp, a CSRF token, random related-content) — the length shifts by more than any reasonable
 * tolerance on nearly every probe, so almost everything looks "different from baseline" and gets
 * misreported as a hit. Comparing normalized text similarity instead absorbs that kind of per-request
 * churn while still catching a genuinely different page.
 *
 * <p>Bodies are normalized (lowercased, digit runs stripped, whitespace collapsed) and compared with a
 * word-shingle Jaccard similarity — O(n), safe on large bodies. A baseline self-similarity (the
 * baseline path fetched twice) sets an adaptive "same as baseline" threshold so a churny soft-404 page
 * doesn't produce false hits. Independent of (but the same technique as) the sibling InjectScope
 * extension's {@code detect.PageComparator} — no cross-extension source dependency.
 */
final class PageComparator {

    private static final int SHINGLE = 2;
    private static final double CEILING = 0.95;
    private static final double MARGIN = 0.03;

    private PageComparator() {}

    /** Similarity of two response bodies in [0,1] (1 = identical after normalization). */
    static double similarity(String a, String b) {
        Set<String> sa = shingles(normalize(a));
        Set<String> sb = shingles(normalize(b));
        if (sa.isEmpty() && sb.isEmpty()) {
            return 1.0;
        }
        if (sa.isEmpty() || sb.isEmpty()) {
            return 0.0;
        }
        int inter = 0;
        for (String s : sa) {
            if (sb.contains(s)) {
                inter++;
            }
        }
        int union = sa.size() + sb.size() - inter;
        return union == 0 ? 1.0 : (double) inter / union;
    }

    /** Threshold for "same as baseline", derived from the baseline's own self-similarity. */
    static double stableThreshold(double selfSimilarity) {
        return Math.min(CEILING, selfSimilarity - MARGIN);
    }

    private static String normalize(String body) {
        if (body == null) {
            return "";
        }
        String s = body.toLowerCase(Locale.ROOT);
        // Strip path-like tokens first (a soft-404 page very often echoes the requested path back --
        // "/admin/dashboard" vs "/__reconhub_483920__" -- which would otherwise register as one
        // strongly differing "word" per probe and drag down an otherwise-identical page's similarity,
        // especially on short bodies where that one token is a large share of the content).
        s = s.replaceAll("/[a-z0-9_./%-]{2,}", " ");
        s = s.replaceAll("\\d+", "");
        s = s.replaceAll("\\s+", " ").trim();
        return s;
    }

    private static Set<String> shingles(String norm) {
        Set<String> out = new HashSet<>();
        if (norm.isEmpty()) {
            return out;
        }
        String[] words = norm.split(" ");
        if (words.length < SHINGLE) {
            for (String w : words) {
                if (!w.isEmpty()) {
                    out.add(w);
                }
            }
            return out;
        }
        for (int i = 0; i + SHINGLE <= words.length; i++) {
            out.add(words[i] + " " + words[i + 1]);
        }
        return out;
    }
}
