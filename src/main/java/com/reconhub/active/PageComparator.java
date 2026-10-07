package com.reconhub.active;

import java.util.HashSet;
import java.util.Locale;
import java.util.Set;
import java.util.regex.Pattern;

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
    // Hoisted (0.43.9) -- String.replaceAll compiles a fresh Pattern on every call, and normalize() ran
    // all three on every probe's body (see BruteforceEngine.runWordlist), including -- before the
    // similarity(Set, String) overload above existed -- on the one baseline body compared against
    // every single probe.
    private static final Pattern PATHLIKE = Pattern.compile("/[a-z0-9_./%-]{2,}");
    private static final Pattern DIGITS = Pattern.compile("\\d+");
    private static final Pattern WHITESPACE = Pattern.compile("\\s+");

    private PageComparator() {}

    /** Similarity of two response bodies in [0,1] (1 = identical after normalization). */
    static double similarity(String a, String b) {
        return similarity(shinglesOf(a), b);
    }

    /**
     * Same as {@link #similarity(String, String)}, but takes the first body's shingles already
     * computed (0.43.9) -- {@code BruteforceEngine} compares every probe's body against the same fixed
     * baseline body for the life of a job (up to {@code bruteforceMaxRequestsPerHost}, 3000 by
     * default), and {@code shinglesOf} -- 3 {@code replaceAll} passes (each compiling its own
     * throwaway {@code Pattern} internally) plus a full shingle-set rebuild -- was being redone on that
     * same, never-changing baseline on every single probe. Compute {@link #shinglesOf} once for the
     * baseline and reuse this overload instead.
     */
    static double similarity(Set<String> baseShingles, String b) {
        Set<String> sb = shinglesOf(b);
        if (baseShingles.isEmpty() && sb.isEmpty()) {
            return 1.0;
        }
        if (baseShingles.isEmpty() || sb.isEmpty()) {
            return 0.0;
        }
        int inter = 0;
        for (String s : baseShingles) {
            if (sb.contains(s)) {
                inter++;
            }
        }
        int union = baseShingles.size() + sb.size() - inter;
        return union == 0 ? 1.0 : (double) inter / union;
    }

    /** Normalizes and shingles one body -- the expensive half of {@link #similarity}, exposed so a
     * caller comparing many bodies against one fixed baseline can compute the baseline's shingles once
     * (0.43.9) instead of on every comparison. */
    static Set<String> shinglesOf(String body) {
        return shingles(normalize(body));
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
        s = PATHLIKE.matcher(s).replaceAll(" ");
        s = DIGITS.matcher(s).replaceAll("");
        s = WHITESPACE.matcher(s).replaceAll(" ").trim();
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
