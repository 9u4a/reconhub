package com.reconhub.active;

import java.util.HashSet;
import java.util.Locale;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * Authorization-test verdict for a Match & Replace resend (0.57.0): compares the replayed response with the
 * originally captured one, Autorize-style. Typical use -- resend with another account's session or with no
 * session at all: {@link Verdict#SAME} means the other identity got the same data back (authz bypass
 * suspected), {@link Verdict#BLOCKED} means it was refused (401/403 or a redirect to login). Pure and
 * Montoya-free for headless testing; the engine runs it on the send thread, never the EDT.
 */
public final class ResponseCompare {

    public enum Verdict {
        SAME("Same"), DIFFERENT("Different"), BLOCKED("Blocked"), NA("n/a");

        private final String label;

        Verdict(String label) {
            this.label = label;
        }

        public String label() {
            return label;
        }
    }

    /** {@code similarity} in [0,1]; -1 when not compared ({@link Verdict#NA}). */
    public record Result(Verdict verdict, int origStatus, int lengthDelta, double similarity) {
    }

    static final double SAME_THRESHOLD = 0.90;
    static final int MAX_CHARS = 256 * 1024;
    private static final int MAX_TOKENS = 20_000;
    private static final Pattern LOGIN_LOCATION =
            Pattern.compile("(?i)(?:login|log-in|signin|sign-in|logon|/auth|sso|session/new)");
    // Values that differ on every response (timestamps, ids, nonces, CSRF tokens) -- normalized away so they
    // don't drag a same-data response under the threshold.
    private static final Pattern LONG_NUMBER = Pattern.compile("\\d{8,40}");
    private static final Pattern LONG_HEX = Pattern.compile("(?i)[0-9a-f-]{32,80}");
    private static final Pattern TOKEN_SPLIT = Pattern.compile("[\\r\\n,;{}\\[\\]<>]+");

    private ResponseCompare() {
    }

    /**
     * @param origStatus 0 when the original has no response (then {@link Verdict#NA})
     * @param newStatus 0 when the resend got no response (then {@link Verdict#NA})
     * @param newLocation the resend's Location header, or null
     */
    public static Result compare(int origStatus, String origBody, int origLength,
                                 int newStatus, String newBody, int newLength, String newLocation) {
        int delta = newLength - origLength;
        if (origStatus == 0 || newStatus == 0) {
            return new Result(Verdict.NA, origStatus, delta, -1);
        }
        if (newStatus == 401 || newStatus == 403
                || (newStatus >= 300 && newStatus < 400 && origStatus != newStatus && newLocation != null
                    && LOGIN_LOCATION.matcher(newLocation).find())) {
            return new Result(Verdict.BLOCKED, origStatus, delta, similarity(origBody, newBody));
        }
        double sim = similarity(origBody, newBody);
        Verdict v = origStatus == newStatus && sim >= SAME_THRESHOLD ? Verdict.SAME : Verdict.DIFFERENT;
        return new Result(v, origStatus, delta, sim);
    }

    /** Length ratio x token-set Jaccard over the normalized bodies; 1.0 for two empty bodies. */
    static double similarity(String a, String b) {
        String x = normalize(a);
        String y = normalize(b);
        if (x.isEmpty() && y.isEmpty()) {
            return 1.0;
        }
        if (x.isEmpty() || y.isEmpty()) {
            return 0.0;
        }
        double lengthRatio = (double) Math.min(x.length(), y.length()) / Math.max(x.length(), y.length());
        Set<String> tx = tokens(x);
        Set<String> ty = tokens(y);
        if (tx.isEmpty() && ty.isEmpty()) {
            return lengthRatio;
        }
        Set<String> union = new HashSet<>(tx);
        union.addAll(ty);
        int inter = 0;
        for (String t : tx) {
            if (ty.contains(t)) {
                inter++;
            }
        }
        return lengthRatio * ((double) inter / union.size());
    }

    private static String normalize(String s) {
        if (s == null) {
            return "";
        }
        String t = s.length() > MAX_CHARS ? s.substring(0, MAX_CHARS) : s;
        t = LONG_HEX.matcher(t).replaceAll("#");
        return LONG_NUMBER.matcher(t).replaceAll("0");
    }

    private static Set<String> tokens(String s) {
        Set<String> out = new HashSet<>();
        for (String t : TOKEN_SPLIT.split(s)) {
            String v = t.strip();
            if (!v.isEmpty()) {
                out.add(v.toLowerCase(Locale.ROOT));
                if (out.size() >= MAX_TOKENS) {
                    break;
                }
            }
        }
        return out;
    }
}
