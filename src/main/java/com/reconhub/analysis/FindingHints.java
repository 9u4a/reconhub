package com.reconhub.analysis;

import com.google.gson.Gson;
import com.reconhub.model.Finding;

import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * How-to-test hints for every finding (0.56.0). A finding whose evidence already carries a {@code Try:} hint
 * (secrets with a note, JS findings, routes, leads) keeps its own; every other type gets the first matching
 * entry of {@code finding-hints.json} (case-insensitive substring of the type). Applied at display/export
 * time only -- evidence and state files are never rewritten, so old data gets hints immediately.
 */
public final class FindingHints {

    static final String TRY = "Try:";

    private static final List<String[]> HINTS = load();   // {lowercased match, hint}
    // Cached by type (a handful of distinct types, rendered every tick). "" = no hint.
    private static final Map<String, String> CACHE = new ConcurrentHashMap<>();

    private FindingHints() {
    }

    /** @return the hint for {@code f}: its own {@code Try:} text if present, else the type's hint, else "". */
    public static String of(Finding f) {
        if (f == null) {
            return "";
        }
        String own = ownHint(f.getEvidence());
        return own.isEmpty() ? forType(f.getType()) : own;
    }

    /** The type hint only when the evidence carries no {@code Try:} of its own (reports: the evidence
     * column already shows an own hint, so this avoids printing it twice). */
    public static String extra(Finding f) {
        if (f == null || !ownHint(f.getEvidence()).isEmpty()) {
            return "";
        }
        return forType(f.getType());
    }

    /** The text after the evidence's {@code Try:} marker, or "" when there is none. */
    public static String ownHint(String evidence) {
        if (evidence == null) {
            return "";
        }
        int i = evidence.indexOf(TRY);
        return i < 0 ? "" : evidence.substring(i + TRY.length()).trim();
    }

    /** The first rule hint whose match is a substring of {@code type} (case-insensitive), or "". */
    public static String forType(String type) {
        if (type == null || type.isBlank()) {
            return "";
        }
        return CACHE.computeIfAbsent(type, t -> {
            String lt = t.toLowerCase(Locale.ROOT);
            for (String[] h : HINTS) {
                if (lt.contains(h[0])) {
                    return h[1];
                }
            }
            return "";
        });
    }

    static int ruleCount() {
        return HINTS.size();
    }

    private static final class HintsFile {
        List<Raw> hints;
        static final class Raw { String match; String hint; }
    }

    private static List<String[]> load() {
        List<String[]> out = new ArrayList<>();
        try (InputStream in = FindingHints.class.getResourceAsStream("/patterns/finding-hints.json")) {
            if (in == null) {
                return out;
            }
            HintsFile f = new Gson().fromJson(new InputStreamReader(in, StandardCharsets.UTF_8), HintsFile.class);
            if (f == null || f.hints == null) {
                return out;
            }
            for (HintsFile.Raw r : f.hints) {
                if (r != null && r.match != null && !r.match.isBlank() && r.hint != null) {
                    out.add(new String[]{r.match.toLowerCase(Locale.ROOT), r.hint});
                }
            }
        } catch (Exception e) {
            // missing/unreadable resource -> no hints (feature degrades gracefully)
        }
        return out;
    }
}
