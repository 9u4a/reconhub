package com.reconhub.analysis;

import java.util.Locale;
import java.util.concurrent.ConcurrentHashMap;
import java.util.Map;

/**
 * Groups a finding's {@code type} string into a coarse {@link Category} for scanning, filtering and
 * reporting. Pure string logic (no UI dependency) so both the Findings tab and the reporters can
 * share it. Keyword-based so it also classifies user-defined custom-rule findings.
 */
public final class FindingTaxonomy {

    // 0.43.7: categoryOf's own cost (lowercase copy + up to ~45 String.contains scans) was being paid
    // on every cell paint, every row-filter pass per tick, and twice per finding per export -- for a
    // value that's a pure function of `type`, and `type` only ever takes a few dozen distinct values
    // (one per finding-generating rule). Memoize it here rather than on Finding itself, since that
    // would mean a lazy field on every Finding instance for a value this cache already shares cheaply.
    private static final Map<String, Category> CACHE = new ConcurrentHashMap<>();

    private FindingTaxonomy() {}

    public enum Category {
        SECRET("Secret"),
        PII("PII"),
        AUTH("Auth"),
        MISCONFIG("Misconfig"),
        INFO_LEAK("Info leak"),
        API("API"),
        INJECTION("Injection"),
        COMMENT("Comment"),
        OTHER("Other");

        private final String label;

        Category(String label) {
            this.label = label;
        }

        public String label() {
            return label;
        }
    }

    /** Maps a finding type to its category. Order matters — earlier checks win. Cached by {@code type}
     * (0.43.7) -- see {@link #CACHE}'s field comment. */
    public static Category categoryOf(String type) {
        if (type == null || type.isBlank()) {
            return Category.OTHER;
        }
        return CACHE.computeIfAbsent(type, FindingTaxonomy::compute);
    }

    private static Category compute(String type) {
        String t = type.toLowerCase(Locale.ROOT);

        if (has(t, "cors", "csp", "cookie", "mixed content", "cacheable", "missing security header")) {
            return Category.MISCONFIG;
        }
        if (has(t, "graphql", "api spec", "spec exposed")) {
            return Category.API;
        }
        if (has(t, "open redirect", "xss", "reflected param")) {
            return Category.INJECTION;
        }
        if (has(t, "role", "admin", "privile", "permission", "scope",
                "authorit", "access level", "clearance")) {
            return Category.AUTH;
        }
        if (has(t, "rrn", "주민", "card number", "phone", "email")) {
            return Category.PII;
        }
        if (has(t, "stack", "trace", "traceback", "exception", "error", "debug",
                "directory listing", "internal path", "var_dump", "print_r",
                "s3", "blob", "storage", "private ipv4", "exposed", "backup")) {
            return Category.INFO_LEAK;
        }
        if (has(t, "comment")) {
            return Category.COMMENT;
        }
        if (has(t, "key", "token", "secret", "jwt", "bearer", "basic auth",
                "password", "credential", "webhook", "private key", "in url")) {
            return Category.SECRET;
        }
        return Category.OTHER;
    }

    /** Convenience: category label for a type. */
    public static String labelOf(String type) {
        return categoryOf(type).label();
    }

    private static boolean has(String haystack, String... needles) {
        for (String n : needles) {
            if (haystack.contains(n)) {
                return true;
            }
        }
        return false;
    }
}
