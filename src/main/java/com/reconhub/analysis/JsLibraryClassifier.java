package com.reconhub.analysis;

import com.google.gson.Gson;

import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Locale;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Tags a JS asset as library / vendor-chunk / third-party code (0.55.0) from
 * {@code patterns/js-libraries.json}, so JS Assets can hide it and {@code JsAnalyzer} can skip deep
 * analysis on it. Returns {@code ""} for app code.
 *
 * <p>Owns its own rule file (not {@code PatternRegistry}) so {@code StateSerializer} can re-classify an
 * imported pre-0.55.0 asset by URL alone through {@link #shared()} without compiling every other rule set.
 * Montoya-free and headless-tested ({@code JsLibraryClassifierTest}).
 */
public final class JsLibraryClassifier {

    /** Body-banner rules only look at this prefix of the body. */
    static final int BANNER_SCAN = 2048;
    /** A body larger than this is never classified by banner alone: an app bundle that concatenates a
     * library starts with that library's banner too, and hiding (and not analyzing) it would lose the
     * app code. jQuery/React-dom/Vue/Lodash/Moment minified builds are all well under this. */
    static final int BANNER_MAX_BODY = 300_000;

    public enum Kind { LIBRARY, VENDOR, THIRD_PARTY }

    public static final class Rule {
        public final Kind kind;
        public final String label;
        public final Pattern host;     // exactly one of host/file/banner is non-null
        public final Pattern file;
        public final Pattern banner;

        Rule(Kind kind, String label, Pattern host, Pattern file, Pattern banner) {
            this.kind = kind;
            this.label = label;
            this.host = host;
            this.file = file;
            this.banner = banner;
        }

        /** Every compiled pattern this rule carries (for the adversarial test). */
        public Pattern pattern() {
            return host != null ? host : file != null ? file : banner;
        }
    }

    private static volatile JsLibraryClassifier shared;

    private final List<Rule> rules;
    private final List<String> loadErrors;

    JsLibraryClassifier(List<Rule> rules, List<String> loadErrors) {
        this.rules = Collections.unmodifiableList(rules);
        this.loadErrors = Collections.unmodifiableList(loadErrors);
    }

    /** The classifier built from the bundled {@code js-libraries.json}, loaded once. */
    public static JsLibraryClassifier shared() {
        JsLibraryClassifier c = shared;
        if (c == null) {
            synchronized (JsLibraryClassifier.class) {
                c = shared;
                if (c == null) {
                    c = load();
                    shared = c;
                }
            }
        }
        return c;
    }

    public List<Rule> rules() { return rules; }
    public List<String> loadErrors() { return loadErrors; }

    /**
     * @param body the JS body, or {@code null} when only the URL is known (state import)
     * @return a display label such as {@code "Library: jQuery 3.6.0"}, {@code "Vendor chunk"},
     *         {@code "3rd-party: Public CDN library"}, or {@code ""} for app code
     */
    public String classify(String url, String body) {
        String host = hostOf(url);
        String file = fileOf(url);
        for (Rule r : rules) {
            if (r.host != null && !host.isEmpty() && r.host.matcher(host).find()) {
                return format(r, null);
            }
            if (r.file != null && !file.isEmpty()) {
                Matcher m = r.file.matcher(file);
                if (m.find()) {
                    return format(r, m);
                }
            }
        }
        if (body == null || body.isEmpty() || body.length() > BANNER_MAX_BODY) {
            return "";
        }
        String head = body.length() > BANNER_SCAN ? body.substring(0, BANNER_SCAN) : body;
        for (Rule r : rules) {
            if (r.banner != null) {
                Matcher m = r.banner.matcher(head);
                if (m.find()) {
                    return format(r, m);
                }
            }
        }
        return "";
    }

    private static String format(Rule r, Matcher m) {
        String label = r.label == null ? "" : r.label;
        if (m != null && m.groupCount() >= 1 && m.group(1) != null) {
            label = label.replace("$1", m.group(1));
        }
        label = label.replace("$1", "").trim();
        return switch (r.kind) {
            case LIBRARY -> "Library: " + label;
            case VENDOR -> label.isEmpty() ? "Vendor chunk" : label;
            case THIRD_PARTY -> "3rd-party: " + label;
        };
    }

    static String hostOf(String url) {
        if (url == null || url.isBlank()) {
            return "";
        }
        try {
            String h = URI.create(url).getHost();
            return h == null ? "" : h.toLowerCase(Locale.ROOT);
        } catch (RuntimeException e) {
            return "";
        }
    }

    /** Lowercased last path segment, query/fragment stripped; {@code import://name.js} works too. */
    static String fileOf(String url) {
        if (url == null || url.isBlank()) {
            return "";
        }
        String s = url;
        int cut = s.length();
        int q = s.indexOf('?');
        if (q >= 0) cut = Math.min(cut, q);
        int h = s.indexOf('#');
        if (h >= 0) cut = Math.min(cut, h);
        s = s.substring(0, cut);
        int slash = s.lastIndexOf('/');
        return (slash >= 0 ? s.substring(slash + 1) : s).toLowerCase(Locale.ROOT);
    }

    // ---- Loading ----------------------------------------------------------

    private static final class RulesFile {
        List<Raw> rules;
        static final class Raw { String kind; String label; String host; String file; String banner; }
    }

    static JsLibraryClassifier load() {
        List<Rule> rules = new ArrayList<>();
        List<String> errors = new ArrayList<>();
        try (InputStream in = JsLibraryClassifier.class.getResourceAsStream("/patterns/js-libraries.json")) {
            if (in == null) {
                errors.add("resource not found: /patterns/js-libraries.json");
                return new JsLibraryClassifier(rules, errors);
            }
            RulesFile f = new Gson().fromJson(new InputStreamReader(in, StandardCharsets.UTF_8), RulesFile.class);
            if (f != null && f.rules != null) {
                for (RulesFile.Raw raw : f.rules) {
                    try {
                        rules.add(compile(raw));
                    } catch (IllegalArgumentException e) {   // includes PatternSyntaxException
                        errors.add("js-libraries[" + raw.label + "]: " + e.getMessage());
                    }
                }
            }
        } catch (Exception e) {
            errors.add("/patterns/js-libraries.json: " + e.getMessage());
        }
        return new JsLibraryClassifier(rules, errors);
    }

    private static Rule compile(RulesFile.Raw raw) {
        Kind kind = switch (raw.kind == null ? "" : raw.kind.trim().toLowerCase(Locale.ROOT)) {
            case "library" -> Kind.LIBRARY;
            case "vendor" -> Kind.VENDOR;
            case "third-party" -> Kind.THIRD_PARTY;
            default -> throw new IllegalArgumentException("unknown kind " + raw.kind);
        };
        int set = (raw.host != null ? 1 : 0) + (raw.file != null ? 1 : 0) + (raw.banner != null ? 1 : 0);
        if (set != 1) {
            throw new IllegalArgumentException("exactly one of host/file/banner required");
        }
        int flags = Pattern.CASE_INSENSITIVE;
        return new Rule(kind, raw.label,
                raw.host == null ? null : Pattern.compile(raw.host, flags),
                raw.file == null ? null : Pattern.compile(raw.file, flags),
                raw.banner == null ? null : Pattern.compile(raw.banner, flags));
    }
}
