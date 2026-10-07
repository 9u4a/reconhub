package com.reconhub.analysis;

import com.google.gson.Gson;

import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

/**
 * Passive, name-based vulnerability-class hinting for parameters. Loads {@code param-classes.json}
 * once and tags a parameter name with matching class labels (e.g. IDOR, Redirect/SSRF). This only
 * classifies names already seen in captured traffic — it never sends anything to a target.
 */
public final class ParameterClassifier {

    private record Rule(String label, Pattern pattern) {}

    private static final List<Rule> RULES = load();
    // classifyJoined's own cache (joined string, not the list) -- kept separate from LIST_CACHE below
    // rather than deriving one from the other, so neither method pays for building a value shape it
    // doesn't need.
    private static final Map<String, String> CACHE = new ConcurrentHashMap<>();
    // Cached list form (0.43.7): classify(name) is the uncached primitive -- every rule's regex re-run
    // per call -- and several hot paths (Dashboard's per-row tagging, RequestInspector's per-parameter
    // Secret/Redirect checks, the HTML/JSON exporters) called it directly instead of the already-cached
    // classifyJoined below, redoing all ~8 rules for the same handful of recurring parameter names on
    // every tick/row/export. Distinct parameter names are few, so this is a small, bounded cache.
    private static final Map<String, List<String>> LIST_CACHE = new ConcurrentHashMap<>();

    private ParameterClassifier() {}

    /** @return matching class labels for a parameter name (empty if none). Uncached primitive -- see
     * {@link #classifyCached} for the memoized version hot paths should prefer. */
    public static List<String> classify(String name) {
        List<String> out = new ArrayList<>();
        if (name == null || name.isBlank()) {
            return out;
        }
        for (Rule r : RULES) {
            if (r.pattern.matcher(name).find()) {
                out.add(r.label);
            }
        }
        return out;
    }

    /** Cached form of {@link #classify} (0.43.7) -- the list a caller gets back is shared/immutable-by-
     * convention (callers must not mutate it; none of the current ones do). Prefer this over
     * {@code classify} on any path that runs more than once per parameter name (cell rendering, per-tick
     * filtering, export). */
    public static List<String> classifyCached(String name) {
        if (name == null || name.isBlank()) {
            return List.of();
        }
        return LIST_CACHE.computeIfAbsent(name, ParameterClassifier::classify);
    }

    /** @return matching class labels joined with ", " (empty string if none). Cached by name. */
    public static String classifyJoined(String name) {
        if (name == null || name.isBlank()) {
            return "";
        }
        return CACHE.computeIfAbsent(name, n -> String.join(", ", classify(n)));
    }

    // ---- Loading --------------------------------------------------------

    private static final class ClassesFile {
        List<Raw> classes;
        static final class Raw { String name; String regex; }
    }

    private static List<Rule> load() {
        List<Rule> rules = new ArrayList<>();
        try (InputStream in = ParameterClassifier.class
                .getResourceAsStream("/patterns/param-classes.json")) {
            if (in == null) {
                return rules;
            }
            ClassesFile f = new Gson()
                    .fromJson(new InputStreamReader(in, StandardCharsets.UTF_8), ClassesFile.class);
            if (f == null || f.classes == null) {
                return rules;
            }
            for (ClassesFile.Raw raw : f.classes) {
                if (raw == null || raw.name == null || raw.regex == null) {
                    continue;
                }
                try {
                    rules.add(new Rule(raw.name, Pattern.compile(raw.regex)));
                } catch (PatternSyntaxException ignored) {
                    // skip a bad rule, keep the rest
                }
            }
        } catch (Exception ignored) {
            // resource missing/unreadable -> no classification (feature degrades gracefully)
        }
        return rules;
    }
}
