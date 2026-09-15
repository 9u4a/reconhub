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
    private static final Map<String, String> CACHE = new ConcurrentHashMap<>();

    private ParameterClassifier() {}

    /** @return matching class labels for a parameter name (empty if none). */
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
