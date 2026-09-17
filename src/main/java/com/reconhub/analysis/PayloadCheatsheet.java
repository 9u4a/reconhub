package com.reconhub.analysis;

import com.google.gson.Gson;

import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * Loads {@code payload-cheatsheets.json}: a reference set of payloads to try, keyed by the
 * {@link ParameterClassifier} class name it applies to, and/or a substring match against a
 * {@link com.reconhub.model.Finding} type for injection-category findings. Passive/reference-only —
 * this class never sends anything; see {@code integration.IntruderPayloads} for the (also passive)
 * Intruder payload-set registration, and {@code ui.CheatsheetDialog} for the read-only viewer.
 */
public final class PayloadCheatsheet {

    /** One cheatsheet entry: the payloads plus an optional short usage note. */
    public record Set(String label, List<String> payloads, String note) {}

    private final Map<String, Set> byClass = new LinkedHashMap<>();
    private final List<FindingRule> findingRules = new ArrayList<>();
    private final List<String> loadErrors = new ArrayList<>();

    private record FindingRule(String needle, Set set) {}

    private PayloadCheatsheet() {}

    public static PayloadCheatsheet load() {
        PayloadCheatsheet sheet = new PayloadCheatsheet();
        try (InputStream in = PayloadCheatsheet.class
                .getResourceAsStream("/patterns/payload-cheatsheets.json")) {
            if (in == null) {
                sheet.loadErrors.add("missing /patterns/payload-cheatsheets.json");
                return sheet;
            }
            Raw raw = new Gson().fromJson(new InputStreamReader(in, StandardCharsets.UTF_8), Raw.class);
            if (raw == null || raw.sets == null) {
                return sheet;
            }
            for (Raw.Entry e : raw.sets) {
                if (e == null || e.clazz == null || e.payloads == null || e.payloads.isEmpty()) {
                    continue;
                }
                Set set = new Set(e.clazz, List.copyOf(e.payloads), e.note == null ? "" : e.note);
                sheet.byClass.put(e.clazz, set);
                if (e.findingTypeContains != null) {
                    for (String needle : e.findingTypeContains) {
                        if (needle != null && !needle.isBlank()) {
                            sheet.findingRules.add(new FindingRule(needle.toLowerCase(Locale.ROOT), set));
                        }
                    }
                }
            }
        } catch (Exception e) {
            sheet.loadErrors.add("payload-cheatsheets.json: " + e);
        }
        return sheet;
    }

    /** All cheatsheet sets, in file order (for one-time Intruder registration). */
    public List<Set> allSets() {
        return List.copyOf(byClass.values());
    }

    /** @return the cheatsheet for an exact parameter-class name (e.g. "IDOR"), or null if none. */
    public Set forClass(String className) {
        return className == null ? null : byClass.get(className);
    }

    /** @return the cheatsheet whose {@code findingTypeContains} needle is found in the Finding type. */
    public Set forFindingType(String type) {
        if (type == null || type.isBlank()) {
            return null;
        }
        String t = type.toLowerCase(Locale.ROOT);
        for (FindingRule r : findingRules) {
            if (t.contains(r.needle)) {
                return r.set;
            }
        }
        return null;
    }

    public List<String> loadErrors() {
        return loadErrors;
    }

    // ---- JSON shape -------------------------------------------------------

    private static final class Raw {
        List<Entry> sets;
        static final class Entry {
            String note;
            List<String> payloads;
            List<String> findingTypeContains;
            @com.google.gson.annotations.SerializedName("class")
            String clazz;
        }
    }
}
