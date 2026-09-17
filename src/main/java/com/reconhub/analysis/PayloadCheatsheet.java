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
import java.util.regex.Pattern;

/**
 * Loads {@code payload-cheatsheets.json}: reference payloads to try, keyed by the
 * {@link ParameterClassifier} class name it applies to, and/or a substring match against a
 * {@link com.reconhub.model.Finding} type (injection-category findings) or an
 * {@link com.reconhub.model.Endpoint}'s Content-Type (body-structure-driven classes like XXE). Each
 * set has two tiers — {@code basic} (plain, unencoded probes) and {@code bypass} (case/encoding/comment
 * obfuscation and other filter/WAF-evasion variants of the same idea). Passive/reference-only — this
 * class never sends anything; see {@code integration.IntruderPayloads} for the (also passive) Intruder
 * registration, and {@code ui.CheatsheetDialog} for the read-only viewer.
 */
public final class PayloadCheatsheet {

    /** One cheatsheet entry: basic + bypass/evasion payloads, plus an optional short usage note. */
    public record Set(String label, List<String> basic, List<String> bypass, String note) {}

    private final Map<String, Set> byClass = new LinkedHashMap<>();
    private final List<FindingRule> findingRules = new ArrayList<>();
    private final List<FindingRule> contentTypeRules = new ArrayList<>();
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
                if (e == null || e.clazz == null) {
                    continue;
                }
                List<String> basic = e.basic == null ? List.of() : List.copyOf(e.basic);
                List<String> bypass = e.bypass == null ? List.of() : List.copyOf(e.bypass);
                if (basic.isEmpty() && bypass.isEmpty()) {
                    continue;
                }
                Set set = new Set(e.clazz, basic, bypass, e.note == null ? "" : e.note);
                sheet.byClass.put(e.clazz, set);
                if (e.findingTypeContains != null) {
                    for (String needle : e.findingTypeContains) {
                        if (needle != null && !needle.isBlank()) {
                            sheet.findingRules.add(new FindingRule(needle.toLowerCase(Locale.ROOT), set));
                        }
                    }
                }
                if (e.contentTypeContains != null) {
                    for (String needle : e.contentTypeContains) {
                        if (needle != null && !needle.isBlank()) {
                            sheet.contentTypeRules.add(new FindingRule(needle.toLowerCase(Locale.ROOT), set));
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

    /** @return the cheatsheet whose {@code contentTypeContains} needle is found in the Content-Type
     * (e.g. an XML/SOAP endpoint surfaces the XXE set). */
    public Set forContentType(String contentType) {
        if (contentType == null || contentType.isBlank()) {
            return null;
        }
        String t = contentType.toLowerCase(Locale.ROOT);
        for (FindingRule r : contentTypeRules) {
            if (t.contains(r.needle)) {
                return r.set;
            }
        }
        return null;
    }

    public List<String> loadErrors() {
        return loadErrors;
    }

    // ---- Value-based heuristic (not name/class driven) ---------------------

    // PHP serialize() shapes: a:N:{ / O:N:"Class": / s:N:"..."; -- matched loosely on a prefix.
    private static final Pattern PHP_SERIALIZED = Pattern.compile("^[aOs]:\\d+:");

    /**
     * True when a parameter's name or example value looks like a serialized-object blob (Java, PHP, or
     * ASP.NET ViewState) rather than a plain value — regardless of its name-based
     * {@link ParameterClassifier} class. Used to surface the {@code Deserialization} cheatsheet on any
     * parameter that carries one of these, since deserialization sinks aren't identifiable by name.
     */
    public static boolean looksSerialized(String name, String value) {
        if ("__VIEWSTATE".equalsIgnoreCase(name) || "__EVENTVALIDATION".equalsIgnoreCase(name)) {
            return true;
        }
        if (value == null) {
            return false;
        }
        String v = value.trim();
        if (v.isEmpty()) {
            return false;
        }
        if (v.startsWith("rO0")) {          // base64 of Java's serialization magic bytes (AC ED 00 05)
            return true;
        }
        return PHP_SERIALIZED.matcher(v).find();
    }

    // ---- JSON shape -------------------------------------------------------

    private static final class Raw {
        List<Entry> sets;
        static final class Entry {
            String note;
            List<String> basic;
            List<String> bypass;
            List<String> findingTypeContains;
            List<String> contentTypeContains;
            @com.google.gson.annotations.SerializedName("class")
            String clazz;
        }
    }
}
