package com.reconhub.analysis;

import com.google.gson.stream.JsonReader;
import com.google.gson.stream.JsonToken;
import com.reconhub.model.Finding;

import java.io.IOException;
import java.io.StringReader;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.HashSet;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/**
 * Passive JSON-body leads (0.57.0), driven by {@code patterns/leads.json}:
 * <ul>
 *   <li><b>Mass assignment candidate</b> -- a POST/PUT/PATCH sent a JSON body and the 2xx JSON response holds
 *   a privileged-looking field (role, isAdmin, ownerId, price, ...) that the request did not send. The
 *   server models it, so try sending it.</li>
 *   <li><b>Sensitive field in response</b> -- a 2xx JSON response carries a non-empty password / hash /
 *   secret / OTP / resident-number style field. Only the length goes into evidence, never the value.</li>
 * </ul>
 * JSON is walked with Gson's streaming reader (no recursion, so a hostile deeply-nested body can't overflow
 * the stack) under size / key / token caps. Pure/static for headless testing.
 */
public final class BodyLeads {

    public static final String MASS_ASSIGNMENT_PREFIX = "Mass assignment candidate: ";
    public static final String SENSITIVE_FIELD_PREFIX = "Sensitive field in response: ";
    static final int MAX_BODY = 512 * 1024;
    static final int MAX_KEYS = 2_000;
    static final int MAX_TOKENS = 50_000;
    static final int MAX_PER_RESPONSE = 5;

    private BodyLeads() {
    }

    /** Both checks over one parse of the response. Empty list when nothing applies. */
    public static List<Finding> scan(String method, String normalizedUrl, int status,
                                     String requestContentType, String requestBody,
                                     String responseContentType, String responseBody,
                                     PatternRegistry.LeadRules rules) {
        List<Finding> out = new ArrayList<>();
        if (rules == null || status < 200 || status > 299 || !isJson(responseContentType)) {
            return out;
        }
        Fields response = fields(responseBody);
        if (response.all.isEmpty()) {
            return out;
        }
        sensitive(normalizedUrl, response.all, rules, out);
        String m = method == null ? "" : method.toUpperCase(Locale.ROOT);
        if ((m.equals("POST") || m.equals("PUT") || m.equals("PATCH")) && isJson(requestContentType)) {
            Fields request = fields(requestBody);
            if (!request.all.isEmpty()) {
                massAssignment(m, normalizedUrl, request.all.keySet(), response.shallow, rules, out);
            }
        }
        return out;
    }

    private static void sensitive(String url, Map<String, String> response, PatternRegistry.LeadRules rules,
                                  List<Finding> out) {
        int n = 0;
        for (Map.Entry<String, String> e : response.entrySet()) {
            if (n >= MAX_PER_RESPONSE) {
                return;
            }
            String v = e.getValue();
            if (v == null || masked(v) || !PatternRegistry.LeadRules.whole(rules.sensitiveFields, e.getKey())) {
                continue;
            }
            String evidence = "'" + e.getKey() + "' returned with a " + v.length() + "-char value  |  Try: check "
                    + "whether it is the real secret (hash format, plaintext), and whether another user's record "
                    + "returns it too (IDOR); the API should never send it";
            out.add(new Finding(SENSITIVE_FIELD_PREFIX + e.getKey(), Finding.Severity.MEDIUM, url, url,
                    evidence, false));
            n++;
        }
    }

    /** {@code response} = the response's shallow keys only (see {@link Fields#shallow}): a privileged field
     * deep inside a result array ("price" of every product in a search) is not about this request's object. */
    private static void massAssignment(String method, String url, Set<String> request, Set<String> response,
                                       PatternRegistry.LeadRules rules, List<Finding> out) {
        Set<String> sent = new HashSet<>();
        for (String k : request) {
            sent.add(norm(k));
        }
        int n = 0;
        for (String k : response) {
            if (n >= MAX_PER_RESPONSE) {
                return;
            }
            if (sent.contains(norm(k)) || !PatternRegistry.LeadRules.whole(rules.privilegedFields, k)) {
                continue;
            }
            String evidence = method + " JSON body did not send '" + k + "' but the response has it  |  Try: "
                    + "add \"" + k + "\" to the request body with a privileged / another user's value and "
                    + "check whether it sticks (re-read the object afterwards)";
            out.add(new Finding(MASS_ASSIGNMENT_PREFIX + k, Finding.Severity.LOW, method + " " + url, url,
                    evidence, false));
            n++;
        }
    }

    /**
     * {@code all}: every object key in the body (any depth), first occurrence wins, in document order; the
     * value is the scalar's text for a string/number, null for anything else (object, array, bool, null).
     * {@code shallow}: keys of objects nested at most {@link #SHALLOW_DEPTH} deep and not inside any array
     * (the object itself, or a {"data":{...}} wrapper).
     */
    record Fields(Map<String, String> all, Set<String> shallow) {
    }

    static final int SHALLOW_DEPTH = 2;

    /** Empty for a non-JSON / oversized body. */
    static Fields fields(String json) {
        Map<String, String> out = new LinkedHashMap<>();
        Set<String> shallow = new LinkedHashSet<>();
        Fields result = new Fields(out, shallow);
        if (json == null || json.isEmpty() || json.length() > MAX_BODY) {
            return result;
        }
        String t = json.stripLeading();
        if (t.isEmpty() || (t.charAt(0) != '{' && t.charAt(0) != '[')) {
            return result;
        }
        int objects = 0;   // open objects
        int arrays = 0;    // open arrays
        try (JsonReader r = new JsonReader(new StringReader(t))) {
            r.setLenient(true);
            int tokens = 0;
            while (tokens++ < MAX_TOKENS && out.size() < MAX_KEYS) {
                JsonToken tok = r.peek();
                switch (tok) {
                    case BEGIN_OBJECT -> { r.beginObject(); objects++; }
                    case END_OBJECT -> { r.endObject(); objects--; }
                    case BEGIN_ARRAY -> { r.beginArray(); arrays++; }
                    case END_ARRAY -> { r.endArray(); arrays--; }
                    case NAME -> {
                        String name = r.nextName();
                        JsonToken v = r.peek();
                        String value = null;
                        if (v == JsonToken.STRING || v == JsonToken.NUMBER) {
                            value = r.nextString();
                        }
                        out.putIfAbsent(name, value);
                        if (arrays == 0 && objects <= SHALLOW_DEPTH) {
                            shallow.add(name);
                        }
                    }
                    case STRING, NUMBER -> r.nextString();
                    case BOOLEAN -> r.nextBoolean();
                    case NULL -> r.nextNull();
                    case END_DOCUMENT -> {
                        return result;
                    }
                }
            }
        } catch (IOException | RuntimeException e) {
            // malformed / truncated JSON: keep what was read so far
        }
        return result;
    }

    public static boolean isJson(String contentType) {
        return contentType != null && contentType.toLowerCase(Locale.ROOT).contains("json");
    }

    /** Empty, or only mask characters ("****", "xxxx", "•••"). */
    private static boolean masked(String v) {
        if (v.isBlank()) {
            return true;
        }
        for (int i = 0; i < v.length(); i++) {
            char c = v.charAt(i);
            if (c != '*' && c != 'x' && c != 'X' && c != '•' && c != '#' && c != ' ') {
                return false;
            }
        }
        return true;
    }

    private static String norm(String k) {
        return k.replace("_", "").replace("-", "").toLowerCase(Locale.ROOT);
    }
}
