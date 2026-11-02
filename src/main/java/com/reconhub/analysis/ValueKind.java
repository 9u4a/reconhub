package com.reconhub.analysis;

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Pattern;

/**
 * Shape of a parameter's example value (0.56.0) -- "what kind of thing is this", independent of the name.
 * Feeds {@link ParameterClassifier#classesOf}: a numeric/UUID value is an IDOR lead even on a param called
 * {@code no}, a URL value is a redirect/SSRF lead whatever its name. Pure/static, bounded regexes over the
 * (already 120-char-capped) example value; results cached by value.
 */
public final class ValueKind {

    public static final String NUMERIC_ID = "numeric-id";
    public static final String NUMBER = "number";
    public static final String UUID = "uuid";
    public static final String EMAIL = "email";
    public static final String URL = "url";
    public static final String PATH = "path";
    public static final String JWT = "jwt";
    public static final String SERIALIZED = "serialized";
    public static final String BASE64 = "base64";

    private static final Pattern DIGITS = Pattern.compile("^\\d{1,19}$");
    private static final Pattern UUID_RE = Pattern.compile(
            "^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$");
    private static final Pattern EMAIL_RE = Pattern.compile("^[^@\\s]{1,64}@[A-Za-z0-9-]{1,63}(?:\\.[A-Za-z0-9-]{1,63}){0,8}\\.[A-Za-z]{2,24}$");
    private static final Pattern URL_RE = Pattern.compile("^(?:[a-zA-Z][a-zA-Z0-9+.-]{1,15}:)?//[^\\s/]{1,253}");
    private static final Pattern PATH_RE = Pattern.compile("^(?:/[^/\\s]|\\.{1,2}/|[a-zA-Z]:\\\\)|\\.\\./");
    private static final Pattern JWT_RE = Pattern.compile("^eyJ[\\w-]{5,}\\.eyJ[\\w-]{2,}\\.");
    private static final Pattern BASE64_RE = Pattern.compile("^[A-Za-z0-9+/]{16,}={0,2}$");

    // Bounded: example values are capped per parameter, but a huge capture could still mean many; cleared
    // wholesale when full rather than tracking LRU order (a re-computation is a few cheap regexes).
    private static final int CACHE_MAX = 50_000;
    private static final Map<String, String> CACHE = new ConcurrentHashMap<>();

    private ValueKind() {
    }

    /** Every pattern, for the ReDoS guard test. */
    static java.util.List<Pattern> patterns() {
        return java.util.List.of(DIGITS, UUID_RE, EMAIL_RE, URL_RE, PATH_RE, JWT_RE, BASE64_RE);
    }

    /** @return one of the kind constants, or "" when the value is blank / unremarkable. */
    public static String of(String value) {
        if (value == null || value.isBlank()) {
            return "";
        }
        String cached = CACHE.get(value);
        if (cached != null) {
            return cached;
        }
        if (CACHE.size() >= CACHE_MAX) {
            CACHE.clear();
        }
        String kind = compute(value);
        CACHE.put(value, kind);
        return kind;
    }

    static String compute(String raw) {
        String v = raw.trim();
        if (v.endsWith("…")) {                 // ParameterInfo's truncation marker -- judge on the prefix
            v = v.substring(0, v.length() - 1);
        }
        v = decode(v);
        if (v.isEmpty()) {
            return "";
        }
        if (PayloadCheatsheet.looksSerialized(null, v)) {
            return SERIALIZED;
        }
        if (DIGITS.matcher(v).matches()) {
            return v.length() >= 3 ? NUMERIC_ID : NUMBER;
        }
        if (UUID_RE.matcher(v).matches()) {
            return UUID;
        }
        if (JWT_RE.matcher(v).find()) {
            return JWT;
        }
        if (URL_RE.matcher(v).find()) {
            return URL;
        }
        if (EMAIL_RE.matcher(v).matches()) {
            return EMAIL;
        }
        if (PATH_RE.matcher(v).find()) {
            return PATH;
        }
        if (v.length() % 4 == 0 && BASE64_RE.matcher(v).matches()) {
            return BASE64;
        }
        return "";
    }

    /** The class a value kind implies on its own, or null. */
    static String impliedClass(String kind) {
        return switch (kind) {
            case NUMERIC_ID, UUID -> "IDOR";
            case URL -> "Redirect/SSRF";
            case PATH -> "File/Path";
            case SERIALIZED -> "Deserialization";
            case JWT -> "Secret/Token";
            default -> null;
        };
    }

    private static String decode(String v) {
        if (v.indexOf('%') < 0) {   // '+' alone is left as-is: base64 values carry it
            return v;
        }
        try {
            return URLDecoder.decode(v, StandardCharsets.UTF_8).trim();
        } catch (IllegalArgumentException e) {
            return v;
        }
    }
}
