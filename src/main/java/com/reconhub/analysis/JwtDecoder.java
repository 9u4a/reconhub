package com.reconhub.analysis;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.Base64;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Decodes JWTs for inspection (header, claims, notable timestamps, weakness warnings). Passive: it
 * only base64url-decodes the token halves already present in captured traffic — it never verifies a
 * signature against a key or contacts anything.
 */
public final class JwtDecoder {

    private static final Pattern JWT = Pattern.compile(
            "eyJ[A-Za-z0-9_-]{5,}\\.eyJ[A-Za-z0-9_-]{5,}\\.[A-Za-z0-9_-]{5,}");
    private static final Gson PRETTY =
            new GsonBuilder().setPrettyPrinting().disableHtmlEscaping().create();
    private static final DateTimeFormatter TS =
            DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss z").withZone(ZoneId.systemDefault());

    private JwtDecoder() {}

    /** @return the first JWT found in {@code text}, or {@code null}. */
    public static String findFirst(String text) {
        if (text == null) {
            return null;
        }
        Matcher m = JWT.matcher(text);
        return m.find() ? m.group() : null;
    }

    public static boolean isJwt(String s) {
        return s != null && JWT.matcher(s).matches();
    }

    /** Human-readable decode of a JWT; returns an error line if it can't be parsed. */
    public static String decode(String token) {
        if (token == null || token.isBlank()) {
            return "(no token)";
        }
        String[] parts = token.split("\\.");
        if (parts.length < 2) {
            return "Not a well-formed JWT.";
        }
        StringBuilder sb = new StringBuilder();
        JsonObject header = parseSegment(parts[0]);
        JsonObject payload = parseSegment(parts[1]);

        sb.append("── Header ──\n").append(pretty(header, parts[0])).append("\n\n");
        sb.append("── Payload ──\n").append(pretty(payload, parts[1])).append('\n');

        if (payload != null) {
            String claims = notableClaims(payload);
            if (!claims.isEmpty()) {
                sb.append("\n── Notable claims ──\n").append(claims);
            }
        }
        String warnings = warnings(header, payload);
        if (!warnings.isEmpty()) {
            sb.append("\n── Warnings ──\n").append(warnings);
        }
        sb.append("\n(Signature not verified — decode only.)");
        return sb.toString();
    }

    // ---- internals ------------------------------------------------------

    private static JsonObject parseSegment(String seg) {
        try {
            byte[] raw = Base64.getUrlDecoder().decode(pad(seg));
            JsonElement el = JsonParser.parseString(new String(raw, StandardCharsets.UTF_8));
            return el.isJsonObject() ? el.getAsJsonObject() : null;
        } catch (RuntimeException e) {
            return null;
        }
    }

    private static String pretty(JsonObject o, String rawSeg) {
        if (o == null) {
            return "(could not decode: " + rawSeg + ")";
        }
        return PRETTY.toJson(o);
    }

    private static String notableClaims(JsonObject p) {
        StringBuilder sb = new StringBuilder();
        appendStr(sb, p, "iss", "issuer");
        appendStr(sb, p, "sub", "subject");
        appendStr(sb, p, "aud", "audience");
        appendTime(sb, p, "iat", "issued at");
        appendTime(sb, p, "nbf", "not before");
        appendTime(sb, p, "exp", "expires");
        return sb.toString();
    }

    private static String warnings(JsonObject header, JsonObject payload) {
        StringBuilder sb = new StringBuilder();
        if (header != null && header.has("alg")) {
            String alg = str(header, "alg");
            if (alg.equalsIgnoreCase("none")) {
                sb.append("• alg=none — unsigned token accepted?\n");
            }
        }
        if (payload != null && payload.has("exp")) {
            long exp = asLong(payload, "exp");
            if (exp > 0 && Instant.ofEpochSecond(exp).isBefore(Instant.now())) {
                sb.append("• token is expired (exp in the past)\n");
            }
            if (payload.has("iat")) {
                long iat = asLong(payload, "iat");
                long days = (exp - iat) / 86400;
                if (iat > 0 && exp > iat && days >= 30) {
                    sb.append("• long-lived token (~").append(days).append(" days)\n");
                }
            }
        }
        return sb.toString();
    }

    private static void appendStr(StringBuilder sb, JsonObject o, String key, String label) {
        if (o.has(key) && o.get(key).isJsonPrimitive()) {
            sb.append("  ").append(label).append(": ").append(str(o, key)).append('\n');
        }
    }

    private static void appendTime(StringBuilder sb, JsonObject o, String key, String label) {
        if (o.has(key)) {
            long v = asLong(o, key);
            if (v > 0) {
                sb.append("  ").append(label).append(": ").append(TS.format(Instant.ofEpochSecond(v)))
                        .append('\n');
            }
        }
    }

    private static String str(JsonObject o, String key) {
        try {
            return o.get(key).getAsString();
        } catch (RuntimeException e) {
            return o.get(key).toString();
        }
    }

    private static long asLong(JsonObject o, String key) {
        try {
            return o.get(key).getAsLong();
        } catch (RuntimeException e) {
            return -1;
        }
    }

    private static String pad(String s) {
        int m = s.length() % 4;
        return m == 0 ? s : s + "====".substring(m);
    }
}
