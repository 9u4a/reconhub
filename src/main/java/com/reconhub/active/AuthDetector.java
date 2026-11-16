package com.reconhub.active;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.reconhub.analysis.JwtDecoder;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * Finds the parts of a request that carry an identity (0.60.0): auth headers and session cookies.
 * Pure string logic (no Montoya) so it is headless-tested and shared by session discovery, the session
 * editor's paste-to-detect, Burp's "Save as ReconHub session", and the STRIP_AUTH rule.
 *
 * <p>Two levels: {@link Confidence#CONFIRMED} = a known auth header / session-cookie name;
 * {@link Confidence#LIKELY} = an unknown name whose value looks like a token (JWT, Bearer, long random).
 * Analytics / consent cookies are never reported. STRIP_AUTH only ever removes CONFIRMED parts.
 */
public final class AuthDetector {

    public enum Kind { HEADER, COOKIE }

    public enum Confidence { CONFIRMED, LIKELY }

    /** One identity-bearing part of a request. */
    public record Part(Kind kind, String name, String value, Confidence confidence) {}

    private static final Pattern AUTH_HEADER = Pattern.compile(
            "(?i)^(?:authorization|proxy-authorization|api-?key|access-?token|token|auth-?token"
                    + "|x-[a-z0-9-]{0,30}(?:token|auth|session|jwt|api-?key|csrf|xsrf)[a-z0-9-]{0,30})$");
    /** Standard headers whose values can look random but never carry the identity. */
    private static final Set<String> NOT_AUTH_HEADERS = Set.of("host", "cookie", "user-agent", "accept",
            "accept-language", "accept-encoding", "content-type", "content-length", "referer", "origin",
            "connection", "cache-control", "pragma", "if-none-match", "if-modified-since", "upgrade-insecure-requests",
            "priority", "te", "x-requested-with", "x-forwarded-for", "x-request-id", "x-correlation-id",
            "traceparent", "tracestate", "sentry-trace", "baggage", "x-amzn-trace-id", "range", "dnt");
    private static final Pattern SESSION_COOKIE = Pattern.compile(
            "(?i)^(?:jsessionid|phpsessid|asp\\.net_sessionid|aspsessionid[a-z0-9]{0,20}|\\.aspxauth|\\.aspnetcore\\.[a-z]{0,20}"
                    + "|connect\\.sid|sid|ssid|session|sessionid|session_id|session-id|sess|_session|[a-z0-9_.-]{1,40}_session"
                    + "|laravel_session|ci_session|token|access_token|accesstoken|access-token|refresh_token|refreshtoken"
                    + "|auth|auth_token|authtoken|auth-token|jwt|id_token|remember_token|remember_me|rememberme"
                    + "|wordpress_logged_in_[a-z0-9]{1,40}|wordpress_sec_[a-z0-9]{1,40}|csrftoken|xsrf-token|_csrf|csrf_token"
                    + "|_session_id|user_session|usersession|login_token|sso[a-z0-9_]{0,20})$");
    private static final Pattern ANALYTICS_COOKIE = Pattern.compile(
            "(?i)^(?:_ga.{0,40}|_gid|_gat.{0,40}|_gcl_.{0,40}|_fbp|_fbc|_hj.{0,40}|ajs_.{0,40}|amplitude.{0,40}|amp_.{0,40}"
                    + "|mp_.{0,60}|optimizely.{0,40}|_clck|_clsk|_uetsid|_uetvid|_ttp|_tt_.{0,40}|wcs_bt|nid"
                    + "|cookieconsent.{0,40}|cookie_consent.{0,40}|optanon.{0,40}|_dc_gtm.{0,40}|__utm.{0,10}|_pk_.{0,40}"
                    + "|intercom-.{0,60}|ch-veil-id|ch-session-.{0,40}|_lfa|_ce\\..{0,20}|_dd_s|lang|locale|language|theme)$");
    /** An application / client API key header (shared by every user, not the identity) -- 0.64.0. */
    private static final Pattern APP_KEY_HEADER = Pattern.compile("(?i)^[a-z0-9-]{0,40}api-?key$");
    /** Keep-list token meaning "keep app API key headers" in a STRIP_AUTH plan. */
    public static final String KEEP_APP_KEYS = "*appkeys";
    private static final Pattern TOKEN_CHARS = Pattern.compile("[A-Za-z0-9+/=_.%~-]{24,4096}");

    private AuthDetector() {}

    /** Identity-bearing parts of a request's headers ({name, value} pairs, in order). */
    public static List<Part> detect(List<String[]> headers) {
        List<Part> out = new ArrayList<>();
        if (headers == null) return out;
        for (String[] h : headers) {
            if (h == null || h.length < 2 || h[0] == null) continue;
            String name = h[0].trim();
            String value = h[1] == null ? "" : h[1].trim();
            String lower = name.toLowerCase(Locale.ROOT);
            if (lower.equals("cookie")) {
                for (Map.Entry<String, String> c : parseCookies(value).entrySet()) {
                    Confidence conf = cookieConfidence(c.getKey(), c.getValue());
                    if (conf != null) out.add(new Part(Kind.COOKIE, c.getKey(), c.getValue(), conf));
                }
            } else if (!value.isEmpty()) {
                Confidence conf = headerConfidence(lower, value);
                if (conf != null) out.add(new Part(Kind.HEADER, name, value, conf));
            }
        }
        return out;
    }

    static Confidence headerConfidence(String lowerName, String value) {
        if (NOT_AUTH_HEADERS.contains(lowerName) || lowerName.startsWith("sec-") || lowerName.startsWith("content-")
                || lowerName.startsWith("accept")) {
            return null;
        }
        if (AUTH_HEADER.matcher(lowerName).matches()) return Confidence.CONFIRMED;
        return looksLikeToken(value) ? Confidence.LIKELY : null;
    }

    static Confidence cookieConfidence(String name, String value) {
        if (name.isEmpty() || ANALYTICS_COOKIE.matcher(name).matches()) return null;
        if (SESSION_COOKIE.matcher(name).matches()) return Confidence.CONFIRMED;
        return looksLikeToken(value) ? Confidence.LIKELY : null;
    }

    /** A JWT, a Bearer/Basic/Token credential, or a long random-looking value with letters and digits. */
    public static boolean looksLikeToken(String value) {
        if (value == null) return false;
        String v = value.trim();
        String lower = v.toLowerCase(Locale.ROOT);
        if (lower.startsWith("bearer ") || lower.startsWith("basic ") || lower.startsWith("token ")) return true;
        if (JwtDecoder.isJwt(v)) return true;
        if (!TOKEN_CHARS.matcher(v).matches()) return false;
        boolean digit = false;
        boolean letter = false;
        for (int i = 0; i < v.length(); i++) {
            char c = v.charAt(i);
            if (Character.isDigit(c)) digit = true;
            else if (Character.isLetter(c)) letter = true;
        }
        return digit && letter;
    }

    /** "a=1; b=2" → ordered {a:1, b:2}; null/blank → empty. Values are kept verbatim. */
    public static LinkedHashMap<String, String> parseCookies(String header) {
        LinkedHashMap<String, String> jar = new LinkedHashMap<>();
        if (header == null || header.isBlank()) return jar;
        for (String part : header.split(";")) {
            String p = part.trim();
            if (p.isEmpty()) continue;
            int eq = p.indexOf('=');
            if (eq <= 0) {
                jar.put(p, "");
            } else {
                jar.put(p.substring(0, eq).trim(), p.substring(eq + 1).trim());
            }
        }
        return jar;
    }

    public static String joinCookies(Map<String, String> jar) {
        StringBuilder sb = new StringBuilder();
        for (Map.Entry<String, String> e : jar.entrySet()) {
            if (sb.length() > 0) sb.append("; ");
            sb.append(e.getKey());
            if (!e.getValue().isEmpty() || !e.getKey().isEmpty()) sb.append('=').append(e.getValue());
        }
        return sb.toString();
    }

    /**
     * STRIP_AUTH plan: which CONFIRMED auth headers / session cookies of this request to remove, keeping
     * the given names (headers lowercased, cookies exact). Returns {header names, cookie names}.
     */
    public static List<String>[] stripPlan(List<String[]> headers, Set<String> keepHeadersLower, Set<String> keepCookies) {
        @SuppressWarnings("unchecked")
        List<String>[] out = new List[]{new ArrayList<String>(), new ArrayList<String>()};
        for (Part p : detect(headers)) {
            if (p.confidence() != Confidence.CONFIRMED) continue;
            if (p.kind() == Kind.HEADER && keepHeadersLower.contains(KEEP_APP_KEYS) && isAppKeyHeader(p.name())) {
                continue;
            }
            if (p.kind() == Kind.HEADER && !keepHeadersLower.contains(p.name().toLowerCase(Locale.ROOT))) {
                out[0].add(p.name());
            } else if (p.kind() == Kind.COOKIE && !keepCookies.contains(p.name())) {
                out[1].add(p.name());
            }
        }
        return out;
    }

    /** X-Api-Key, apikey, X-Goog-Api-Key, ... -- an app key shared by all users. */
    public static boolean isAppKeyHeader(String name) {
        return name != null && APP_KEY_HEADER.matcher(name.trim()).matches();
    }

    // ---- JWT summary -----------------------------------------------------------------------

    /** Who a token belongs to and when it expires (UI only; never exported). */
    public record TokenInfo(String subject, long expEpochSec) {
        public boolean expired(long nowEpochSec) {
            return expEpochSec > 0 && expEpochSec <= nowEpochSec;
        }
    }

    private static final String[] SUBJECT_CLAIMS = {"email", "preferred_username", "username", "user_name", "sub",
            "user_id", "userId", "uid", "name", "id"};

    /** The first JWT among {@code values} (a "Bearer " prefix is stripped), summarized; null when none. */
    public static TokenInfo tokenInfo(Iterable<String> values) {
        for (String raw : values) {
            if (raw == null) continue;
            String v = raw.trim();
            if (v.toLowerCase(Locale.ROOT).startsWith("bearer ")) v = v.substring(7).trim();
            if (!JwtDecoder.isJwt(v)) continue;
            JwtDecoder.Parsed p = JwtDecoder.parse(v);
            if (p == null || p.payload() == null) continue;
            JsonObject pl = p.payload();
            String subject = "";
            for (String c : SUBJECT_CLAIMS) {
                JsonElement e = pl.get(c);
                if (e != null && e.isJsonPrimitive()) {
                    subject = c + "=" + e.getAsString();
                    break;
                }
            }
            long exp = 0;
            JsonElement e = pl.get("exp");
            if (e != null && e.isJsonPrimitive()) {
                try {
                    exp = e.getAsLong();
                } catch (RuntimeException ignored) {
                    exp = 0;
                }
            }
            return new TokenInfo(subject, exp);
        }
        return null;
    }

    /** Header list from a pasted raw request or header block ("Name: value" lines; first request line skipped). */
    public static List<String[]> parseHeaderBlock(String text) {
        List<String[]> out = new ArrayList<>();
        if (text == null) return out;
        for (String line : text.split("\\r?\\n")) {
            if (line.isBlank()) {
                if (!out.isEmpty()) break;   // end of headers (body follows)
                continue;
            }
            int colon = line.indexOf(':');
            if (colon <= 0 || line.substring(0, colon).contains(" ")) continue;   // request line / junk
            out.add(new String[]{line.substring(0, colon).trim(), line.substring(colon + 1).trim()});
        }
        return out;
    }

    /** Ordered map view of parts, for display. */
    static Map<String, String> asMap(List<Part> parts, Kind kind) {
        Map<String, String> m = new LinkedHashMap<>();
        for (Part p : parts) {
            if (p.kind() == kind) m.put(p.name(), p.value());
        }
        return m;
    }
}
