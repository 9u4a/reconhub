package com.reconhub.active;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

/**
 * One match-and-replace rule for the bulk-send feature ({@code ui.MatchReplaceDialog} /
 * {@link MatchReplaceEngine}). Two independent modes, matching what the request-transform step
 * ({@code MatchReplaceEngine}'s Montoya-object construction, which this class deliberately knows
 * nothing about) needs to build:
 *
 * <ul>
 *   <li><b>HEADER</b> -- replaces (or adds) one named header's value on the request.
 *   <li><b>RAW</b> -- find/replace across the request's entire raw text (request line, headers, body),
 *       the same mental model as Burp Proxy's own Match and Replace rules.
 * </ul>
 *
 * <p>The two {@code computeX} methods here are pure string logic with zero Montoya types involved,
 * specifically so they can be headlessly unit tested -- see {@code MatchReplaceRuleTest}. Actually
 * building a modified {@code HttpRequest} from their output (which needs a real captured request and,
 * for RAW mode, calls a Montoya static factory that throws outside a live Burp runtime) lives in
 * {@link MatchReplaceEngine} instead, and is Burp-smoke-test only.
 *
 * <p>In {@code useRegex} mode, {@code replacement} is passed to {@code Matcher.replaceAll} as-is (not
 * escaped), so {@code $1}/{@code $2} backreferences work -- same as Burp's own Match and Replace and
 * every other "regex replace" tool. In literal mode, {@code replacement} is a plain literal string
 * ({@code String.replace}, which never interprets {@code $}).
 */
public record MatchReplaceRule(Mode mode, String headerName, String matchText, boolean useRegex,
                               String replacement, boolean addHeaderIfMissing) {

    /**
     * REMOVE_HEADER (0.57.0) deletes {@code headerName}; match/replace fields are ignored.
     * COOKIE (0.60.0) sets cookie {@code headerName} to {@code replacement} inside the Cookie header (added
     * if missing), leaving every other cookie as captured; REMOVE_COOKIE drops just that cookie.
     * STRIP_AUTH (0.60.0) removes every auth header / session cookie {@link AuthDetector} confirms on the
     * request except those named in {@code matchText} ({@link #keepSpec}) -- so a session swap can't keep
     * the original user's other credential.
     */
    public enum Mode { HEADER, RAW, REMOVE_HEADER, COOKIE, REMOVE_COOKIE, STRIP_AUTH }

    public static MatchReplaceRule cookie(String name, String value) {
        return new MatchReplaceRule(Mode.COOKIE, name, "", false, value, true);
    }

    public static MatchReplaceRule removeCookie(String name) {
        return new MatchReplaceRule(Mode.REMOVE_COOKIE, name, "", false, "", false);
    }

    /** STRIP_AUTH keeping the given header / cookie names (case-insensitive). */
    public static MatchReplaceRule stripAuthExcept(java.util.Collection<String> keepHeaders,
                                                   java.util.Collection<String> keepCookies) {
        StringBuilder sb = new StringBuilder();
        for (String h : keepHeaders) sb.append(sb.length() == 0 ? "" : ",").append("h:").append(h);
        for (String c : keepCookies) sb.append(sb.length() == 0 ? "" : ",").append("c:").append(c);
        return new MatchReplaceRule(Mode.STRIP_AUTH, null, sb.toString(), false, "", false);
    }

    /** For STRIP_AUTH: {lowercased header names to keep, cookie names to keep}. */
    public java.util.Set<String>[] keepSpec() {
        @SuppressWarnings("unchecked")
        java.util.Set<String>[] out = new java.util.Set[]{new java.util.HashSet<String>(), new java.util.HashSet<String>()};
        if (matchText != null) {
            for (String part : matchText.split(",")) {
                if (part.startsWith("h:")) out[0].add(part.substring(2).trim().toLowerCase(java.util.Locale.ROOT));
                else if (part.startsWith("c:")) out[1].add(part.substring(2).trim());
            }
        }
        return out;
    }

    /**
     * COOKIE / REMOVE_COOKIE: the new Cookie header value given the current one ({@code null} = no Cookie
     * header). Returns {@code null} for "leave the request as is" (removing a cookie from a request that
     * has no Cookie header) and {@code ""} for "remove the Cookie header" (its last cookie was removed).
     */
    public String computeCookieHeader(String currentOrNull) {
        java.util.LinkedHashMap<String, String> jar = AuthDetector.parseCookies(currentOrNull);
        if (mode == Mode.REMOVE_COOKIE) {
            if (currentOrNull == null) return null;
            jar.remove(headerName);
        } else {
            jar.put(headerName, replacement == null ? "" : replacement);
        }
        return AuthDetector.joinCookies(jar);
    }

    // Shared across every rule instance, keyed by the regex text itself (0.43.9) -- a record has no
    // room for a per-instance lazy-compiled field (no extra instance fields allowed), and
    // Pattern.compile is a pure function of matchText, so a small process-wide cache is both safe and
    // simple. Without it, MatchReplaceEngine.buildRequest (which applies every rule to every target)
    // recompiled the same handful of patterns target x rule times per bulk send, and the live dialog
    // preview recompiled on every keystroke.
    private static final Map<String, Pattern> PATTERN_CACHE = new ConcurrentHashMap<>();

    /** Null (never blank) if {@code useRegex} and {@code matchText} doesn't compile -- callers (the
     * dialog) must check this before offering to send, same as {@code SettingsPanel.validateRegex}. */
    public String regexError() {
        if (!useRegex || matchText == null || matchText.isEmpty()) {
            return null;
        }
        try {
            Pattern.compile(matchText);
            return null;
        } catch (PatternSyntaxException e) {
            return "Match pattern is invalid: " + e.getDescription() + " near index " + e.getIndex();
        }
    }

    /**
     * HEADER mode: the new value a header should have, given its current value ({@code null} if the
     * request doesn't have it yet). Returns {@code null} when this rule can't apply to this request at
     * all (header absent and {@link #addHeaderIfMissing} is false) -- the caller records that as a
     * skipped/errored result rather than silently sending the request unmodified.
     *
     * <p>An empty {@link #matchText} means "replace the whole value" -- so for a header that's absent
     * with {@link #addHeaderIfMissing} true and an empty {@code matchText}, the new header is just
     * {@link #replacement}. A non-empty {@code matchText} substitutes only the matched part(s) within
     * the current value, same as {@link #computeRawText}.
     */
    public String computeHeaderValue(String currentValueOrNull) {
        if (currentValueOrNull == null) {
            return addHeaderIfMissing ? replacement : null;
        }
        return applyTo(currentValueOrNull);
    }

    /** RAW mode: the request's raw text with this rule's match/replace applied. A rule that never
     * matches (e.g. {@code matchText} not present anywhere) returns the text unchanged, same as {@code
     * String.replace}/{@code Matcher.replaceAll} would. */
    public String computeRawText(String originalRawText) {
        return applyTo(originalRawText);
    }

    private String applyTo(String text) {
        if (text == null) {
            return null;
        }
        String repl = replacement == null ? "" : replacement;
        if (matchText == null || matchText.isEmpty()) {
            return repl;
        }
        if (useRegex) {
            Pattern p = PATTERN_CACHE.computeIfAbsent(matchText, Pattern::compile);
            return p.matcher(text).replaceAll(repl);
        }
        return text.replace(matchText, repl);
    }
}
