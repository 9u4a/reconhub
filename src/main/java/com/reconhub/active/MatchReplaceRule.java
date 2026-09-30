package com.reconhub.active;

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

    public enum Mode { HEADER, RAW }

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
            return Pattern.compile(matchText).matcher(text).replaceAll(repl);
        }
        return text.replace(matchText, repl);
    }
}
