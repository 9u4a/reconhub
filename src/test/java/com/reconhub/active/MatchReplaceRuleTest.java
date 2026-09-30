package com.reconhub.active;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;

/** {@code MatchReplaceRule}'s pure string logic (no Montoya types) -- the one part of 0.42.0's Match &
 * Replace feature that can be headlessly tested; building the actual modified {@code HttpRequest}
 * (real captured request + RAW mode's Montoya static factory) needs a live Burp runtime and is
 * Burp-smoke-test only (see {@code MatchReplaceEngine.buildRequest}'s javadoc). */
class MatchReplaceRuleTest {

    private static MatchReplaceRule header(String name, String match, boolean regex, String replace,
                                           boolean addIfMissing) {
        return new MatchReplaceRule(MatchReplaceRule.Mode.HEADER, name, match, regex, replace,
                addIfMissing);
    }

    private static MatchReplaceRule raw(String match, boolean regex, String replace) {
        return new MatchReplaceRule(MatchReplaceRule.Mode.RAW, null, match, regex, replace, false);
    }

    // ---- computeHeaderValue -----------------------------------------------------------------------

    @Test
    void headerModeWithEmptyMatchReplacesTheWholeCurrentValue() {
        MatchReplaceRule rule = header("Cookie", "", false, "session=abc123", false);
        assertEquals("session=abc123", rule.computeHeaderValue("session=old; other=1"));
    }

    @Test
    void headerModeWithNonEmptyMatchReplacesOnlyTheMatchedSubstring() {
        MatchReplaceRule rule = header("Cookie", "session=old", false, "session=new", false);
        assertEquals("session=new; other=1", rule.computeHeaderValue("session=old; other=1"));
    }

    @Test
    void headerModeWithNoCurrentValueAndAddIfMissingFalseReturnsNull() {
        MatchReplaceRule rule = header("X-Custom", "", false, "value", false);
        assertNull(rule.computeHeaderValue(null));
    }

    @Test
    void headerModeWithNoCurrentValueAndAddIfMissingTrueAddsIt() {
        MatchReplaceRule rule = header("X-Custom", "", false, "value", true);
        assertEquals("value", rule.computeHeaderValue(null));
    }

    @Test
    void headerModeRegexSubstitution() {
        MatchReplaceRule rule = header("Cookie", "session=\\w+", true, "session=REPLACED", false);
        assertEquals("session=REPLACED; other=1", rule.computeHeaderValue("session=abc123; other=1"));
    }

    @Test
    void headerModeRegexWithBackreference() {
        MatchReplaceRule rule = header("Cookie", "id=(\\d+)", true, "id=$1$1", false);
        assertEquals("id=4242", rule.computeHeaderValue("id=42"));
    }

    @Test
    void headerModeMatchNotFoundLeavesValueUnchanged() {
        MatchReplaceRule rule = header("Cookie", "nope", false, "x", false);
        assertEquals("session=abc", rule.computeHeaderValue("session=abc"));
    }

    // ---- computeRawText ----------------------------------------------------------------------------

    @Test
    void rawModeLiteralReplace() {
        MatchReplaceRule rule = raw("GET /old/path", false, "GET /new/path");
        String original = "GET /old/path HTTP/1.1\r\nHost: h.example\r\n\r\n";
        assertEquals("GET /new/path HTTP/1.1\r\nHost: h.example\r\n\r\n", rule.computeRawText(original));
    }

    @Test
    void rawModeRegexReplace() {
        MatchReplaceRule rule = raw("Host: .*", true, "Host: other.example");
        String original = "GET / HTTP/1.1\r\nHost: h.example\r\n\r\n";
        assertEquals("GET / HTTP/1.1\r\nHost: other.example\r\n\r\n", rule.computeRawText(original));
    }

    @Test
    void rawModeWithEmptyMatchReplacesEntireText() {
        MatchReplaceRule rule = raw("", false, "REPLACED");
        assertEquals("REPLACED", rule.computeRawText("anything at all"));
    }

    @Test
    void rawModeNoMatchLeavesTextUnchanged() {
        MatchReplaceRule rule = raw("nope-not-present", false, "x");
        String original = "GET / HTTP/1.1\r\n\r\n";
        assertEquals(original, rule.computeRawText(original));
    }

    // ---- regexError ---------------------------------------------------------------------------------

    @Test
    void regexErrorIsNullWhenNotUsingRegex() {
        MatchReplaceRule rule = raw("[unterminated", false, "x");
        assertNull(rule.regexError());   // literal mode -- never compiled as regex, so no error
    }

    @Test
    void regexErrorIsNullForBlankMatchText() {
        MatchReplaceRule rule = raw("", true, "x");
        assertNull(rule.regexError());
    }

    @Test
    void regexErrorIsNullForAValidPattern() {
        MatchReplaceRule rule = raw("session=\\w+", true, "x");
        assertNull(rule.regexError());
    }

    @Test
    void regexErrorNamesTheProblemForAnInvalidPattern() {
        MatchReplaceRule rule = raw("[unterminated", true, "x");
        String err = rule.regexError();
        assertNotNull(err);
        assertEquals(true, err.contains("invalid"));
    }
}
