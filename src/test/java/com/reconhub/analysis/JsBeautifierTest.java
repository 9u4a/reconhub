package com.reconhub.analysis;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullSource;
import org.junit.jupiter.params.provider.ValueSource;

import java.util.Random;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;

/**
 * The whitespace-only invariant (beautify only ever inserts/removes whitespace, never touches any
 * other character), realistic formatting, lexical safety (strings/regex/comments/templates are never
 * reformatted), and pathological-input safety. Ported from a 0.34.0 scratchpad headless check.
 */
class JsBeautifierTest {

    // Must match JsBeautifier's own notion of whitespace (Character.isWhitespace), not the ASCII-only
    // regex \s -- otherwise a Unicode whitespace char (e.g. U+2028 LINE SEPARATOR) that the beautifier
    // legitimately collapses/converts would falsely look like a lost/added character to this check.
    private static String stripWs(String s) {
        if (s == null) {
            return "";
        }
        StringBuilder sb = new StringBuilder(s.length());
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (!Character.isWhitespace(c)) {
                sb.append(c);
            }
        }
        return sb.toString();
    }

    /** Runs beautify(x), asserts the core whitespace-only invariant, and returns the output. */
    private static String checked(String x) {
        String out = JsBeautifier.beautify(x);
        assertEquals(stripWs(x), stripWs(out), "beautify must only add/remove whitespace");
        return out;
    }

    @Test
    void realisticMinifiedSnippet() {
        String x = "(self.webpackChunk=self.webpackChunk||[]).push([[42],{123:(e,t,n)=>{"
                + "e.exports=function(){return fetch(\"/api/admin/users\").then(function(r){"
                + "return r.json()})}}}]);";
        String out = checked(x);
        assertTrue(out.lines().count() > 1, "multi-line output");
        assertTrue(out.lines().anyMatch(l -> l.startsWith("  ")), "some indentation present");
        assertTrue(out.contains("\"/api/admin/users\""), "URL literal intact on one physical span");
    }

    @Test
    void stringLiteralSafety() {
        String x = "var a=\";{}//not a comment\";";
        String out = checked(x);
        int qStart = out.indexOf('"');
        int qEnd = out.indexOf('"', qStart + 1);
        String inside = out.substring(qStart + 1, qEnd);
        assertFalse(inside.contains("\n"), "no newline injected inside string");
        assertEquals(";{}//not a comment", inside, "string content unchanged");
    }

    @Test
    void regexVsDivisionAmbiguity() {
        String x = "a=b/c;d=e/f;";
        String out = checked(x);
        assertTrue(out.lines().count() <= 2, "both divisions stay on one line (no regex misfire)");
    }

    @Test
    void regexWithCharClassUntouched() {
        String x = "x.replace(/[;{}]/g,\"\")";
        String out = checked(x);
        assertTrue(out.contains("/[;{}]/g"), "regex body untouched");
    }

    @Test
    void forLoopSemicolonsStayInsideParens() {
        String x = "for(var i=0;i<n;i++){f(i)}";
        String out = checked(x);
        String firstLine = out.lines().findFirst().orElse("");
        assertEquals(2, firstLine.chars().filter(c -> c == ';').count(),
                "all three ';' stay on the for(...) line");
    }

    @Test
    void templateLiteralSafety() {
        String x = "`a;{b}${c+d}`";
        assertEquals(x, checked(x), "template literal copied verbatim");
    }

    @Test
    void blockAndLineComments() {
        String x = "/* license\nheader */a();//trailing\nb();";
        String out = checked(x);
        assertTrue(out.contains("/* license\nheader */"), "block comment preserved verbatim");
    }

    @ParameterizedTest
    @NullSource
    @ValueSource(strings = {
            "", "   ", "\t\n\r",
            "\"unterminated",
            "/*unterminated",
            "/",
    })
    void pathologicalInputsNeverThrowNeverLoseCharacters(String p) {
        String out = assertDoesNotThrow(() -> JsBeautifier.beautify(p));
        assertNotNull(out);
        assertEquals(stripWs(p == null ? "" : p), stripWs(out));
    }

    @Test
    void pathologicalBraceFlood() {
        String open = "{".repeat(10_000);
        String close = "}".repeat(10_000);
        assertEquals(stripWs(open), stripWs(assertDoesNotThrow(() -> JsBeautifier.beautify(open))));
        assertEquals(stripWs(close), stripWs(assertDoesNotThrow(() -> JsBeautifier.beautify(close))));
    }

    @Test
    void pathologicalLongRun() {
        String a = "a".repeat(1_000_000);
        assertEquals(stripWs(a), stripWs(assertDoesNotThrow(() -> JsBeautifier.beautify(a))));
    }

    @Test
    void randomBinaryGarbageNeverThrows() {
        Random r = new Random(42);
        StringBuilder sb = new StringBuilder(200_000);
        for (int i = 0; i < 200_000; i++) {
            sb.append((char) r.nextInt(65536));
        }
        String randomInput = sb.toString();
        String out = assertDoesNotThrow(() -> JsBeautifier.beautify(randomInput));
        assertNotNull(out);
        assertEquals(stripWs(randomInput), stripWs(out));
    }

    @Test
    void oversizeInputGuard() {
        String big = "a".repeat(JsBeautifier.MAX_INPUT + 1);
        assertEquals(big, JsBeautifier.beautify(big), "over MAX_INPUT returns input unchanged");
    }

    @Test
    void largeRealisticInputCompletesQuickly() {
        StringBuilder sb = new StringBuilder(3_000_000);
        String unit = "function f(e,t){if(e){return t/2}else{var x=\"a;b{c}\";return x}};";
        while (sb.length() < 3_000_000) {
            sb.append(unit);
        }
        String big = sb.substring(0, 3_000_000);
        long start = System.currentTimeMillis();
        String out = JsBeautifier.beautify(big);
        long elapsed = System.currentTimeMillis() - start;
        assertTrue(elapsed < 1000, "3MB beautify should complete in < 1000ms, took " + elapsed);
        assertTrue(out.length() > 0);
    }

    @Test
    void snippetSkipsBannerAndUseStrict() {
        assertTrue(JsBeautifier.snippet("/* Copyright 2024 */\n\"use strict\";\nfunction foo(){}", 200)
                .startsWith("function foo"));
    }

    @Test
    void snippetCollapsesWhitespace() {
        assertFalse(JsBeautifier.snippet("a   \n\n  b", 200).contains("\n"));
    }

    @Test
    void snippetTruncatesWithEllipsis() {
        String longSnip = JsBeautifier.snippet("x".repeat(500), 100);
        assertEquals(101, longSnip.length());
        assertTrue(longSnip.endsWith("…"));
    }

    @Test
    void snippetNullAndEmptyAndZeroMaxCharsAreSafe() {
        assertEquals("", JsBeautifier.snippet(null, 100));
        assertEquals("", JsBeautifier.snippet("", 100));
        assertEquals("", JsBeautifier.snippet("abc", 0));
    }
}
