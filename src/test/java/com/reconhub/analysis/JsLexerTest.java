package com.reconhub.analysis;

import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** {@link JsLexer} edge cases: regex vs division, nested template expressions, comments with braces. */
class JsLexerTest {

    /** Non-whitespace tokens as "KIND:text". */
    private static List<String> sig(String js) {
        JsLexer lx = JsLexer.tokenize(js);
        List<String> out = new ArrayList<>();
        for (int i = 0; i < lx.size(); i++) {
            if (lx.kind(i) != JsLexer.WS) {
                out.add(name(lx.kind(i)) + ":" + lx.text(i));
            }
        }
        return out;
    }

    private static String name(byte k) {
        return switch (k) {
            case JsLexer.IDENT -> "ID";
            case JsLexer.NUMBER -> "NUM";
            case JsLexer.STRING -> "STR";
            case JsLexer.TEMPLATE -> "TPL";
            case JsLexer.REGEX -> "RE";
            case JsLexer.LINE_COMMENT -> "LC";
            case JsLexer.BLOCK_COMMENT -> "BC";
            case JsLexer.PUNCT -> "P";
            default -> "WS";
        };
    }

    @Test
    void tokensTileTheInputWithNoGaps() {
        String js = "var a=`x${b+`y${c}`}z`;/*{*/ if(a)/re[/]x/g.test(s)//}\n'q\\'' ";
        JsLexer lx = JsLexer.tokenize(js);
        int pos = 0;
        for (int i = 0; i < lx.size(); i++) {
            assertEquals(pos, lx.start(i));
            assertTrue(lx.end(i) > lx.start(i));
            pos = lx.end(i);
        }
        assertEquals(js.length(), pos);
    }

    @Test
    void divisionAfterIdentifierNumberOrParen() {
        assertEquals(List.of("ID:a", "P:/", "ID:b", "P:/", "ID:c"), sig("a / b / c"));
        assertEquals(List.of("NUM:4", "P:/", "NUM:2"), sig("4/2"));
        assertEquals(List.of("P:(", "ID:x", "P:)", "P:/", "NUM:2"), sig("(x)/2"));
    }

    @Test
    void regexAfterPunctuationOrKeyword() {
        assertEquals(List.of("ID:x", "P:=", "RE:/a\\/b[/]c/gi", "P:;"), sig("x=/a\\/b[/]c/gi;"));
        assertEquals(List.of("ID:return", "RE:/}/", "P:."), sig("return /}/."));
        assertEquals(List.of("ID:f", "P:(", "RE:/x/", "P:)"), sig("f(/x/)"));
    }

    @Test
    void templateWithNestedExpressionsIsOneToken() {
        List<String> t = sig("u=`/api/${id}/x/${a ? `n${b}` : '}'}`;z");
        assertEquals(List.of("ID:u", "P:=", "TPL:`/api/${id}/x/${a ? `n${b}` : '}'}`", "P:;", "ID:z"), t);
    }

    @Test
    void commentsContainingBracesAreComments() {
        assertEquals(List.of("BC:/* { } */", "ID:a", "LC:// }{", "ID:b"), sig("/* { } */a// }{\nb"));
    }

    @Test
    void unterminatedStringAndRegexStopAtNewline() {
        assertEquals(List.of("ID:a", "P:=", "STR:'oops\n", "ID:b"), sig("a='oops\nb"));
        assertEquals(List.of("P:(", "RE:/abc", "ID:d"), sig("(/abc\nd"));
    }

    @Test
    void tokenAtFindsContainingToken() {
        String js = "foo('bar')";
        JsLexer lx = JsLexer.tokenize(js);
        assertEquals(JsLexer.STRING, lx.kind(lx.tokenAt(js.indexOf("bar"))));
        assertEquals(JsLexer.IDENT, lx.kind(lx.tokenAt(1)));
        assertEquals(-1, lx.tokenAt(js.length()));
    }
}
