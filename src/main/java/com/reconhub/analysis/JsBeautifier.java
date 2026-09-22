package com.reconhub.analysis;

import java.util.Set;

/**
 * Display-only, best-effort JS reformatter -- <b>not a parser</b>. It never builds an AST, never
 * spaces operators, never breaks commas or wraps long lines, and makes no attempt to be "correct"
 * JavaScript formatting; its only job is to turn one giant minified line into something with line
 * breaks and indentation, which is strictly easier to read than the original even when imperfect.
 *
 * <p>The one thing that <b>must</b> be right is lexical state: string/template/regex/comment bodies
 * are copied through byte-for-byte, never reformatted, because a newline injected into a string
 * literal (very common in minified code, e.g. {@code ";{}"} as a literal value) would make the
 * output read worse than the input. Governing invariant, checked by the test suite: stripping all
 * whitespace from {@code beautify(x)} always reproduces stripping all whitespace from {@code x}
 * exactly -- every rule here only inserts or removes whitespace, never any other character.
 *
 * <p>Never throws. Any {@code RuntimeException} (or an input over {@link #MAX_INPUT}) makes
 * {@link #beautify} return the input completely unchanged -- worse than beautified, never worse
 * than broken.
 */
public final class JsBeautifier {

    /**
     * Largest body this will attempt to reformat. This runs on the EDT in response to a UI toggle
     * (see {@code ui.MessageViewer}), so the budget is "stay responsive to a click", not "don't drop
     * a valuable result" -- deliberately much smaller than {@link SourceMapDetector}'s 8&nbsp;MB parse
     * limit, which runs on a background ingest thread. Do not unify the two.
     */
    public static final int MAX_INPUT = 3_000_000;

    private static final int MAX_INDENT = 40;              // clamp runaway nesting depth
    private static final int SNIPPET_SCAN_CAP = 8_192;      // snippet() never looks past this
    private static final int BACKSCAN_WS_CAP = 4_096;       // regexAllowed(): bounded whitespace skip
    private static final int BACKSCAN_WORD_CAP = 32;        // regexAllowed(): bounded word scan

    // Characters after which a following '/' starts a regex literal, not a division operator.
    private static final String PUNCT_ALLOW = "(,=:[!&|?{};+-*%~^<>";
    private static final Set<String> REGEX_KEYWORDS = Set.of(
            "return", "typeof", "case", "in", "of", "new", "delete", "void", "do", "else",
            "yield", "await");

    private JsBeautifier() {
    }

    /** Reformats minified JS for reading. Display only -- never throws, never loses a character. */
    public static String beautify(String js) {
        if (js == null) {
            return "";
        }
        if (js.length() > MAX_INPUT) {
            return js;
        }
        try {
            return new Formatter().run(js);
        } catch (RuntimeException e) {
            return js;
        }
    }

    /**
     * A short, single-line identifying snippet: skips one leading banner comment and a leading
     * {@code "use strict";}, collapses whitespace, truncates to {@code maxChars}. Never throws.
     */
    public static String snippet(String js, int maxChars) {
        try {
            if (js == null || js.isEmpty() || maxChars <= 0) {
                return "";
            }
            String head = js.substring(0, Math.min(js.length(), SNIPPET_SCAN_CAP));
            int i = skipWs(head, 0);
            if (i + 1 < head.length() && head.charAt(i) == '/' && head.charAt(i + 1) == '*') {
                int end = head.indexOf("*/", i + 2);
                i = skipWs(head, end >= 0 ? end + 2 : head.length());
            }
            if (i + 1 < head.length() && head.charAt(i) == '/' && head.charAt(i + 1) == '/') {
                int end = head.indexOf('\n', i + 2);
                i = skipWs(head, end >= 0 ? end + 1 : head.length());
            }
            if (i + 13 <= head.length() && (head.regionMatches(i, "\"use strict\";", 0, 13)
                    || head.regionMatches(i, "'use strict';", 0, 13))) {
                i = skipWs(head, i + 13);
            }
            String rest = head.substring(Math.min(i, head.length()));
            String collapsed = rest.replaceAll("\\s+", " ").trim();
            return collapsed.length() > maxChars
                    ? collapsed.substring(0, maxChars) + "…" : collapsed;
        } catch (RuntimeException e) {
            return "";
        }
    }

    // ---- lexer/formatter --------------------------------------------------

    private enum State { CODE, SQ, DQ, TEMPLATE, LINE_COMMENT, BLOCK_COMMENT, REGEX }

    /** One-shot, single-input formatter instance -- all mutable state lives here, not in statics. */
    private static final class Formatter {
        private final StringBuilder out = new StringBuilder();
        private int depth;
        private int parenDepth;
        private boolean pendingBreak;
        private boolean pendingSpace;

        String run(String js) {
            State state = State.CODE;
            int regexClassDepth = 0;
            int n = js.length();
            for (int i = 0; i < n; i++) {
                char c = js.charAt(i);
                switch (state) {
                    case CODE -> {
                        if (c == '\'') {
                            flush();
                            out.append(c);
                            state = State.SQ;
                        } else if (c == '"') {
                            flush();
                            out.append(c);
                            state = State.DQ;
                        } else if (c == '`') {
                            flush();
                            out.append(c);
                            state = State.TEMPLATE;
                        } else if (c == '/' && i + 1 < n && js.charAt(i + 1) == '/') {
                            flush();
                            out.append("//");
                            i++;
                            state = State.LINE_COMMENT;
                        } else if (c == '/' && i + 1 < n && js.charAt(i + 1) == '*') {
                            flush();
                            out.append("/*");
                            i++;
                            state = State.BLOCK_COMMENT;
                        } else if (c == '/' && regexAllowed(out)) {
                            flush();
                            out.append(c);
                            state = State.REGEX;
                            regexClassDepth = 0;
                        } else if (c == '{') {
                            flush();
                            out.append(c);
                            depth++;
                            pendingBreak = true;
                        } else if (c == '}') {
                            depth = Math.max(0, depth - 1);
                            flush();
                            out.append(c);
                            int p = skipWs(js, i + 1);
                            char nextCh = p < n ? js.charAt(p) : 0;
                            if (nextCh != 0 && ",;)]".indexOf(nextCh) >= 0) {
                                pendingSpace = true;
                            } else if (startsWithWord(js, p, "else") || startsWithWord(js, p, "catch")
                                    || startsWithWord(js, p, "finally") || startsWithWord(js, p, "while")) {
                                pendingSpace = true;
                            } else if (p < n) {
                                pendingBreak = true;
                            }
                        } else if (c == ';') {
                            flush();
                            out.append(c);
                            if (parenDepth == 0) {
                                pendingBreak = true;
                            }
                        } else if (c == '(') {
                            flush();
                            out.append(c);
                            parenDepth++;
                        } else if (c == ')') {
                            parenDepth = Math.max(0, parenDepth - 1);
                            flush();
                            out.append(c);
                        } else if (Character.isWhitespace(c)) {
                            if (!pendingBreak) {
                                pendingSpace = true;
                            }
                        } else {
                            flush();
                            out.append(c);
                        }
                    }
                    case SQ -> {
                        if (c == '\\' && i + 1 < n) {
                            out.append(c).append(js.charAt(i + 1));
                            i++;
                        } else {
                            out.append(c);
                            if (c == '\'' || c == '\n') {
                                state = State.CODE;
                            }
                        }
                    }
                    case DQ -> {
                        if (c == '\\' && i + 1 < n) {
                            out.append(c).append(js.charAt(i + 1));
                            i++;
                        } else {
                            out.append(c);
                            if (c == '"' || c == '\n') {
                                state = State.CODE;
                            }
                        }
                    }
                    case TEMPLATE -> {
                        if (c == '\\' && i + 1 < n) {
                            out.append(c).append(js.charAt(i + 1));
                            i++;
                        } else {
                            out.append(c);
                            if (c == '`') {
                                state = State.CODE;
                            }
                        }
                    }
                    case LINE_COMMENT -> {
                        if (c == '\n') {
                            state = State.CODE;
                            i--;   // reprocess the newline in CODE (normal whitespace handling)
                        } else {
                            out.append(c);
                        }
                    }
                    case BLOCK_COMMENT -> {
                        out.append(c);
                        if (c == '/' && out.length() >= 2 && out.charAt(out.length() - 2) == '*') {
                            state = State.CODE;
                        }
                    }
                    case REGEX -> {
                        if (c == '\\' && i + 1 < n) {
                            out.append(c).append(js.charAt(i + 1));
                            i++;
                        } else if (c == '\n') {
                            // A regex literal can't legally contain a raw newline -- bounded-damage
                            // exit: a misclassified '/' costs at most this one line, not the rest of
                            // the file.
                            state = State.CODE;
                            i--;
                        } else {
                            out.append(c);
                            if (c == '[') {
                                regexClassDepth++;
                            } else if (c == ']' && regexClassDepth > 0) {
                                regexClassDepth--;
                            } else if (c == '/' && regexClassDepth == 0) {
                                int j = i + 1;
                                while (j < n && Character.isLetter(js.charAt(j))) {
                                    out.append(js.charAt(j));
                                    j++;
                                }
                                i = j - 1;
                                state = State.CODE;
                            }
                        }
                    }
                }
            }
            return out.toString();
        }

        private void flush() {
            if (pendingBreak) {
                out.append('\n');
                int ind = Math.min(depth, MAX_INDENT);
                out.append("  ".repeat(ind));
                pendingBreak = false;
                pendingSpace = false;
            } else if (pendingSpace) {
                out.append(' ');
                pendingSpace = false;
            }
        }
    }

    // ---- shared helpers -----------------------------------------------------

    /** True when a '/' at the current position in {@code out} starts a regex literal, not division. */
    private static boolean regexAllowed(StringBuilder out) {
        int j = out.length() - 1;
        int scanned = 0;
        while (j >= 0 && Character.isWhitespace(out.charAt(j)) && scanned < BACKSCAN_WS_CAP) {
            j--;
            scanned++;
        }
        if (j < 0) {
            return true;   // start of file
        }
        char last = out.charAt(j);
        if (PUNCT_ALLOW.indexOf(last) >= 0) {
            return true;
        }
        if (!isIdentChar(last)) {
            return false;
        }
        int end = j + 1;
        int start = end;
        int wscan = 0;
        while (start > 0 && isIdentChar(out.charAt(start - 1)) && wscan < BACKSCAN_WORD_CAP) {
            start--;
            wscan++;
        }
        return REGEX_KEYWORDS.contains(out.substring(start, end));
    }

    private static boolean isIdentChar(char c) {
        return Character.isLetterOrDigit(c) || c == '_' || c == '$';
    }

    private static int skipWs(String s, int from) {
        int j = Math.max(0, from);
        int limit = Math.min(s.length(), from + BACKSCAN_WS_CAP);
        while (j < limit && Character.isWhitespace(s.charAt(j))) {
            j++;
        }
        return j;
    }

    private static boolean startsWithWord(String s, int pos, String word) {
        int len = word.length();
        if (pos < 0 || pos + len > s.length() || !s.regionMatches(pos, word, 0, len)) {
            return false;
        }
        return pos + len >= s.length() || !isIdentChar(s.charAt(pos + len));
    }
}
