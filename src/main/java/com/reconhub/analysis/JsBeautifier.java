package com.reconhub.analysis;

/**
 * Display-only, best-effort JS reformatter -- <b>not a parser</b>. It never builds an AST, never
 * spaces operators, never breaks commas or wraps long lines, and makes no attempt to be "correct"
 * JavaScript formatting; its only job is to turn one giant minified line into something with line
 * breaks and indentation, which is strictly easier to read than the original even when imperfect.
 *
 * <p>Lexical state comes from {@link JsLexer} (shared with structural analysis). The one thing that
 * <b>must</b> be right is lexical state: string/template/regex/comment bodies
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
    private static final int BACKSCAN_WS_CAP = 4_096;       // skipWs(): bounded whitespace skip

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

    // ---- formatter (consumes JsLexer's token stream) ---------------------------

    /** One-shot, single-input formatter instance -- all mutable state lives here, not in statics. */
    private static final class Formatter {
        private final StringBuilder out = new StringBuilder();
        private int depth;
        private int parenDepth;
        private boolean pendingBreak;
        private boolean pendingSpace;

        String run(String js) {
            JsLexer lx = JsLexer.tokenize(js);
            int n = js.length();
            for (int t = 0; t < lx.size(); t++) {
                byte k = lx.kind(t);
                int s = lx.start(t);
                int e = lx.end(t);
                switch (k) {
                    case JsLexer.WS -> {
                        if (!pendingBreak) {
                            pendingSpace = true;
                        }
                    }
                    case JsLexer.PUNCT -> punct(js, js.charAt(s), s, n);
                    default -> {
                        // identifiers, numbers, and literal/comment bodies: copied verbatim
                        flush();
                        out.append(js, s, e);
                    }
                }
            }
            return out.toString();
        }

        private void punct(String js, char c, int i, int n) {
            if (c == '{') {
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
            } else {
                flush();
                out.append(c);
            }
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

    private static boolean isIdentChar(char c) {
        return JsLexer.isIdentChar(c);
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
