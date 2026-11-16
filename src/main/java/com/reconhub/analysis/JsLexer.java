package com.reconhub.analysis;

import java.util.Arrays;
import java.util.Set;

/**
 * Lexical token stream over a JS body -- the state machine {@link JsBeautifier} has always used
 * (strings, template literals, regex literals, comments), exposed so other analysis can consume it.
 * <b>Not a parser</b>: it never builds an AST and never throws on malformed input; every character of
 * the input belongs to exactly one token, so tokens tile the body with no gaps.
 *
 * <p>Tokens are stored in parallel primitive arrays (kind / start / end offsets into the source), not
 * as objects -- a 3M-char minified bundle yields on the order of a million tokens.
 *
 * <p>Bounded-damage rules (unchanged from the beautifier): a single- or double-quoted string and a
 * regex literal end at a raw newline, so a misclassified quote or '/' costs at most one line.
 * Template literals track nested {@code ${ ... }} expressions (including nested templates, strings and
 * braces) so a backtick inside an expression doesn't end the outer template.
 */
public final class JsLexer {

    /** Token kinds. */
    public static final byte WS = 0;
    public static final byte IDENT = 1;          // identifiers and keywords (incl. $ and _)
    public static final byte NUMBER = 2;
    public static final byte STRING = 3;         // '...' or "..." including quotes
    public static final byte TEMPLATE = 4;       // `...` including backticks and any ${...} parts
    public static final byte REGEX = 5;          // /.../flags
    public static final byte LINE_COMMENT = 6;   // //... up to (not including) the newline
    public static final byte BLOCK_COMMENT = 7;  // /* ... */
    public static final byte PUNCT = 8;          // exactly one character

    // Characters after which a following '/' starts a regex literal, not a division operator.
    private static final String PUNCT_ALLOW = "(,=:[!&|?{};+-*%~^<>";
    private static final Set<String> REGEX_KEYWORDS = Set.of(
            "return", "typeof", "case", "in", "of", "new", "delete", "void", "do", "else",
            "yield", "await");
    private static final int MAX_TEMPLATE_DEPTH = 32;

    private final String src;
    private byte[] kinds = new byte[64];
    private int[] starts = new int[64];
    private int[] ends = new int[64];
    private int size;

    private JsLexer(String src) {
        this.src = src;
    }

    /** Tokenizes {@code js} (null → empty). Never throws for any input. */
    public static JsLexer tokenize(String js) {
        JsLexer lx = new JsLexer(js == null ? "" : js);
        lx.run();
        return lx;
    }

    public String source() { return src; }
    public int size() { return size; }
    public byte kind(int i) { return kinds[i]; }
    public int start(int i) { return starts[i]; }
    public int end(int i) { return ends[i]; }
    public String text(int i) { return src.substring(starts[i], ends[i]); }

    /** True when token {@code i} is a single PUNCT character {@code c}. */
    public boolean isPunct(int i, char c) {
        return i >= 0 && i < size && kinds[i] == PUNCT && src.charAt(starts[i]) == c;
    }

    /** True when token {@code i} is an IDENT spelled {@code word}. */
    public boolean isIdent(int i, String word) {
        return i >= 0 && i < size && kinds[i] == IDENT && ends[i] - starts[i] == word.length()
                && src.regionMatches(starts[i], word, 0, word.length());
    }

    /** Index of the token containing source offset {@code pos} (binary search), or -1. */
    public int tokenAt(int pos) {
        if (pos < 0 || size == 0 || pos >= ends[size - 1]) {
            return -1;
        }
        int lo = 0;
        int hi = size - 1;
        while (lo <= hi) {
            int mid = (lo + hi) >>> 1;
            if (ends[mid] <= pos) {
                lo = mid + 1;
            } else if (starts[mid] > pos) {
                hi = mid - 1;
            } else {
                return mid;
            }
        }
        return -1;
    }

    /** True for kinds that are code (not whitespace, comment, or literal body). */
    public static boolean isCode(byte k) {
        return k == IDENT || k == NUMBER || k == PUNCT;
    }

    /** True for kinds skipped when walking significant tokens (whitespace and comments). */
    public static boolean isTrivia(byte k) {
        return k == WS || k == LINE_COMMENT || k == BLOCK_COMMENT;
    }

    // ---- lexing --------------------------------------------------------------

    private void add(byte k, int s, int e) {
        if (size == kinds.length) {
            int cap = size * 2;
            kinds = Arrays.copyOf(kinds, cap);
            starts = Arrays.copyOf(starts, cap);
            ends = Arrays.copyOf(ends, cap);
        }
        kinds[size] = k;
        starts[size] = s;
        ends[size] = e;
        size++;
    }

    private void run() {
        int n = src.length();
        int i = 0;
        while (i < n) {
            char c = src.charAt(i);
            int s = i;
            if (Character.isWhitespace(c)) {
                while (i < n && Character.isWhitespace(src.charAt(i))) i++;
                add(WS, s, i);
            } else if (c == '\'' || c == '"') {
                i = scanQuoted(i, c);
                add(STRING, s, i);
            } else if (c == '`') {
                i = scanTemplate(i, 0);
                add(TEMPLATE, s, i);
            } else if (c == '/' && i + 1 < n && src.charAt(i + 1) == '/') {
                i += 2;
                while (i < n && src.charAt(i) != '\n') i++;
                add(LINE_COMMENT, s, i);
            } else if (c == '/' && i + 1 < n && src.charAt(i + 1) == '*') {
                int close = src.indexOf("*/", i + 2);
                i = close < 0 ? n : close + 2;
                add(BLOCK_COMMENT, s, i);
            } else if (c == '/' && regexAllowed()) {
                i = scanRegex(i);
                add(REGEX, s, i);
            } else if (isIdentStart(c)) {
                while (i < n && isIdentChar(src.charAt(i))) i++;
                add(IDENT, s, i);
            } else if (c >= '0' && c <= '9' || (c == '.' && i + 1 < n && Character.isDigit(src.charAt(i + 1)))) {
                i++;
                while (i < n && (isIdentChar(src.charAt(i)) || src.charAt(i) == '.')) i++;
                add(NUMBER, s, i);
            } else {
                add(PUNCT, s, i + 1);
                i++;
            }
        }
    }

    /** End offset (exclusive) of a quoted string starting at {@code i}; ends at the quote or a raw newline. */
    private int scanQuoted(int i, char q) {
        int n = src.length();
        int j = i + 1;
        while (j < n) {
            char c = src.charAt(j);
            if (c == '\\' && j + 1 < n) {
                j += 2;
                continue;
            }
            j++;
            if (c == q || c == '\n') {
                return j;
            }
        }
        return n;
    }

    /** End offset of a template literal starting at backtick {@code i}, tracking nested ${...}. */
    private int scanTemplate(int i, int depth) {
        int n = src.length();
        int j = i + 1;
        while (j < n) {
            char c = src.charAt(j);
            if (c == '\\' && j + 1 < n) {
                j += 2;
            } else if (c == '`') {
                return j + 1;
            } else if (c == '$' && j + 1 < n && src.charAt(j + 1) == '{' && depth < MAX_TEMPLATE_DEPTH) {
                j = scanTemplateExpr(j + 2, depth + 1);
            } else {
                j++;
            }
        }
        return n;
    }

    /** Skips a ${...} expression body starting just after '{'; returns the offset after its '}'. */
    private int scanTemplateExpr(int i, int depth) {
        int n = src.length();
        int braces = 0;
        int j = i;
        while (j < n) {
            char c = src.charAt(j);
            if (c == '\'' || c == '"') {
                j = scanQuoted(j, c);
            } else if (c == '`') {
                j = scanTemplate(j, depth);
            } else if (c == '/' && j + 1 < n && src.charAt(j + 1) == '*') {
                int close = src.indexOf("*/", j + 2);
                j = close < 0 ? n : close + 2;
            } else if (c == '{') {
                braces++;
                j++;
            } else if (c == '}') {
                if (braces == 0) {
                    return j + 1;
                }
                braces--;
                j++;
            } else {
                j++;
            }
        }
        return n;
    }

    /** End offset of a regex literal starting at '/' {@code i} (flags included); ends at a raw newline. */
    private int scanRegex(int i) {
        int n = src.length();
        int j = i + 1;
        int classDepth = 0;
        while (j < n) {
            char c = src.charAt(j);
            if (c == '\\' && j + 1 < n) {
                j += 2;
            } else if (c == '\n') {
                return j;   // bounded damage: a regex can't contain a raw newline
            } else {
                j++;
                if (c == '[') {
                    classDepth++;
                } else if (c == ']' && classDepth > 0) {
                    classDepth--;
                } else if (c == '/' && classDepth == 0) {
                    while (j < n && Character.isLetter(src.charAt(j))) j++;
                    return j;
                }
            }
        }
        return n;
    }

    /** True when a '/' at the current position starts a regex literal, judged by the previous significant token. */
    private boolean regexAllowed() {
        int t = size - 1;
        while (t >= 0 && isTrivia(kinds[t])) t--;
        if (t < 0) {
            return true;   // start of file
        }
        if (kinds[t] == PUNCT) {
            return PUNCT_ALLOW.indexOf(src.charAt(starts[t])) >= 0;
        }
        if (kinds[t] == IDENT) {
            return REGEX_KEYWORDS.contains(src.substring(starts[t], ends[t]));
        }
        return false;
    }

    static boolean isIdentStart(char c) {
        return Character.isLetter(c) || c == '_' || c == '$';
    }

    static boolean isIdentChar(char c) {
        return Character.isLetterOrDigit(c) || c == '_' || c == '$';
    }
}
