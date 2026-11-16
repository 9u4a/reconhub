package com.reconhub.analysis;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Deque;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Lightweight structure over a {@link JsLexer} token stream (ADR 0001): bracket matching, function scopes
 * from brace matching, and identifier assignments per scope. <b>Not a parser</b> -- it recognizes a few
 * shapes ({@code function f(..){}}, arrows, method shorthand, {@code x = expr}) and treats anything else
 * as plain tokens. Malformed input degrades to fewer scopes/assignments, never an exception.
 *
 * <p>Works on <i>significant</i> tokens only (whitespace and comments dropped); every index below is a
 * significant-token index ("sig index"), translated to lexer tokens via {@link #tok}.
 */
final class JsStructure {

    /** Words that look like {@code name(...) {} } but are statements, not method shorthand. */
    private static final Set<String> NOT_METHOD = Set.of("if", "for", "while", "switch", "catch", "with",
            "function", "return", "typeof", "do", "else", "new", "delete", "void", "await", "yield", "in",
            "of", "instanceof", "case", "throw", "super", "import");
    /** Statement keywords that end an expression when met at depth 0 (ASI in unminified code). */
    private static final Set<String> STMT_START = Set.of("var", "let", "const", "function", "return", "if",
            "for", "while", "class", "switch", "throw", "try", "do");
    static final Set<String> KEYWORDS = Set.of("var", "let", "const", "function", "return", "if", "else",
            "for", "while", "do", "switch", "case", "default", "break", "continue", "new", "delete", "typeof",
            "void", "in", "of", "instanceof", "this", "null", "undefined", "true", "false", "try", "catch",
            "finally", "throw", "class", "extends", "super", "import", "export", "async", "await", "yield",
            "with", "debugger", "static", "get", "set");

    /** A function scope. Scope 0 is the top level (whole body). */
    static final class Scope {
        final int id;
        final int head;        // first sig index of the function (keyword / params / method name)
        final int bodyStart;   // '{' of a block body, or first token of an arrow expression body
        final int bodyEnd;     // matching '}' or last token of the expression body (inclusive)
        final String name;     // "" when anonymous / not inferable
        final Set<String> params;

        Scope(int id, int head, int bodyStart, int bodyEnd, String name, Set<String> params) {
            this.id = id;
            this.head = head;
            this.bodyStart = bodyStart;
            this.bodyEnd = bodyEnd;
            this.name = name;
            this.params = params;
        }
    }

    /** {@code name = <rhs>} where rhs spans sig indices [rhsStart, rhsEnd]. */
    record Assign(int scope, String name, int at, int rhsStart, int rhsEnd) {}

    final JsLexer lx;
    final String src;
    final int n;
    final int[] tok;       // sig index -> lexer token index
    final int[] match;     // sig index -> matching bracket sig index, or -1
    final int[] parent;    // sig index -> innermost enclosing open bracket sig index, or -1
    final int[] scope;     // sig index -> innermost function scope id
    final List<Scope> scopes = new ArrayList<>();
    final List<Assign> assigns = new ArrayList<>();
    private final List<Map<String, List<Assign>>> assignsByScope = new ArrayList<>();
    private final int[] sigOfTok;
    private final int[] exprMemo;   // exprEnd(from, false) cache; -2 = not computed

    private JsStructure(JsLexer lx) {
        this.lx = lx;
        this.src = lx.source();
        int count = 0;
        for (int i = 0; i < lx.size(); i++) {
            if (!JsLexer.isTrivia(lx.kind(i))) count++;
        }
        this.n = count;
        this.tok = new int[n];
        this.sigOfTok = new int[lx.size()];
        Arrays.fill(sigOfTok, -1);
        int k = 0;
        for (int i = 0; i < lx.size(); i++) {
            if (!JsLexer.isTrivia(lx.kind(i))) {
                sigOfTok[i] = k;
                tok[k++] = i;
            }
        }
        this.match = new int[n];
        this.parent = new int[n];
        this.scope = new int[n];
        this.exprMemo = new int[n];
        Arrays.fill(exprMemo, -2);
        matchBrackets();
        findScopes();
        assignScopes();
        findAssignments();
    }

    static JsStructure of(String body) {
        return new JsStructure(JsLexer.tokenize(body));
    }

    // ---- token helpers -------------------------------------------------------

    /** The PUNCT character at sig index {@code i}, or 0 for anything else / out of range. */
    char ch(int i) {
        if (i < 0 || i >= n) return 0;
        int t = tok[i];
        return lx.kind(t) == JsLexer.PUNCT ? src.charAt(lx.start(t)) : 0;
    }

    byte kind(int i) {
        return i < 0 || i >= n ? -1 : lx.kind(tok[i]);
    }

    boolean ident(int i) {
        return kind(i) == JsLexer.IDENT;
    }

    boolean isWord(int i, String w) {
        return i >= 0 && i < n && lx.isIdent(tok[i], w);
    }

    String text(int i) {
        return i < 0 || i >= n ? "" : lx.text(tok[i]);
    }

    int startOffset(int i) {
        return lx.start(tok[i]);
    }

    int endOffset(int i) {
        return lx.end(tok[i]);
    }

    /** Sig index of the significant token containing source offset {@code pos}, or -1. */
    int sigAt(int pos) {
        int t = lx.tokenAt(pos);
        return t < 0 ? -1 : sigOfTok[t];
    }

    /** First sig index whose token starts at or after {@code pos}, or n. */
    int sigFrom(int pos) {
        int lo = 0;
        int hi = n;
        while (lo < hi) {
            int mid = (lo + hi) >>> 1;
            if (startOffset(mid) < pos) lo = mid + 1; else hi = mid;
        }
        return lo;
    }

    /** True for '=' immediately followed by '>' with no gap (an arrow). */
    boolean isArrow(int i) {
        return ch(i) == '=' && ch(i + 1) == '>' && endOffset(i) == startOffset(i + 1);
    }

    /** Unquoted text of a STRING token, or the IDENT text. */
    String keyText(int i) {
        String t = text(i);
        if (kind(i) == JsLexer.STRING && t.length() >= 2) {
            return t.substring(1, t.length() - (t.endsWith(t.substring(0, 1)) ? 1 : 0));
        }
        return t;
    }

    /**
     * Last sig index (inclusive) of the expression starting at {@code from}: stops before a depth-0
     * {@code ,} {@code ;} or an unmatched closer, or before a statement keyword (ASI). Brackets are
     * skipped whole. With {@code stopAtColon} a depth-0 {@code :} also ends it (ternary branches).
     */
    int exprEnd(int from, boolean stopAtColon) {
        if (stopAtColon) {
            return exprWalk(from, true, null);
        }
        if (from < 0 || from >= n) return n - 1;
        if (exprMemo[from] != -2) return exprMemo[from];
        // Memoized for every depth-0 position the walk passes: walking from any of them reaches the same
        // stop. Keeps arrow / assignment chains (x=>x=>…, a=b,c=d,…) linear instead of quadratic.
        List<Integer> visited = new ArrayList<>();
        int end = exprWalk(from, false, visited);
        for (int v : visited) exprMemo[v] = end;
        exprMemo[from] = end;
        return end;
    }

    private int exprWalk(int from, boolean stopAtColon, List<Integer> visited) {
        int i = from;
        while (i < n) {
            if (visited != null && i > from) {
                if (ident(i) && STMT_START.contains(text(i)) && ch(i - 1) != '.') {
                    return i - 1;   // not memoized: walking *from* a keyword does not stop at it
                }
                if (exprMemo[i] != -2) {
                    return exprMemo[i];
                }
                visited.add(i);
            }
            char c = ch(i);
            if (c == '(' || c == '[' || c == '{') {
                if (match[i] < 0) return n - 1;
                i = match[i] + 1;
                continue;
            }
            if (c == ')' || c == ']' || c == '}' || c == ',' || c == ';' || (stopAtColon && c == ':')) {
                return i - 1;
            }
            if (i > from && ident(i) && STMT_START.contains(text(i)) && ch(i - 1) != '.') {
                return i - 1;
            }
            i++;
        }
        return n - 1;
    }

    int exprEnd(int from) {
        return exprEnd(from, false);
    }

    /** True when identifier {@code i} reads a variable: not a property name, not an object-literal key. */
    boolean isVarRef(int i) {
        if (!ident(i) || ch(i - 1) == '.' || KEYWORDS.contains(text(i))) return false;
        if (ch(i + 1) == ':' && parent[i] >= 0 && ch(parent[i]) == '{') {
            // `{key: value}` key -- but a shorthand-free key is never a read
            return false;
        }
        return true;
    }

    /** Function scopes containing sig {@code i}, innermost first (excluding the top level). */
    List<Scope> enclosing(int i) {
        List<Scope> out = new ArrayList<>();
        for (int k = 1; k < scopes.size(); k++) {
            Scope s = scopes.get(k);
            if (s.head <= i && i <= s.bodyEnd) out.add(s);
        }
        out.sort((x, y) -> Integer.compare(x.bodyEnd - x.head, y.bodyEnd - y.head));
        return out;
    }

    /** Argument expressions of the call whose '(' is at {@code open}: sig ranges [from, to], depth-0 commas. */
    List<int[]> args(int open) {
        List<int[]> out = new ArrayList<>();
        int close = open >= 0 && open < n ? match[open] : -1;
        if (close <= open) return out;
        int start = open + 1;
        int i = start;
        while (i < close) {
            char c = ch(i);
            if ((c == '(' || c == '[' || c == '{') && match[i] > i) {
                i = match[i] + 1;
                continue;
            }
            if (c == ',') {
                if (i > start) out.add(new int[]{start, i - 1});
                start = i + 1;
            }
            i++;
        }
        if (close > start) out.add(new int[]{start, close - 1});
        return out;
    }

    /** For an object literal whose '{' is at {@code brace}: depth-1 key → value sig range [from, to]
     * (shorthand {@code {a}} maps a to its own token). Insertion-ordered. */
    Map<String, int[]> objectEntries(int brace) {
        Map<String, int[]> out = new java.util.LinkedHashMap<>();
        if (ch(brace) != '{' || match[brace] <= brace) return out;
        int close = match[brace];
        int i = brace + 1;
        while (i < close) {
            if (ch(i) == '.' && ch(i + 1) == '.' && ch(i + 2) == '.') {   // spread: skip to next comma
                i = skipToComma(i, close);
                continue;
            }
            byte k = kind(i);
            if ((k == JsLexer.IDENT || k == JsLexer.STRING || k == JsLexer.NUMBER) && ch(i + 1) == ':') {
                int end = exprEnd(i + 2);
                out.putIfAbsent(keyText(i), new int[]{i + 2, Math.min(end, close - 1)});
                i = skipToComma(i + 2, close);
            } else if (k == JsLexer.IDENT && (ch(i + 1) == ',' || i + 1 == close)) {
                out.putIfAbsent(text(i), new int[]{i, i});
                i += 2;
            } else {
                i = skipToComma(i, close);   // method shorthand, computed key, ...
            }
        }
        return out;
    }

    private int skipToComma(int i, int close) {
        while (i < close) {
            char c = ch(i);
            if ((c == '(' || c == '[' || c == '{') && match[i] > i) {
                i = match[i] + 1;
                continue;
            }
            i++;
            if (c == ',') break;
        }
        return i;
    }

    // ---- assignments ---------------------------------------------------------

    /** Assignments to {@code name} made in scope {@code scopeId} (never null). */
    List<Assign> assignsTo(int scopeId, String name) {
        Map<String, List<Assign>> m = assignsByScope.get(scopeId);
        List<Assign> l = m == null ? null : m.get(name);
        return l == null ? List.of() : l;
    }

    // ---- passes --------------------------------------------------------------

    private void matchBrackets() {
        Arrays.fill(match, -1);
        Deque<Integer> stack = new ArrayDeque<>();
        for (int i = 0; i < n; i++) {
            parent[i] = stack.isEmpty() ? -1 : stack.peek();
            char c = ch(i);
            if (c == '(' || c == '[' || c == '{') {
                stack.push(i);
            } else if (c == ')' || c == ']' || c == '}') {
                char want = c == ')' ? '(' : c == ']' ? '[' : '{';
                // tolerate a few unmatched openers (malformed / misclassified regex) before giving up
                int depth = 0;
                for (Integer open : stack) {
                    if (ch(open) == want) break;
                    if (++depth > 8) { depth = -1; break; }
                }
                if (depth < 0 || depth >= stack.size()) {
                    continue;   // stray closer: ignore
                }
                for (int d = 0; d < depth; d++) stack.pop();
                int open = stack.pop();
                match[open] = i;
                match[i] = open;
                parent[i] = stack.isEmpty() ? -1 : stack.peek();
            }
        }
    }

    private void findScopes() {
        scopes.add(new Scope(0, 0, 0, n - 1, "", Set.of()));
        for (int i = 0; i < n; i++) {
            if (isWord(i, "function")) {
                int j = i + 1;
                if (ch(j) == '*') j++;
                String name = null;
                if (ident(j)) {
                    name = text(j);
                    j++;
                }
                if (ch(j) == '(' && match[j] > j) {
                    int b = match[j] + 1;
                    if (ch(b) == '{' && match[b] > b) {
                        addScope(i, b, match[b], name != null ? name : inferName(i), params(j + 1, match[j] - 1));
                    }
                }
            } else if (isArrow(i)) {
                int head;
                Set<String> ps;
                if (ch(i - 1) == ')' && match[i - 1] >= 0) {
                    int open = match[i - 1];
                    head = isWord(open - 1, "async") ? open - 1 : open;
                    ps = params(open + 1, i - 2);
                } else if (ident(i - 1)) {
                    head = isWord(i - 2, "async") ? i - 2 : i - 1;
                    ps = Set.of(text(i - 1));
                } else {
                    continue;
                }
                int b = i + 2;
                if (b >= n) continue;
                if (ch(b) == '{' && match[b] > b) {
                    addScope(head, b, match[b], inferName(head), ps);
                } else {
                    addScope(head, b, Math.max(b, exprEnd(b)), inferName(head), ps);
                }
            } else if (ident(i) && ch(i + 1) == '(' && match[i + 1] > i + 1 && ch(i - 1) != '.'
                    && !NOT_METHOD.contains(text(i)) && !isWord(i - 1, "function")) {
                int b = match[i + 1] + 1;
                if (ch(b) == '{' && match[b] > b) {
                    addScope(i, b, match[b], text(i), params(i + 2, match[i + 1] - 1));
                }
            }
        }
    }

    private void addScope(int head, int bodyStart, int bodyEnd, String name, Set<String> params) {
        scopes.add(new Scope(scopes.size(), head, bodyStart, bodyEnd, name == null ? "" : name, params));
    }

    /** Parameter names bound in sig range [from, to]: identifiers not used as a key, default value, or property. */
    private Set<String> params(int from, int to) {
        Set<String> out = new java.util.LinkedHashSet<>();   // ordered: wrappers map args by position
        for (int k = from; k <= to && k < n; k++) {
            if (ident(k) && ch(k + 1) != ':' && ch(k - 1) != '=' && ch(k - 1) != '.'
                    && !KEYWORDS.contains(text(k))) {
                out.add(text(k));
            }
        }
        return out;
    }

    /** Name a function expression is bound to: {@code name = function}, {@code name: () =>}, or "". */
    private String inferName(int head) {
        int p = head - 1;
        if (isWord(p, "async")) p--;
        if (ch(p) == '=' && "=!<>".indexOf(ch(p - 1)) < 0 && ident(p - 1)) {
            return text(p - 1);
        }
        if (ch(p) == ':' && (ident(p - 1) || kind(p - 1) == JsLexer.STRING)) {
            return keyText(p - 1);
        }
        return "";
    }

    private void assignScopes() {
        List<Scope> order = new ArrayList<>(scopes.subList(1, scopes.size()));
        order.sort((a, b) -> a.head != b.head ? Integer.compare(a.head, b.head)
                : Integer.compare(b.bodyEnd, a.bodyEnd));
        Deque<Scope> stack = new ArrayDeque<>();
        int next = 0;
        for (int i = 0; i < n; i++) {
            while (!stack.isEmpty() && i > stack.peek().bodyEnd) stack.pop();
            while (next < order.size() && order.get(next).head == i) {
                Scope s = order.get(next++);
                if (stack.isEmpty() || s.bodyEnd <= stack.peek().bodyEnd) {
                    stack.push(s);
                }
            }
            // skip scopes whose head we passed without pushing (nested inside a malformed range)
            while (next < order.size() && order.get(next).head < i) next++;
            scope[i] = stack.isEmpty() ? 0 : stack.peek().id;
        }
    }

    private void findAssignments() {
        for (int s = 0; s < scopes.size(); s++) assignsByScope.add(null);
        for (int i = 0; i < n; i++) {
            if (!ident(i) || ch(i - 1) == '.' || KEYWORDS.contains(text(i))) continue;
            int rhs;
            if (ch(i + 1) == '=' && ch(i + 2) != '=' && !isArrow(i + 1)) {
                rhs = i + 2;
            } else if ((ch(i + 1) == '+' || ch(i + 1) == '|' || ch(i + 1) == '?') && ch(i + 2) == '='
                    && ch(i + 3) != '=' && endOffset(i + 1) == startOffset(i + 2)) {
                rhs = i + 3;
            } else {
                continue;
            }
            if (rhs >= n) continue;
            int end = exprEnd(rhs);
            if (end < rhs) continue;
            Assign a = new Assign(scope[i], text(i), i, rhs, end);
            assigns.add(a);
            Map<String, List<Assign>> m = assignsByScope.get(a.scope());
            if (m == null) {
                m = new HashMap<>();
                assignsByScope.set(a.scope(), m);
            }
            m.computeIfAbsent(a.name(), x -> new ArrayList<>(2)).add(a);
        }
    }
}
