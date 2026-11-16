package com.reconhub.analysis;

import com.reconhub.model.Finding;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * The single JS deep-analysis entry point (0.58.0, ADR 0001): JS body + JS rule set → Leads, per-file
 * notes, and a too-large flag. Pure: no Montoya, no DataStore -- {@link JsAnalyzer} is the thin adapter
 * that records the output.
 *
 * <p>A connection is a <b>Lead</b> only when the token-stream structure proves it (precision over
 * recall):
 * <ul>
 *   <li><b>DOM XSS</b>: an attacker-controllable source reaches a sink in the same function -- directly
 *       in the sink's argument / right-hand side, or through a variable assigned from it in that function.
 *       Values passed through function arguments are unproven. {@code always} sinks need a source too.</li>
 *   <li><b>Pairs</b> ({@code js-pairs.json}): {@code guard} = the target is used inside the code the anchor
 *       guards; {@code argument} = the target literal is passed into the anchor's call, directly or via a
 *       same-scope variable.</li>
 * </ul>
 * Anything the pass cannot prove -- a source merely near a sink, a target merely near an anchor, a sink
 * with no source, a flat locator rule hit -- becomes a <b>note</b> on the JS file, not a Finding.
 */
public final class JsStructuralAnalyzer {

    /** Bodies longer than this skip the structural pass (flat-rule notes still run). Same budget as the
     * beautifier's lexer (ADR 0001: fixed, no measurement gate). */
    public static final int MAX_INPUT = JsBeautifier.MAX_INPUT;
    public static final String TOO_LARGE_NOTE =
            "File too large for structural analysis -- DOM XSS / pair Leads were not computed (secrets and "
                    + "flat-rule matches still ran)";
    /** How far apart (chars) an unlinked source/sink or anchor/target may be and still earn a note. */
    static final int NOTE_WINDOW = 600;
    private static final int MAX_LEADS_PER_KIND = 40;
    private static final int MAX_NOTES = 60;
    private static final int MAX_MATCHES_PER_RULE = 200;
    private static final int MAX_NOTE_MATCHES_PER_RULE = 3;
    private static final int SNIPPET_MAX = 80;
    /** Max significant tokens scanned per region (sink argument, guarded branch, call args) -- bounds the
     * worst case at MAX_MATCHES_PER_RULE x MAX_SCAN on adversarial bundles. */
    static final int MAX_SCAN = 20_000;

    private JsStructuralAnalyzer() {}

    /** One Lead, recorded by the adapter as a {@link Finding}. Same shape the old analyzers emitted. */
    public record Lead(String type, Finding.Severity severity, String rawMatch, String evidence) {}

    /** Analysis output: Leads (Findings), notes (JS file detail only), and whether the size cap hit. */
    public record Result(List<Lead> leads, List<String> notes, boolean tooLarge) {}

    /** The JS rule set the pass consumes. */
    public record Rules(List<PatternRegistry.JsSource> sources, List<PatternRegistry.JsSink> sinks,
                        List<PatternRegistry.JsPair> pairs, List<PatternRegistry.SecretRule> noteRules) {
        public static Rules of(PatternRegistry r) {
            return new Rules(r.jsSources(), r.jsSinks(), r.jsPairs(), r.jsNoteRules());
        }
    }

    public static Result analyze(String body, Rules rules) {
        if (body == null || body.isEmpty()) {
            return new Result(List.of(), List.of(), false);
        }
        List<Lead> leads = new ArrayList<>();
        Set<String> notes = new LinkedHashSet<>();
        boolean tooLarge = body.length() > MAX_INPUT;
        if (tooLarge) {
            notes.add(TOO_LARGE_NOTE);
        } else {
            JsStructure st = JsStructure.of(body);
            flows(st, rules.sources(), rules.sinks(), leads, notes);
            pairs(st, rules.pairs(), leads, notes);
        }
        flatNotes(body, rules.noteRules(), notes);
        List<String> noteList = new ArrayList<>(notes);
        if (noteList.size() > MAX_NOTES) {
            noteList = new ArrayList<>(noteList.subList(0, MAX_NOTES));
        }
        return new Result(Collections.unmodifiableList(leads), Collections.unmodifiableList(noteList), tooLarge);
    }

    // ---- DOM XSS flows ------------------------------------------------------------

    private record SourceHit(int sig, int offset, PatternRegistry.JsSource source) {}

    private static void flows(JsStructure st, List<PatternRegistry.JsSource> sources,
                              List<PatternRegistry.JsSink> sinks, List<Lead> leads, Set<String> notes) {
        if (sinks == null || sinks.isEmpty()) return;
        String body = st.src;
        // Source hits in code (not inside strings/comments). An anchored source only counts when its
        // anchor appears somewhere in the body -- decided once per body (0.55.0 semantics).
        List<SourceHit> hits = new ArrayList<>();
        for (PatternRegistry.JsSource s : sources) {
            if (s.anchor != null && !s.anchor.matcher(body).find()) continue;
            Matcher m = s.pattern.matcher(body);
            int c = 0;
            while (m.find() && c++ < MAX_MATCHES_PER_RULE) {
                int pos = m.start();
                if (pos < body.length() && (body.charAt(pos) == '"' || body.charAt(pos) == '\'')) pos++;
                int sig = st.sigAt(pos);
                if (sig >= 0 && JsLexer.isCode(st.kind(sig))) {
                    hits.add(new SourceHit(sig, pos, s));
                }
            }
        }
        hits.sort((a, b) -> Integer.compare(a.sig, b.sig));
        Map<Integer, Map<String, SourceHit>> tainted = taint(st, hits);

        Set<String> seen = new java.util.HashSet<>();
        int recorded = 0;
        for (PatternRegistry.JsSink sink : sinks) {
            Matcher m = sink.pattern.matcher(body);
            int c = 0;
            while (m.find() && c++ < MAX_MATCHES_PER_RULE && recorded < MAX_LEADS_PER_KIND) {
                int first = st.sigAt(m.start());
                if (first < 0 || !JsLexer.isCode(st.kind(first))) continue;
                int op = -1;
                for (int k = first; k < st.n && st.startOffset(k) < m.end(); k++) {
                    char ch = st.ch(k);
                    if (ch == '(' || (ch == '=' && st.ch(k + 1) != '=')) { op = k; break; }
                }
                if (op < 0) continue;
                int from = op + 1;
                int to = st.ch(op) == '(' ? (st.match[op] > op ? st.match[op] - 1 : st.exprEnd(from))
                        : st.exprEnd(from);
                SourceHit src = reaching(st, hits, tainted, from, to, st.scope[op]);
                String sinkText = m.group().trim();
                if (src != null) {
                    String key = sink.name + "|" + src.source.name;
                    if (seen.add(key)) {
                        String fn = st.scopes.get(st.scope[op]).name;
                        String where = fn.isEmpty() ? "" : " in " + fn + "()";
                        leads.add(new Lead("DOM XSS: " + src.source.name + " -> " + sink.name, sink.severity,
                                sinkText, "source " + src.source.name + " reaches sink " + sink.name + where
                                + "  |  Try: inject via " + src.source.inject + "; " + sink.test));
                        recorded++;
                    }
                } else {
                    SourceHit near = nearest(hits, m.start());
                    if (near != null) {
                        notes.add("Unproven flow: " + sink.name + " near " + near.source.name
                                + " (not linked through a variable in the same function) -- " + snippet(sinkText));
                    } else if (sink.always) {
                        notes.add(sink.name + " call: argument not traced to an attacker-controlled source -- "
                                + snippet(sinkText));
                    }
                }
            }
        }
    }

    /** Variables carrying a source, per scope: assigned (in that scope) from an expression that contains a
     * source hit or another tainted variable of the same scope. Fixpoint, bounded. */
    private static Map<Integer, Map<String, SourceHit>> taint(JsStructure st, List<SourceHit> hits) {
        Map<Integer, Map<String, SourceHit>> tainted = new HashMap<>();
        if (hits.isEmpty()) return tainted;
        for (int round = 0; round < 6; round++) {
            boolean changed = false;
            for (JsStructure.Assign a : st.assigns) {
                Map<String, SourceHit> t = tainted.get(a.scope());
                if (t != null && t.containsKey(a.name())) continue;
                SourceHit h = reaching(st, hits, tainted, a.rhsStart(), a.rhsEnd(), a.scope());
                if (h != null) {
                    tainted.computeIfAbsent(a.scope(), x -> new HashMap<>()).put(a.name(), h);
                    changed = true;
                }
            }
            if (!changed) break;
        }
        return tainted;
    }

    /** A source reaching sig range [from, to] evaluated in {@code scopeId}: a source hit inside the range
     * whose innermost function is that scope, else a variable read in the range tainted in that scope. */
    private static SourceHit reaching(JsStructure st, List<SourceHit> hits,
                                      Map<Integer, Map<String, SourceHit>> tainted,
                                      int from, int to, int scopeId) {
        if (from > to) return null;
        to = Math.min(to, from + MAX_SCAN);
        int lo = lowerBound(hits, from);
        for (int i = lo; i < hits.size() && hits.get(i).sig <= to; i++) {
            if (st.scope[hits.get(i).sig] == scopeId) return hits.get(i);
        }
        Map<String, SourceHit> t = tainted.get(scopeId);
        if (t == null || t.isEmpty()) return null;
        for (int k = from; k <= to; k++) {
            if (st.scope[k] == scopeId && st.isVarRef(k)) {
                SourceHit h = t.get(st.text(k));
                if (h != null) return h;
            }
        }
        return null;
    }

    private static int lowerBound(List<SourceHit> hits, int sig) {
        int lo = 0;
        int hi = hits.size();
        while (lo < hi) {
            int mid = (lo + hi) >>> 1;
            if (hits.get(mid).sig < sig) lo = mid + 1; else hi = mid;
        }
        return lo;
    }

    private static SourceHit nearest(List<SourceHit> hits, int offset) {
        for (SourceHit h : hits) {
            if (Math.abs(h.offset - offset) <= NOTE_WINDOW) return h;
        }
        return null;
    }

    // ---- pairs ------------------------------------------------------------------------

    private static void pairs(JsStructure st, List<PatternRegistry.JsPair> pairs, List<Lead> leads,
                              Set<String> notes) {
        if (pairs == null) return;
        String body = st.src;
        for (PatternRegistry.JsPair pair : pairs) {
            Set<String> seen = new java.util.HashSet<>();
            Matcher am = pair.anchor.matcher(body);
            int c = 0;
            int recorded = 0;
            while (am.find() && c++ < MAX_MATCHES_PER_RULE && recorded < MAX_LEADS_PER_KIND) {
                int a = st.sigAt(am.start());
                if (a < 0 || !JsLexer.isCode(st.kind(a))) continue;
                List<String[]> found = pair.link == PatternRegistry.JsPair.Link.ARGUMENT
                        ? argumentTargets(st, a, pair.target) : guardTargets(st, a, pair.target);
                for (String[] f : found) {
                    if (!seen.add(f[0])) continue;
                    leads.add(new Lead(pair.name + ": " + f[0], pair.severity, f[0],
                            f[1] + "  |  Try: " + pair.note));
                    recorded++;
                }
                if (found.isEmpty()) {
                    String near = nearbyTarget(body, am.start(), am.end(), pair.target);
                    if (near != null) {
                        notes.add("Unlinked: " + pair.name + " -- \"" + near
                                + "\" is near the matched logic but not structurally tied to it");
                    }
                }
            }
        }
    }

    /** {target, evidence} pairs for a GUARD anchor at sig {@code a}. */
    private static List<String[]> guardTargets(JsStructure st, int a, Pattern target) {
        List<int[]> regions = new ArrayList<>();
        int anchor = a;
        boolean negated = st.ch(anchor - 1) == '!';
        // the anchor expression: member chain plus an optional call, e.g. user.hasRole('admin')
        int e = anchor;
        while (st.ch(e + 1) == '.' && st.ident(e + 2)) e += 2;
        if (st.ch(e + 1) == '(' && st.match[e + 1] > e + 1) {
            int open = e + 1;
            regions.add(new int[]{open + 1, st.match[open] - 1});           // requireRole('admin', '/x')
            e = st.match[open];
            if (st.ch(e + 1) == '(' && st.match[e + 1] > e + 1) {            // requireRole('a')(Page('/x'))
                regions.add(new int[]{e + 2, st.match[e + 1] - 1});
            }
        }
        // cond && expr / cond ? a : b
        if (st.ch(e + 1) == '&' && st.ch(e + 2) == '&' && !negated) {
            regions.add(new int[]{e + 3, st.exprEnd(e + 3)});
        } else if (st.ch(e + 1) == '?' && st.ch(e + 2) != '.' && st.ch(e + 2) != '?') {
            int thenEnd = st.exprEnd(e + 2, true);
            if (negated) {
                if (st.ch(thenEnd + 1) == ':') regions.add(new int[]{thenEnd + 2, st.exprEnd(thenEnd + 2)});
            } else {
                regions.add(new int[]{e + 2, thenEnd});
            }
        }
        // enclosing brackets: if (...) branch, the call the anchor is an argument of, the object literal it's in
        int p = st.parent[anchor];
        for (int level = 0; p >= 0 && level < 6; level++, p = st.parent[p]) {
            char c = st.ch(p);
            if (c == '(') {
                if (st.isWord(p - 1, "if") || st.isWord(p - 1, "while")) {
                    int close = st.match[p];
                    if (close < 0) break;
                    int[] branch = statementAt(st, close + 1);
                    if (!negated) {
                        regions.add(branch);
                    } else {
                        // last token of the then-statement: its '}' or the ';' after the expression
                        int last = st.ch(close + 1) == '{' ? st.match[close + 1] : branch[1] + 1;
                        if (st.isWord(last + 1, "else")) {
                            regions.add(statementAt(st, last + 2));
                        }
                    }
                    break;
                }
                if (level == 0 && (st.ident(p - 1) || st.ch(p - 1) == ')') && st.match[p] > p
                        && !st.isWord(p - 1, "for") && !st.isWord(p - 1, "switch")
                        && !st.isWord(p - 1, "function") && st.parent[anchor] == p) {
                    regions.add(new int[]{p + 1, st.match[p] - 1});   // createElement(PrivateRoute, {...})
                }
            } else if (c == '{') {
                if (level <= 1 && isObjectLiteral(st, p) && st.match[p] > p) {
                    regions.add(new int[]{p + 1, st.match[p] - 1});   // {path:'/x', canActivate:[Guard]}
                }
                break;
            } else if (c != '[') {
                break;
            }
        }
        List<String[]> out = new ArrayList<>();
        Set<String> dup = new java.util.HashSet<>();
        for (int[] r : regions) {
            int stop = Math.min(r[1], Math.max(0, r[0]) + MAX_SCAN);
            for (int k = Math.max(0, r[0]); k <= stop && k < st.n; k++) {
                if (st.kind(k) != JsLexer.STRING) continue;
                String t = targetOf(st.text(k), target);
                if (t != null && dup.add(t)) {
                    out.add(new String[]{t, "route \"" + t + "\" is used inside the code this check guards"});
                }
            }
        }
        return out;
    }

    /** {target, evidence} pairs for an ARGUMENT anchor at sig {@code a}: literals passed into its call. */
    private static List<String[]> argumentTargets(JsStructure st, int a, Pattern target) {
        int e = st.isWord(a, "new") ? a + 1 : a;
        int guard = 0;
        while (st.ch(e + 1) == '.' && st.ident(e + 2) && guard++ < 8) e += 2;
        if (st.ch(e + 1) != '(' || st.match[e + 1] <= e + 1) return List.of();
        int open = e + 1;
        int close = st.match[open];
        int scopeId = st.scope[open];
        List<String[]> out = new ArrayList<>();
        Set<String> dup = new java.util.HashSet<>();
        for (int k = open + 1; k < close && k <= open + MAX_SCAN; k++) {
            if (st.kind(k) == JsLexer.STRING) {
                String t = targetOf(st.text(k), target);
                if (t != null && dup.add(t)) {
                    out.add(new String[]{t, "value \"" + t + "\" is passed directly into the crypto call"});
                }
            } else if (st.isVarRef(k)) {
                for (JsStructure.Assign as : st.assignsTo(scopeId, st.text(k))) {
                    for (int r = as.rhsStart(); r <= as.rhsEnd(); r++) {
                        if (st.kind(r) != JsLexer.STRING) continue;
                        String t = targetOf(st.text(r), target);
                        if (t != null && dup.add(t)) {
                            out.add(new String[]{t, "value \"" + t + "\" reaches the crypto call via variable "
                                    + as.name()});
                        }
                    }
                }
            }
        }
        return out;
    }

    /** The statement starting at sig {@code i}: a {...} block (contents) or an expression statement. */
    private static int[] statementAt(JsStructure st, int i) {
        if (st.ch(i) == '{' && st.match[i] > i) return new int[]{i + 1, st.match[i] - 1};
        return new int[]{i, st.exprEnd(i)};
    }

    private static boolean isObjectLiteral(JsStructure st, int brace) {
        char prev = st.ch(brace - 1);
        return prev == '(' || prev == ',' || prev == ':' || prev == '=' || prev == '[' || prev == '?'
                || st.isWord(brace - 1, "return");
    }

    /** The target value (group 1 if present) when the pattern matches this literal token, else null. */
    private static String targetOf(String literal, Pattern target) {
        Matcher m = target.matcher(literal);
        if (!m.find()) return null;
        String v = m.groupCount() >= 1 && m.group(1) != null ? m.group(1) : m.group();
        return v.trim();
    }

    private static String nearbyTarget(String body, int start, int end, Pattern target) {
        int from = Math.max(0, start - NOTE_WINDOW);
        int to = Math.min(body.length(), end + NOTE_WINDOW);
        Matcher m = target.matcher(body.substring(from, to));
        if (m.find()) {
            return (m.groupCount() >= 1 && m.group(1) != null ? m.group(1) : m.group()).trim();
        }
        return null;
    }

    // ---- flat-rule notes ----------------------------------------------------------------

    private static void flatNotes(String body, List<PatternRegistry.SecretRule> rules, Set<String> notes) {
        if (rules == null) return;
        for (PatternRegistry.SecretRule r : rules) {
            Matcher m = r.pattern.matcher(body);
            int c = 0;
            while (c < MAX_NOTE_MATCHES_PER_RULE && notes.size() < MAX_NOTES && m.find()) {
                c++;
                notes.add(r.name + ": " + snippet(m.group()) + (r.note == null ? "" : "  |  Try: " + r.note));
            }
        }
    }

    static String snippet(String s) {
        String t = s.replaceAll("\\s+", " ").trim();
        return t.length() > SNIPPET_MAX ? t.substring(0, SNIPPET_MAX) + "…" : t;
    }
}
