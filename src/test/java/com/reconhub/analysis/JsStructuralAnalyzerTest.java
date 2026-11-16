package com.reconhub.analysis;

import com.reconhub.model.Finding;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.regex.Pattern;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * {@link JsStructuralAnalyzer} (0.58.0): Leads only when the token-stream structure proves the link;
 * everything else becomes a per-file note. The 0.57 JsFlowAnalyzer/JsPairAnalyzer true-positive cases
 * are migrated here. Hand-built rules so the tests don't depend on the shipped JSON wording.
 */
class JsStructuralAnalyzerTest {

    // ---- rules -----------------------------------------------------------------

    private static PatternRegistry.JsSource src(String name, String regex, String inject) {
        return new PatternRegistry.JsSource(name, Pattern.compile(regex), inject);
    }

    private static PatternRegistry.JsSink sink(String name, String regex, boolean always) {
        return new PatternRegistry.JsSink(name, Pattern.compile(regex), Finding.Severity.HIGH, "do X", always);
    }

    private static final List<PatternRegistry.JsSource> SOURCES = List.of(
            src("URL fragment", "location\\.hash", "the fragment"),
            src("URL query", "location\\.search", "a query parameter"));
    private static final List<PatternRegistry.JsSink> SINKS = List.of(
            sink("innerHTML", "\\.innerHTML\\s*=[^=]", false),
            sink("eval()", "\\beval\\s*\\(", true));

    private static final Pattern ROUTE = Pattern.compile("[\"'](/[A-Za-z0-9_/-]{1,40})[\"']");
    private static final PatternRegistry.JsPair GATE = new PatternRegistry.JsPair("authz gate",
            Finding.Severity.MEDIUM, Pattern.compile("isAdmin|requireRole|canActivate"), ROUTE, "do X",
            PatternRegistry.JsPair.Link.GUARD);
    private static final PatternRegistry.JsPair KEY = new PatternRegistry.JsPair("crypto key",
            Finding.Severity.HIGH, Pattern.compile("CryptoJS\\."),
            Pattern.compile("[\"']([A-Za-z0-9+/=_-]{16,64})[\"']"), "do Y", PatternRegistry.JsPair.Link.ARGUMENT);

    private static JsStructuralAnalyzer.Result flows(String body) {
        return JsStructuralAnalyzer.analyze(body, new JsStructuralAnalyzer.Rules(SOURCES, SINKS, List.of(), List.of()));
    }

    private static JsStructuralAnalyzer.Result pairs(String body, PatternRegistry.JsPair... ps) {
        return JsStructuralAnalyzer.analyze(body,
                new JsStructuralAnalyzer.Rules(List.of(), List.of(), List.of(ps), List.of()));
    }

    private static boolean hasLead(JsStructuralAnalyzer.Result r, String type) {
        return r.leads().stream().anyMatch(l -> l.type().equals(type));
    }

    private static boolean hasNote(JsStructuralAnalyzer.Result r, String part) {
        return r.notes().stream().anyMatch(n -> n.contains(part));
    }

    // ---- DOM XSS ------------------------------------------------------------------

    @Test
    void sourceReachesSinkThroughSameFunctionVariable() {   // migrated 0.57 TP
        JsStructuralAnalyzer.Result r = flows("var x = location.hash; el.innerHTML = x;");
        assertTrue(hasLead(r, "DOM XSS: URL fragment -> innerHTML"), r.toString());
        assertTrue(r.leads().get(0).evidence().contains("Try: inject via the fragment"), r.toString());
    }

    @Test
    void sourceDirectlyInSinkValue() {
        JsStructuralAnalyzer.Result r = flows("function go(){ el.innerHTML = decodeURIComponent(location.hash.slice(1)); }");
        assertTrue(hasLead(r, "DOM XSS: URL fragment -> innerHTML"), r.toString());
        assertTrue(r.leads().get(0).evidence().contains("in go()"), r.toString());
    }

    @Test
    void chainOfVariablesInOneFunction() {
        JsStructuralAnalyzer.Result r = flows(
                "function f(){ var a = location.search, b = '<p>' + a + '</p>'; node.innerHTML = b; }");
        assertTrue(hasLead(r, "DOM XSS: URL query -> innerHTML"), r.toString());
    }

    @Test
    void nearbyButUnrelatedIsANoteNotALead() {
        JsStructuralAnalyzer.Result r = flows(
                "function a(){ var h = location.hash; log(h); } function b(){ el.innerHTML = msg; }");
        assertTrue(r.leads().isEmpty(), r.toString());
        assertTrue(hasNote(r, "Unproven flow: innerHTML near URL fragment"), r.toString());
    }

    @Test
    void sameVariableNameInAnotherFunctionIsNotLinked() {
        JsStructuralAnalyzer.Result r = flows(
                "function a(){ var x = location.hash; } function b(){ var x = tpl; el.innerHTML = x; }");
        assertTrue(r.leads().isEmpty(), r.toString());
    }

    @Test
    void valuePassedThroughFunctionArgumentIsUnproven() {
        JsStructuralAnalyzer.Result r = flows("function render(v){ el.innerHTML = v; } render(location.hash);");
        assertTrue(r.leads().isEmpty(), r.toString());
    }

    @Test
    void nonAlwaysSinkWithNoSourceIsDropped() {   // migrated 0.57 behavior
        JsStructuralAnalyzer.Result r = flows("el.innerHTML = someLocalTemplate;");
        assertTrue(r.leads().isEmpty());
        assertTrue(r.notes().isEmpty(), r.toString());
    }

    @Test
    void alwaysSinkNeedsAProvableSource() {
        JsStructuralAnalyzer.Result none = flows("eval(decodeURIComponent(s));");
        assertTrue(none.leads().isEmpty(), none.toString());
        assertTrue(hasNote(none, "eval() call: argument not traced"), none.toString());

        JsStructuralAnalyzer.Result withSrc = flows("function f(){ var s = location.hash; eval(s); }");
        assertTrue(hasLead(withSrc, "DOM XSS: URL fragment -> eval()"), withSrc.toString());
    }

    @Test
    void farApartSourceAndSinkGiveNothing() {   // migrated 0.57 negative
        String body = "location.hash;" + "x".repeat(JsStructuralAnalyzer.NOTE_WINDOW + 50) + "el.innerHTML = y;";
        JsStructuralAnalyzer.Result r = flows(body);
        assertTrue(r.leads().isEmpty());
        assertTrue(r.notes().isEmpty(), r.toString());
    }

    @Test
    void sourceInsideAStringLiteralIsNotASource() {
        assertTrue(flows("el.innerHTML = 'location.hash';").leads().isEmpty());
    }

    @Test
    void anchoredSourceNeedsItsAnchorSomewhereInTheBody() {   // migrated 0.57 TP (0.55.0 anchor semantics)
        PatternRegistry.JsSource pm = new PatternRegistry.JsSource("postMessage data",
                Pattern.compile("\\be\\.data\\b"), "a postMessage",
                Pattern.compile("addEventListener\\(\"message\""));
        JsStructuralAnalyzer.Rules rules = new JsStructuralAnalyzer.Rules(List.of(pm), SINKS, List.of(), List.of());

        String noListener = "function render(e){ el.innerHTML = e.data.html; }";
        assertTrue(JsStructuralAnalyzer.analyze(noListener, rules).leads().isEmpty());

        String withListener = "window.addEventListener(\"message\", h); function h(e){ el.innerHTML = e.data; }";
        assertTrue(hasLead(JsStructuralAnalyzer.analyze(withListener, rules), "DOM XSS: postMessage data -> innerHTML"));
    }

    @Test
    void shippedPostMessageSourceIgnoresBareDataProperty() {   // migrated 0.57 negative
        PatternRegistry reg = PatternRegistry.load();
        String body = "axios.get(u).then(function(r){ node.innerHTML = r.data.html; });";
        assertTrue(JsStructuralAnalyzer.analyze(body, JsStructuralAnalyzer.Rules.of(reg)).leads().stream()
                .noneMatch(l -> l.type().contains("postMessage")));
    }

    @Test
    void shippedRulesFindAClassicHashFlow() {
        PatternRegistry reg = PatternRegistry.load();
        String body = "function show(){ var q = location.hash.substring(1); document.getElementById('o').innerHTML = q; }";
        assertTrue(JsStructuralAnalyzer.analyze(body, JsStructuralAnalyzer.Rules.of(reg)).leads().stream()
                .anyMatch(l -> l.type().startsWith("DOM XSS: URL fragment")));
    }

    @Test
    void oneLeadPerSinkSourceKindPerBody() {   // migrated 0.57 dedup
        String one = "function f(){ var x = location.hash; el.innerHTML = x; } ";
        JsStructuralAnalyzer.Result r = flows(one.repeat(10));
        assertEquals(1, r.leads().stream().filter(l -> l.type().contains("innerHTML")).count(), r.toString());
    }

    // ---- pairs: guard -----------------------------------------------------------

    @Test
    void wrappedRouteIsAGuardLead() {   // migrated 0.57 TP
        JsStructuralAnalyzer.Result r = pairs("const AdminRoute = requireRole('admin')(withPath('/admin/users'));", GATE);
        assertEquals(1, r.leads().size(), r.toString());
        assertEquals("/admin/users", r.leads().get(0).rawMatch());
        assertTrue(r.leads().get(0).type().startsWith("authz gate: /admin/users"));
        assertTrue(r.leads().get(0).evidence().contains("Try: do X"));
    }

    @Test
    void routeInsideTheGuardedIfBranch() {
        JsStructuralAnalyzer.Result r = pairs("if (user.isAdmin) { navigate('/admin/panel'); } go('/home');", GATE);
        assertEquals(List.of("/admin/panel"), r.leads().stream().map(JsStructuralAnalyzer.Lead::rawMatch).toList());
    }

    @Test
    void usesCapturingGroupOneAsTheTarget() {   // migrated 0.57 TP, now inside the guarded branch
        JsStructuralAnalyzer.Result r = pairs("if (requireRole('r')) { fetch('/api/admin/delete'); }", GATE);
        assertTrue(r.leads().stream().anyMatch(l -> l.rawMatch().equals("/api/admin/delete")), r.toString());
    }

    @Test
    void negatedCheckGuardsTheElseBranch() {
        JsStructuralAnalyzer.Result r = pairs("if (!isAdmin()) { go('/login'); } else { go('/admin/home'); }", GATE);
        assertEquals(List.of("/admin/home"), r.leads().stream().map(JsStructuralAnalyzer.Lead::rawMatch).toList());
    }

    @Test
    void andAndTernaryOperands() {
        assertEquals("/admin/x", pairs("isAdmin && router.push('/admin/x');", GATE).leads().get(0).rawMatch());
        JsStructuralAnalyzer.Result t = pairs("var p = isAdmin ? '/admin/y' : '/user/y';", GATE);
        assertEquals(List.of("/admin/y"), t.leads().stream().map(JsStructuralAnalyzer.Lead::rawMatch).toList());
    }

    @Test
    void routeObjectWithGuardKey() {
        JsStructuralAnalyzer.Result r = pairs(
                "const routes = [{path: '/admin/users', canActivate: [AdminGuard]}, {path: '/public'}];", GATE);
        assertEquals(List.of("/admin/users"), r.leads().stream().map(JsStructuralAnalyzer.Lead::rawMatch).toList());
    }

    @Test
    void routeMerelyNearbyIsANote() {
        JsStructuralAnalyzer.Result r = pairs("requireRole('r'); fetch('/api/admin/delete');", GATE);
        assertTrue(r.leads().isEmpty(), r.toString());
        assertTrue(hasNote(r, "Unlinked: authz gate"), r.toString());
    }

    @Test
    void noTargetAndFarTargetGiveNothing() {   // migrated 0.57 negatives
        assertTrue(pairs("if (isAdmin()) { renderMenu(); }", GATE).leads().isEmpty());
        String far = "isAdmin();" + "x".repeat(JsStructuralAnalyzer.NOTE_WINDOW + 50) + "'/admin/secret';";
        JsStructuralAnalyzer.Result r = pairs(far, GATE);
        assertTrue(r.leads().isEmpty());
        assertTrue(r.notes().isEmpty());
    }

    @Test
    void dedupsSameTargetPerBody() {   // migrated 0.57 dedup
        JsStructuralAnalyzer.Result r = pairs("requireRole('x')('/admin/a'); ".repeat(8), GATE);
        assertEquals(1, r.leads().stream().filter(l -> l.rawMatch().equals("/admin/a")).count(), r.toString());
    }

    // ---- pairs: argument --------------------------------------------------------

    @Test
    void keyLiteralPassedDirectlyIntoCryptoCall() {
        JsStructuralAnalyzer.Result r = pairs("var c = CryptoJS.AES.encrypt(data, 'abcdefghijklmnop1234');", KEY);
        assertEquals(List.of("abcdefghijklmnop1234"), r.leads().stream().map(JsStructuralAnalyzer.Lead::rawMatch).toList());
        assertTrue(r.leads().get(0).evidence().contains("passed directly"));
    }

    @Test
    void keyLiteralViaSameScopeVariable() {
        JsStructuralAnalyzer.Result r = pairs(
                "function enc(d){ var k = '0123456789abcdefXYZ'; return CryptoJS.AES.encrypt(d, k, {iv: iv}); }", KEY);
        assertEquals(1, r.leads().size(), r.toString());
        assertTrue(r.leads().get(0).evidence().contains("via variable k"), r.toString());
    }

    @Test
    void unrelatedLiteralNearCryptoIsNotALead() {
        JsStructuralAnalyzer.Result r = pairs(
                "var title = 'averyveryverylongtitle'; var c = CryptoJS.AES.encrypt(d, key);", KEY);
        assertTrue(r.leads().isEmpty(), r.toString());
        assertTrue(hasNote(r, "Unlinked: crypto key"), r.toString());
    }

    @Test
    void shippedPairRulesLoadWithLinkTypes() {
        PatternRegistry reg = PatternRegistry.load();
        assertTrue(reg.jsPairs().stream().anyMatch(p -> p.link == PatternRegistry.JsPair.Link.GUARD));
        assertTrue(reg.jsPairs().stream().anyMatch(p -> p.link == PatternRegistry.JsPair.Link.ARGUMENT));
    }

    // ---- notes, size cap ----------------------------------------------------------------

    @Test
    void flatLocatorRulesBecomeNotesNotLeads() {
        PatternRegistry reg = PatternRegistry.load();
        JsStructuralAnalyzer.Result r = JsStructuralAnalyzer.analyze("var e = CryptoJS.AES.encrypt(m, k);",
                JsStructuralAnalyzer.Rules.of(reg));
        assertTrue(r.leads().isEmpty(), r.toString());
        assertTrue(hasNote(r, "CryptoJS cipher usage"), r.toString());
        assertTrue(hasNote(r, "Try: "), r.toString());
    }

    @Test
    void oversizedBodySkipsStructureButKeepsFlatNotes() {
        PatternRegistry reg = PatternRegistry.load();
        String body = "var x = location.hash; el.innerHTML = x; CryptoJS.AES.encrypt(m, k);"
                + " ".repeat(JsStructuralAnalyzer.MAX_INPUT);
        JsStructuralAnalyzer.Result r = JsStructuralAnalyzer.analyze(body, JsStructuralAnalyzer.Rules.of(reg));
        assertTrue(r.tooLarge());
        assertTrue(r.leads().isEmpty(), "no structural Leads above the cap");
        assertEquals(JsStructuralAnalyzer.TOO_LARGE_NOTE, r.notes().get(0));
        assertTrue(hasNote(r, "CryptoJS cipher usage"));
    }

    @Test
    void emptyAndMalformedInputNeverThrow() {
        JsStructuralAnalyzer.Rules rules = JsStructuralAnalyzer.Rules.of(PatternRegistry.load());
        assertFalse(JsStructuralAnalyzer.analyze("", rules).tooLarge());
        JsStructuralAnalyzer.analyze("}}}{{{ ((( el.innerHTML = location.hash ]]] `${", rules);
        JsStructuralAnalyzer.analyze("function(", rules);
        JsStructuralAnalyzer.analyze("=>=>=>", rules);
    }
}
