package com.reconhub.analysis;

import com.reconhub.core.DataStore;
import com.reconhub.export.HtmlReporter;
import com.reconhub.export.JsonExporter;
import com.reconhub.export.MarkdownReporter;
import com.reconhub.export.SarifExporter;
import com.reconhub.export.StateSerializer;
import com.reconhub.model.ClientFlow;
import com.reconhub.model.Endpoint;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** {@link ClientFlowLeads} (0.59.0): Seen, IDOR / no-auth typing, hints, Repeater template, exports. */
class ClientFlowLeadsTest {

    private static ClientFlow flow(String method, String path, List<String> body, List<String> query, String auth) {
        ClientFlow f = new ClientFlow(method, path, "app.example");
        f.merge(body, query, auth, "fn", "", "fetch", "fetch('" + path + "'", "https://app.example/main.js", true, null);
        return f;
    }

    private static Endpoint endpoint(DataStore store, String method, String path, int status) {
        return store.recordEndpoint(method, "app.example", path, "https://app.example" + path, status, "application/json",
                "proxy", Set.of(), null, Set.of());
    }

    // ---- Seen (#10) ---------------------------------------------------------------------

    @Test
    void placeholderMatchesOneSegmentAndMethodMustAgree() {
        DataStore store = new DataStore();
        Endpoint e = endpoint(store, "GET", "/api/users/42", 200);
        endpoint(store, "GET", "/api/users/42/orders", 200);
        ClientFlowLeads.SeenIndex idx = ClientFlowLeads.index(store.snapshotEndpoints());

        assertSame(e, idx.find(flow("GET", "/api/users/{id}", List.of(), List.of(), "")));
        assertNull(idx.find(flow("DELETE", "/api/users/{id}", List.of(), List.of(), "")));
        assertNull(idx.find(flow("GET", "/api/users", List.of(), List.of(), "")));
        assertSame(e, idx.find(flow("GET", "https://app.example/api/users/{uid}/", List.of(), List.of(), "")));
    }

    @Test
    void endpointsOnlyReferencedInJsAreNotSeen() {
        DataStore store = new DataStore();
        endpoint(store, "GET", "/api/admin", 0);   // status 0 = never answered (JS-referenced only)
        assertNull(ClientFlowLeads.index(store.snapshotEndpoints())
                .find(flow("GET", "/api/admin", List.of(), List.of(), "")));
    }

    // ---- type / hint (#11) ----------------------------------------------------------------

    @Test
    void idorFromPlaceholderNumericSegmentOrKeys() {
        assertEquals(ClientFlowLeads.TYPE_IDOR, ClientFlowLeads.type(flow("GET", "/api/orders/{orderId}", List.of(), List.of(), "Authorization")));
        assertEquals(ClientFlowLeads.TYPE_IDOR, ClientFlowLeads.type(flow("GET", "/api/users/1/profile", List.of(), List.of(), "Authorization")));
        assertEquals(ClientFlowLeads.TYPE_IDOR, ClientFlowLeads.type(flow("POST", "/member/modify.do", List.of("memberNo", "email"), List.of(), "x")));
        assertEquals(ClientFlowLeads.TYPE_IDOR, ClientFlowLeads.type(flow("GET", "/board/view", List.of(), List.of("board_seq"), "x")));
        assertTrue(ClientFlowLeads.hint(flow("GET", "/api/orders/{orderId}", List.of(), List.of(), "x")).startsWith("change {orderId}"));
    }

    @Test
    void noAuthAndPlainFlows() {
        assertEquals(ClientFlowLeads.TYPE_NO_AUTH, ClientFlowLeads.type(flow("GET", "/api/notices", List.of("valid", "paid"), List.of(), "")));
        assertEquals(ClientFlowLeads.TYPE, ClientFlowLeads.type(flow("GET", "/api/notices", List.of(), List.of(), "Authorization")));
        assertTrue(ClientFlowLeads.hint(flow("GET", "/api/notices", List.of(), List.of(), "")).contains("unauthenticated"));
    }

    @Test
    void taxonomyPrefixAndHintOrderComeFirst() {
        assertEquals(FindingTaxonomy.Category.AUTH, FindingTaxonomy.categoryOf(ClientFlowLeads.TYPE_IDOR));
        assertEquals(FindingTaxonomy.Category.AUTH, FindingTaxonomy.categoryOf(ClientFlowLeads.TYPE_NO_AUTH));
        assertEquals(FindingTaxonomy.Category.API, FindingTaxonomy.categoryOf(ClientFlowLeads.TYPE));
        assertTrue(FindingHints.forType(ClientFlowLeads.TYPE_IDOR).contains("second account"));
        assertTrue(FindingHints.forType(ClientFlowLeads.TYPE_NO_AUTH).contains("unauthenticated"));
        assertTrue(FindingHints.forType(ClientFlowLeads.TYPE).contains("Repeater template"));
    }

    // ---- Repeater template (#10) -------------------------------------------------------------

    @Test
    void repeaterTemplateCarriesMethodPathAuthAndJsonBody() {
        ClientFlowLeads.Template t = ClientFlowLeads.template(
                flow("PUT", "/api/users/{id}", List.of("name", "role"), List.of("lang"), "Authorization (localStorage)"));
        assertEquals("app.example", t.host());
        assertEquals(443, t.port());
        assertTrue(t.secure());
        String body = "{\"name\":\"\",\"role\":\"\"}";
        assertTrue(t.raw().startsWith("PUT /api/users/{id}?lang= HTTP/1.1\r\nHost: app.example\r\n"), t.raw());
        assertTrue(t.raw().contains("Authorization: <token>\r\n"), t.raw());
        assertTrue(t.raw().contains("Content-Length: " + body.length() + "\r\n"), t.raw());
        assertTrue(t.raw().endsWith("\r\n\r\n" + body), t.raw());
    }

    @Test
    void absoluteTemplateTargetsItsOwnHost() {
        ClientFlowLeads.Template t = ClientFlowLeads.template(
                flow("GET", "http://api.internal.example:8080/v1/items", List.of(), List.of(), ""));
        assertEquals("api.internal.example", t.host());
        assertEquals(8080, t.port());
        assertFalse(t.secure());
        assertTrue(t.raw().startsWith("GET /v1/items HTTP/1.1\r\nHost: api.internal.example\r\n"), t.raw());
        assertFalse(t.raw().contains("Content-Type"), "GET without keys has no body");
    }

    // ---- store + exports (#11) ----------------------------------------------------------------

    @Test
    void sameKeyMergesAndExportsIncludeFlowsButStateDoesNot(@TempDir Path dir) throws Exception {
        DataStore store = new DataStore();
        ClientFlow a = store.recordClientFlow(new ClientFlow("GET", "/api/orders/{orderId}", "app.example"));
        a.merge(List.of(), List.of(), "", "load", "route /orders", "fetch", "fetch(`/api/orders/${orderId}`",
                "https://app.example/a.js", true, null);
        ClientFlow b = store.recordClientFlow(new ClientFlow("GET", "/api/orders/{orderId}", "app.example"));
        assertSame(a, b);
        b.merge(List.of(), List.of("page"), "Authorization", "", "", "", "", "https://app.example/b.js", true, null);
        assertEquals(1, store.snapshotClientFlows().size());
        assertEquals(List.of("https://app.example/a.js", "https://app.example/b.js"), a.getJsUrls());
        assertEquals("Authorization", a.getAuth());

        Path json = dir.resolve("r.json");
        JsonExporter.export(store, json);
        String j = Files.readString(json, StandardCharsets.UTF_8);
        assertTrue(j.contains("\"clientFlows\"") && j.contains("/api/orders/{orderId}") && j.contains(ClientFlowLeads.TYPE_IDOR), j);

        Path md = dir.resolve("r.md");
        MarkdownReporter.export(store, md);
        assertTrue(Files.readString(md, StandardCharsets.UTF_8).contains("## Client Flows"));

        Path html = dir.resolve("r.html");
        HtmlReporter.export(store, html);
        assertTrue(Files.readString(html, StandardCharsets.UTF_8).contains("Client Flows"));

        Path sarif = dir.resolve("r.sarif");
        SarifExporter.export(store, sarif);
        assertTrue(Files.readString(sarif, StandardCharsets.UTF_8).contains(ClientFlowLeads.TYPE_IDOR));

        Path state = dir.resolve("s.json");
        StateSerializer.export(store, state, false);
        assertFalse(Files.readString(state, StandardCharsets.UTF_8).contains("/api/orders/{orderId}"),
                "state format unchanged: flows are recomputed from JS, not saved");
    }

    @Test
    void deleteHostAndClearRemoveFlows() {
        DataStore store = new DataStore();
        store.recordClientFlow(new ClientFlow("GET", "/a", "one.example"));
        store.recordClientFlow(new ClientFlow("GET", "/b", "two.example"));
        store.deleteHost("one.example");
        assertEquals(List.of("/b"), store.snapshotClientFlows().stream().map(ClientFlow::getPath).toList());
        store.clear();
        assertTrue(store.snapshotClientFlows().isEmpty());
    }

    // ---- end to end through the analyzer ----------------------------------------------------------

    @Test
    void analyzerRecordsFlowsFromAppJsOnly() {
        PatternRegistry reg = PatternRegistry.load();
        com.reconhub.core.Settings s = new com.reconhub.core.Settings();
        s.setSaveJsToDisk(false);
        DataStore store = new DataStore();
        JsAnalyzer an = new JsAnalyzer(null, store, reg, new SecretScanner(store, reg.secretRules(), true),
                new SecretScanner(store, reg.jsLeadRules(), false), JsStructuralAnalyzer.Rules.of(reg),
                new CommentExtractor(store), new SourceMapDetector(store), s);
        String js = "function del(id){ return fetch('/api/users/' + id, {method: 'DELETE'}); }";
        an.analyze("https://app.example/main.js", js, null);
        an.analyze("https://app.example/jquery-3.7.1.min.js", js + " fetch('/api/lib');", null);
        List<ClientFlow> flows = store.snapshotClientFlows();
        assertEquals(1, flows.size(), flows.toString());
        assertEquals("DELETE /api/users/{id}", flows.get(0).key());
        assertEquals("app.example", flows.get(0).getHost());
    }
}
