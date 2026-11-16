package com.reconhub.ui;

import com.reconhub.model.ClientFlow;
import com.reconhub.model.Endpoint;
import com.reconhub.model.Finding;
import com.reconhub.model.JsAsset;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** JS Assets detail tabs (0.63.0): row data per tab, note parsing, badges, and the panel itself (headless). */
class JsInfoContentTest {

    private static final String URL = "https://app.example/static/main.3f2a.js?v=1";

    private static JsAsset asset() {
        JsAsset a = new JsAsset(URL, "abc123", 4096);
        a.setNotes(List.of(
                "Unproven flow: innerHTML near URL fragment (location.hash) (not linked through a variable in the same function) -- el.innerHTML=",
                "Unlinked: Client-side authorization gate -> route -- \"/admin\" is near the matched logic but not structurally tied to it",
                "CryptoJS cipher usage: CryptoJS.AES.encrypt(  |  Try: find the key/IV/mode",
                "File too large for structural analysis -- DOM XSS / pair Leads were not computed"));
        return a;
    }

    private static JsInfoContent.Content content() {
        Finding low = new Finding("Hidden parameter in JS: debug", Finding.Severity.LOW, "debug", URL,
                "parameter referenced in JS  |  Try: add ?debug=1", false);
        Finding high = new Finding("DOM XSS: URL fragment -> innerHTML", Finding.Severity.HIGH, "el.innerHTML=", URL,
                "source reaches sink  |  Try: inject via the fragment", false);
        ClientFlow f = new ClientFlow("DELETE", "/api/users/{id}", "app.example");
        f.merge(List.of("reason"), List.of(), "", "del", "route /admin", "fetch", "", URL, true, null);
        Endpoint e = new Endpoint("GET", "app.example", "/api/me", "https://app.example/api/me");
        return JsInfoContent.build(new JsInfoContent.Input(asset(), List.of(low, high), List.of(f), List.of(e), 12));
    }

    @Test
    void headerAndRowsPerTab() {
        JsInfoContent.Content c = content();
        assertEquals("main.3f2a.js", c.title());
        assertEquals(List.of("4.0 KB", "Risk 12"), c.badges().stream().map(JsInfoContent.Badge::text).toList());
        assertTrue(c.badges().get(1).warn(), "risk >= 10 is highlighted");
        assertEquals(Finding.Severity.HIGH, c.findings().get(0).severity(), "HIGH first");
        assertEquals("", c.findings().get(1).value(), "a value already in the type name is not repeated");
        assertTrue(c.findings().get(0).hint().contains("inject via the fragment"));
        JsInfoContent.FlowRow flow = c.flows().get(0);
        assertEquals("DELETE", flow.method());
        assertEquals("reason", flow.bodyKeys());
        assertEquals("(none)", flow.auth());
        assertEquals(List.of("https://app.example/api/me"), c.endpoints());
        assertEquals("SHA-256", c.file().get(1)[0]);
    }

    @Test
    void notesAreSplitIntoKindDetailAndHint() {
        List<JsInfoContent.NoteRow> n = content().notes();
        assertEquals(List.of("Possible flow", "Possible pair", "CryptoJS cipher usage", "Info"),
                n.stream().map(JsInfoContent.NoteRow::kind).toList());
        assertEquals("CryptoJS.AES.encrypt(", n.get(2).detail());
        assertEquals("find the key/IV/mode", n.get(2).hint());
        assertTrue(n.get(0).detail().startsWith("innerHTML near URL fragment"));
    }

    @Test
    void libraryGetsAWarnBadgeAndNote() {
        JsAsset lib = new JsAsset("https://cdn.example/jquery-3.7.1.min.js", "x", 90_000);
        lib.setKind("jQuery");
        JsInfoContent.Content c = JsInfoContent.build(new JsInfoContent.Input(lib, List.of(), List.of(), List.of(), 0));
        assertTrue(c.badges().get(0).warn());
        assertEquals("jQuery", c.badges().get(0).text());
        assertTrue(c.libraryNote().contains("deep analysis is skipped"));
        assertEquals("87.9 KB", JsInfoContent.kb(90_000));
    }

    @Test
    void panelBuildsAndFillsTablesHeadless() {
        System.setProperty("java.awt.headless", "true");
        JsInfoPanel p = new JsInfoPanel();
        p.show(content());
        assertEquals("Findings (2)", p.tabs().getTitleAt(JsInfoPanel.FINDINGS));
        assertEquals("Client Flows (1)", p.tabs().getTitleAt(JsInfoPanel.FLOWS));
        assertEquals("Notes (4)", p.tabs().getTitleAt(JsInfoPanel.NOTES));
        assertEquals("Endpoints (1)", p.tabs().getTitleAt(JsInfoPanel.ENDPOINTS));
        p.clear();
        assertEquals("Findings", p.tabs().getTitleAt(JsInfoPanel.FINDINGS));
    }
}
