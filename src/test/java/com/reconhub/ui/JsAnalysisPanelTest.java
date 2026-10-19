package com.reconhub.ui;

import com.reconhub.core.DataStore;
import com.reconhub.model.Finding;
import com.reconhub.model.JsAsset;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * {@code JsAnalysisPanel.jsSourcedFindings} -- the JS-tab row filter (findings whose locationUrl matches
 * a JsAsset URL). The static helper is testable without building the panel (which needs a live Burp
 * runtime for MessageViewer); the panel's rendering is a manual smoke-test item.
 */
class JsAnalysisPanelTest {

    private static Finding finding(String type, String location) {
        return new Finding(type, Finding.Severity.MEDIUM, type + "-match", location, "evidence", false);
    }

    @Test
    void keepsOnlyFindingsLocatedAtAJsAssetUrl() {
        DataStore store = new DataStore();
        store.recordJsAsset(new JsAsset("https://h.example/app.js", "sha-1", 100));
        store.recordFinding(finding("eval() call", "https://h.example/app.js"));          // JS-sourced
        store.recordFinding(finding("CryptoJS cipher usage", "https://h.example/app.js")); // JS-sourced
        store.recordFinding(finding("Missing security header", "https://h.example/"));      // not JS

        List<Finding> js = JsAnalysisPanel.jsSourcedFindings(store);
        assertEquals(2, js.size());
        assertTrue(js.stream().allMatch(f -> f.getLocationUrl().equals("https://h.example/app.js")));
    }

    @Test
    void emptyWhenNoJsAssets() {
        DataStore store = new DataStore();
        store.recordFinding(finding("eval() call", "https://h.example/app.js"));
        assertTrue(JsAnalysisPanel.jsSourcedFindings(store).isEmpty());
    }

    @Test
    void findingAtANonAssetUrlIsExcluded() {
        DataStore store = new DataStore();
        store.recordJsAsset(new JsAsset("https://h.example/a.js", "sha-a", 10));
        store.recordFinding(finding("axios call", "https://h.example/b.js"));   // different URL
        assertTrue(JsAnalysisPanel.jsSourcedFindings(store).isEmpty());
    }

    @Test
    void multipleBundlesAllContribute() {
        DataStore store = new DataStore();
        store.recordJsAsset(new JsAsset("https://h.example/a.js", "sha-a", 10));
        store.recordJsAsset(new JsAsset("https://h.example/b.js", "sha-b", 10));
        store.recordFinding(finding("eval() call", "https://h.example/a.js"));
        store.recordFinding(finding("fetch() API call", "https://h.example/b.js"));
        assertEquals(Set.of("https://h.example/a.js", "https://h.example/b.js"),
                Set.copyOf(JsAnalysisPanel.jsSourcedFindings(store).stream()
                        .map(Finding::getLocationUrl).toList()));
    }
}
