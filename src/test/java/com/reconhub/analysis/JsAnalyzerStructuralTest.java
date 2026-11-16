package com.reconhub.analysis;

import com.reconhub.core.DataStore;
import com.reconhub.core.Settings;
import com.reconhub.model.Finding;
import com.reconhub.model.JsAsset;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** {@link JsAnalyzer} as the thin adapter over {@link JsStructuralAnalyzer} (0.58.0). Headless. */
class JsAnalyzerStructuralTest {

    private static final PatternRegistry REG = PatternRegistry.load();
    private static final String BODY = "function show(){ var q = location.hash.substring(1);"
            + " document.getElementById('o').innerHTML = q; }"
            + " var e = CryptoJS.AES.encrypt(m, k); var aws = 'AKIAABCDEFGHIJKLMNOP';";

    private static JsAnalyzer analyzer(DataStore store, Settings settings) {
        return new JsAnalyzer(null, store, REG, new SecretScanner(store, REG.secretRules(), true),
                new SecretScanner(store, REG.jsLeadRules(), false), JsStructuralAnalyzer.Rules.of(REG),
                new CommentExtractor(store), new SourceMapDetector(store), settings);
    }

    private static Settings settings() {
        Settings s = new Settings();
        s.setSaveJsToDisk(false);
        return s;
    }

    @Test
    void manualImportRecordsLeadsAndNotes() {
        DataStore store = new DataStore();
        analyzer(store, settings()).analyze("https://app.example/main.js", BODY, null);   // null = manual import
        List<Finding> fs = store.snapshotFindings();
        assertTrue(fs.stream().anyMatch(f -> f.getType().startsWith("DOM XSS: URL fragment")), fs.toString());
        assertFalse(fs.stream().anyMatch(f -> f.getType().equals("CryptoJS cipher usage")),
                "flat locator matches are notes now, not Findings");
        JsAsset a = store.snapshotJsAssets().get(0);
        assertTrue(a.getNotes().stream().anyMatch(n -> n.startsWith("CryptoJS cipher usage")), a.getNotes().toString());
    }

    @Test
    void secretsAreScannedExactlyOnce() {
        DataStore store = new DataStore();
        analyzer(store, settings()).analyze("https://app.example/main.js", BODY, null);
        assertEquals(1, store.snapshotJsAssets().get(0).getExtractedSecrets());
        assertEquals(1, store.snapshotFindings().stream()
                .filter(f -> f.getType().equals("AWS Access Key ID")).count());
    }

    @Test
    void libraryJsSkipsTheStructuralPassUnlessEnabled() {
        DataStore store = new DataStore();
        analyzer(store, settings()).analyze("https://app.example/jquery-3.7.1.min.js", BODY, null);
        assertFalse(store.snapshotFindings().stream().anyMatch(f -> f.getType().startsWith("DOM XSS")));
        assertTrue(store.snapshotJsAssets().get(0).getNotes().isEmpty());
        // secrets still scanned on library JS
        assertEquals(1, store.snapshotJsAssets().get(0).getExtractedSecrets());

        DataStore store2 = new DataStore();
        Settings on = settings();
        on.setAnalyzeLibraryJs(true);
        analyzer(store2, on).analyze("https://app.example/jquery-3.7.1.min.js", BODY, null);
        assertTrue(store2.snapshotFindings().stream().anyMatch(f -> f.getType().startsWith("DOM XSS")));
    }
}
