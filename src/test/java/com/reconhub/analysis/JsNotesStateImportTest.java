package com.reconhub.analysis;

import com.reconhub.core.DataStore;
import com.reconhub.core.Settings;
import com.reconhub.export.StateSerializer;
import com.reconhub.model.Finding;
import com.reconhub.model.JsAsset;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 0.58.0: per-file notes are never serialized (state format unchanged); after an import they are
 * rebuilt from the saved JS file, without inflating already-imported Leads.
 */
class JsNotesStateImportTest {

    private static final PatternRegistry REG = PatternRegistry.load();
    private static final String BODY = "function show(){ var q = location.hash.substring(1);"
            + " document.getElementById('o').innerHTML = q; } var e = CryptoJS.AES.encrypt(m, k);";

    private static JsAnalyzer analyzer(DataStore store, Settings s) {
        return new JsAnalyzer(null, store, REG, new SecretScanner(store, REG.secretRules(), true),
                new SecretScanner(store, REG.jsLeadRules(), false), JsStructuralAnalyzer.Rules.of(REG),
                new CommentExtractor(store), new SourceMapDetector(store), s);
    }

    @Test
    void notesAreRebuiltFromTheSavedFileAfterImport(@TempDir Path dir) throws Exception {
        Settings s = new Settings();
        s.setSaveJsToDisk(true);
        s.setJsSaveDirectory(dir.resolve("js"));
        DataStore before = new DataStore();
        analyzer(before, s).analyze("https://app.example/main.js", BODY, null);
        JsAsset original = before.snapshotJsAssets().get(0);
        assertFalse(original.getNotes().isEmpty());
        assertFalse(original.getSavedPath().isEmpty());

        Path state = dir.resolve("state.json");
        StateSerializer.export(before, state, false);
        assertFalse(Files.readString(state, StandardCharsets.UTF_8).contains("CryptoJS cipher usage"),
                "notes must not be written into the state file");

        DataStore after = new DataStore();
        StateSerializer.importInto(after, state, true);
        JsAsset imported = after.snapshotJsAssets().get(0);
        assertTrue(imported.getNotes().isEmpty(), "notes are not part of the state");
        Finding lead = after.snapshotFindings().stream()
                .filter(f -> f.getType().startsWith("DOM XSS")).findFirst().orElseThrow();
        int seenBefore = lead.getTimesSeen();

        String body = Files.readString(Path.of(imported.getSavedPath()), StandardCharsets.UTF_8);
        analyzer(after, s).rebuildFromStored(imported, body);

        assertTrue(imported.getNotes().stream().anyMatch(n -> n.startsWith("CryptoJS cipher usage")),
                imported.getNotes().toString());
        assertEquals(seenBefore, lead.getTimesSeen(), "an already-imported Lead is not re-counted");
    }
}
