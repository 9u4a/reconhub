package com.reconhub.ui;

import com.reconhub.model.Finding;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * {@code JsAnalysisPanel.summarize} / {@code jsFileLabel} -- the rollup line and per-file label of the
 * JS Analysis tab (0.50.0). Pure static helpers, so testable without building the panel (which needs a
 * live Burp runtime for MessageViewer) -- same split as {@code jsSourcedFindings}.
 */
class JsAnalysisSummaryTest {

    private static Finding f(String type, String location) {
        return new Finding(type, Finding.Severity.MEDIUM, type + "-m", location, "ev", false);
    }

    @Test
    void emptyInputIsZeroFiles() {
        assertEquals("0 files", JsAnalysisPanel.summarize(List.of()).strip());
    }

    @Test
    void countsCategoriesAndDistinctFiles() {
        String s = JsAnalysisPanel.summarize(List.of(
                f("eval() call", "https://h.example/a.js"),              // Injection, a.js
                f("CryptoJS cipher usage", "https://h.example/a.js"),    // Crypto, a.js
                f("fetch() API call", "https://h.example/b.js")));       // API, b.js
        assertTrue(s.contains("2 files"), s);
        assertTrue(s.contains("Crypto 1"), s);
        assertTrue(s.contains("Injection 1"), s);
        assertTrue(s.contains("API 1"), s);
    }

    @Test
    void sameFileManyFindingsIsOneFile() {
        String s = JsAnalysisPanel.summarize(List.of(
                f("eval() call", "https://h.example/a.js"),
                f("document.cookie access", "https://h.example/a.js")));
        assertTrue(s.contains("1 file"), s);
        assertTrue(!s.contains("files"), "singular 'file' for one distinct file: " + s);
    }

    @Test
    void zeroCategoriesAreOmitted() {
        String s = JsAnalysisPanel.summarize(List.of(f("eval() call", "https://h.example/a.js")));
        assertTrue(s.contains("Injection 1"), s);
        assertTrue(!s.contains("Crypto"), "no Crypto findings -> not shown: " + s);
    }

    @Test
    void jsFileLabelExtractsFilename() {
        assertEquals("app.min.js", JsAnalysisPanel.jsFileLabel(f("t", "https://h.example/static/app.min.js")));
        assertEquals("chunk.js", JsAnalysisPanel.jsFileLabel(f("t", "https://h.example/a/b/chunk.js?v=3")));
    }

    @Test
    void jsFileLabelFallsBackToFullUrlWhenNoFilename() {
        assertEquals("https://h.example/", JsAnalysisPanel.jsFileLabel(f("t", "https://h.example/")));
        assertEquals("(unknown)", JsAnalysisPanel.jsFileLabel(f("t", "")));
    }
}
