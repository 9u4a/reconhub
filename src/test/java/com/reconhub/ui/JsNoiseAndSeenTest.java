package com.reconhub.ui;

import com.reconhub.model.Endpoint;
import com.reconhub.model.Finding;
import com.reconhub.model.JsAsset;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** 0.55.0 static helpers: JS Assets' noise rule and JS Analysis' "Seen" column. The panels themselves
 * need a live Burp runtime (MessageViewer), so only these pure parts are headless-tested. */
class JsNoiseAndSeenTest {

    @Test
    void libraryIsNoiseRegardlessOfContent() {
        JsAsset a = new JsAsset("https://h.example/jquery.min.js", "s1", 90_000);
        a.setKind("Library: jQuery");
        a.setExtractedEndpoints(3);
        assertTrue(JsAssetsPanel.isNoise(a, 5));
    }

    @Test
    void emptyChunkIsNoiseButSmallFileWithFindingsIsNot() {
        JsAsset tiny = new JsAsset("https://h.example/12.chunk.js", "s2", 400);
        assertTrue(JsAssetsPanel.isNoise(tiny, 0));
        assertFalse(JsAssetsPanel.isNoise(tiny, 1));
        tiny.setExtractedEndpoints(1);
        assertFalse(JsAssetsPanel.isNoise(tiny, 0));
        JsAsset big = new JsAsset("https://h.example/main.js", "s3", JsAssetsPanel.EMPTY_CHUNK_MAX_CHARS);
        assertFalse(JsAssetsPanel.isNoise(big, 0));
    }

    @Test
    void seenOnlyAppliesToRouteFindings() {
        Set<String> seen = Set.of("/admin/users");
        Finding route = new Finding("Sensitive route in JS: admin", Finding.Severity.MEDIUM,
                "https://h.example/admin/users/", "https://h.example/app.js", "ev", false);
        Finding unseen = new Finding("Sensitive route in JS: admin", Finding.Severity.MEDIUM,
                "/admin/settings", "https://h.example/app.js", "ev", false);
        Finding other = new Finding("eval() sink", Finding.Severity.HIGH, "eval(",
                "https://h.example/app.js", "ev", false);
        assertEquals(Boolean.TRUE, JsAnalysisPanel.seen(route, seen));
        assertEquals(Boolean.FALSE, JsAnalysisPanel.seen(unseen, seen));
        assertNull(JsAnalysisPanel.seen(other, seen));
    }

    @Test
    void seenPathsCountOnlyEndpointsThatAnswered() {
        Endpoint answered = new Endpoint("GET", "h.example", "/admin/users/", "https://h.example/admin/users/");
        answered.recordObservation(200, "text/html", "proxy", null);
        Endpoint jsOnly = new Endpoint("JS", "h.example", "/admin/settings", "/admin/settings");
        assertEquals(Set.of("/admin/users"), JsAnalysisPanel.seenPaths(List.of(answered, jsOnly)));
    }
}
